"""Native signed request authentication, not a mock provider/SSO claim."""
import hashlib
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, ProviderConnection, TrustedProxyRequest
from app.trusted_proxy import configuration
from test_api import context


@pytest.fixture
def signing(monkeypatch, tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    public = tmp_path / 'management-public.pem'
    public.write_bytes(pem)
    monkeypatch.setenv('MAGPIE_PROXY_PUBLIC_KEY_FILE', str(public))
    monkeypatch.setenv('MAGPIE_PROXY_ISSUER', 'https://management.example.invalid')
    monkeypatch.setenv('MAGPIE_PROXY_AUDIENCE', 'magpie:test-installation')
    configuration.cache_clear()
    subject = str(uuid.uuid4())
    def issue(method='GET', target='/admin/providers', body=b'', changes=None, headers=None, key=None):
        now = int(time.time())
        claims = dict(iss='https://management.example.invalid', aud='magpie:test-installation',
                      sub=subject, iat=now, nbf=now, exp=now+45, jti=str(uuid.uuid4()),
                      actor_kind='human', scope='magpie:admin:read' if method == 'GET' else 'magpie:admin:write',
                      method=method, target=target, body_sha256=hashlib.sha256(body).hexdigest())
        claims.update(changes or {})
        token = jwt.encode(claims, key or private, algorithm='ES256', headers=headers)
        return {'Authorization': 'Bearer mgd_'+token, 'Content-Type': 'application/json'}, claims
    yield issue, subject
    configuration.cache_clear()


def test_default_disabled_and_existing_bootstrap_unchanged(context, monkeypatch):
    client, _ = context
    for name in ['MAGPIE_PROXY_PUBLIC_KEY_FILE', 'MAGPIE_PROXY_ISSUER', 'MAGPIE_PROXY_AUDIENCE']:
        monkeypatch.delenv(name, raising=False)
    configuration.cache_clear()
    assert client.get('/admin/providers', headers={'Authorization':'Bearer mgd_untrusted'}).status_code == 401
    assert client.get('/admin/providers', headers={'Authorization':'Bearer '+'a'*40}).status_code == 200


def test_delegated_reads_are_bound_and_do_not_create_local_users(context, signing):
    client, db = context
    issue, _ = signing
    headers, _ = issue()
    assert client.get('/admin/providers', headers=headers).status_code == 200
    # Read replay within the bounded lifetime is harmless, not a write nonce guarantee.
    assert client.get('/admin/providers', headers=headers).status_code == 200
    assert client.get('/admin/models', headers=headers).status_code == 401
    assert client.get('/admin/providers?unexpected=1', headers=headers).status_code == 401
    with Session(db) as session:
        assert session.query(TrustedProxyRequest).count() == 0


@pytest.mark.parametrize('change', [
    {'aud':'different-installation'}, {'aud':['magpie:test-installation','other']},
    {'iss':'https://attacker.example.invalid'}, {'exp':0}, {'exp':int(time.time())+3600},
    {'sub':'not-a-verified-identity'}, {'jti':'not-a-nonce'}, {'iat':True},
    {'scope':'magpie:admin:write'}, {'body_sha256':'0'*64},
])
def test_invalid_claims_fail_closed(context, signing, change):
    client, _ = context
    issue, _ = signing
    headers, _ = issue(changes=change)
    assert client.get('/admin/providers', headers=headers).status_code == 401


def test_unknown_header_and_wrong_signature_are_rejected(context, signing):
    client, _ = context
    issue, _ = signing
    for kwargs in [{'headers':{'jku':'https://attacker.example.invalid/key'}},
                   {'key':ec.generate_private_key(ec.SECP256R1())}]:
        headers, _ = issue(**kwargs)
        assert client.get('/admin/providers', headers=headers).status_code == 401


def test_write_body_scope_replay_and_originating_audit(context, signing):
    client, db = context
    issue, subject = signing
    body = json.dumps({'name':'native-delegation-fixture','provider_type':'openai'}).encode()
    headers, claims = issue('POST', body=body)
    assert client.post('/admin/providers', content=body+b' ', headers=headers).status_code == 401
    assert client.post('/admin/providers', content=body, headers=headers).status_code == 201
    duplicate = client.post('/admin/providers', content=body, headers=headers)
    assert duplicate.status_code == 409
    assert 'already consumed' in duplicate.json()['detail']
    with Session(db) as session:
        assert session.query(ProviderConnection).count() == 1
        record = session.get(TrustedProxyRequest, claims['jti'])
        assert record.subject == subject
        assert len(record.actor) <= 30 and record.actor.startswith('px:')
        audit = session.scalar(select(AuditLog).where(AuditLog.action == 'provider.create'))
        assert audit.actor == record.actor and audit.proxy_request_id == record.id
        assert record.body_sha256 == hashlib.sha256(body).hexdigest()
    read_only, _ = issue('POST', body=body, changes={'scope':'magpie:admin:read'})
    assert client.post('/admin/providers', content=body, headers=read_only).status_code == 401


def test_failed_write_does_not_restore_captured_token(context, signing):
    client, db = context
    issue, _ = signing
    body = json.dumps({'name':'conflict','provider_type':'openai'}).encode()
    first, _ = issue('POST', body=body)
    assert client.post('/admin/providers', content=body, headers=first).status_code == 201
    second, claims = issue('POST', body=body)
    assert client.post('/admin/providers', content=body, headers=second).status_code == 409
    replay = client.post('/admin/providers', content=body, headers=second)
    assert replay.status_code == 409 and 'already consumed' in replay.json()['detail']
    with Session(db) as session:
        assert session.get(TrustedProxyRequest, claims['jti']) is not None


def test_delegation_cannot_manage_native_identity(context, signing):
    client, _ = context
    issue, _ = signing
    body = json.dumps({'username':'not-allowed','password':'not a real password'}).encode()
    headers, _ = issue('POST', '/admin/users', body)
    assert client.post('/admin/users', content=body, headers=headers).status_code == 401
    headers, _ = issue('GET','/admin/users')
    assert client.get('/admin/users', headers=headers).status_code == 401


def test_agents_have_distinct_read_identity_and_cannot_write(context, signing):
    client, _ = context
    issue, _ = signing
    agent = str(uuid.uuid4())
    headers, _ = issue(changes={'actor_kind':'agent','agent_id':agent})
    assert client.get('/admin/providers', headers=headers).status_code == 200
    body = json.dumps({'name':'denied','provider_type':'openai'}).encode()
    headers, _ = issue('POST',body=body,changes={'actor_kind':'agent','agent_id':agent})
    assert client.post('/admin/providers',content=body,headers=headers).status_code == 401
    headers, _ = issue(changes={'actor_kind':'agent'})
    assert client.get('/admin/providers',headers=headers).status_code == 401


def test_owned_request_lookup_does_not_disclose_other_subject(context, signing):
    client, _ = context
    issue, _ = signing
    body = json.dumps({'name':'lookup','provider_type':'openai'}).encode()
    headers, claims = issue('POST', body=body)
    assert client.post('/admin/providers', content=body, headers=headers).status_code == 201
    target = '/admin/proxy-requests/'+claims['jti']
    own, _ = issue(target=target)
    result = client.get(target, headers=own)
    assert result.status_code == 200 and result.json()['state'] == 'consumed'
    assert result.json()['audits'][0]['action'] == 'provider.create'
    other, _ = issue(target=target, changes={'sub':str(uuid.uuid4())})
    assert client.get(target, headers=other).status_code == 404
