import hashlib
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.database import Base
from app.main import app, db_session
from app.models import CatalogLock, ClientKey, ProviderConnection, ModelCapability
from app import providers

@pytest.fixture
def context(monkeypatch):
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', 'a' * 40)
    monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', Fernet.generate_key().decode())
    db = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(db)
    with Session(db) as session:
        session.add(CatalogLock(id=1)); session.commit()
    def get_db():
        with Session(db) as session:
            yield session
    app.dependency_overrides[db_session] = get_db
    with TestClient(app) as client:
        yield client, db
    app.dependency_overrides.clear()
    db.dispose()

def admin():
    return {'Authorization': 'Bearer ' + 'a' * 40}

def test_decrypt_existing_provider_key_after_cryptography_upgrade(monkeypatch):
    # Synthetic fixture generated using cryptography 47.0.0; never a real key.
    from app.security import decrypt_secret
    monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=')
    token = 'gAAAAABq9_AQnoW72hNpjX9yfWxvybQYz7M-ky1X60-xmMg1jqm0JbVXSSCYK_5TJWPKijcKGwx9vvJRKM6EW7dnDfI-RJarYEnvRS5lBNQIjNbyMv6it68='
    assert decrypt_secret(token) == 'synthetic-legacy-provider-key'

def test_offline_admin_recovery_revokes_sessions_and_audits(context, monkeypatch):
    import app.recover_admin as recovery
    from app.models import AdminSession, AdminUser
    client, db = context
    original = {'username': 'recovery-admin', 'password': 'original password'}
    assert client.post('/admin/users', headers=admin(), json=original).status_code == 201
    old = client.post('/admin/sessions', json=original).json()['token']
    with Session(db) as session:
        session.get(AdminUser, 1).active = False
        session.commit()
        with pytest.raises(ValueError):
            recovery.recover(session, original['username'], 'short')
        with pytest.raises(ValueError):
            recovery.recover(session, 'missing-user', 'valid new password')
        assert recovery.recover(session, original['username'], 'valid new password') == 1
        assert session.get(AdminUser, 1).active is True
        assert session.query(AdminSession).filter_by(user_id=1, revoked=True).count() == 1
    assert client.get('/admin/providers', headers={'Authorization': 'Bearer ' + old}).status_code == 401
    assert client.post('/admin/sessions', json=original).status_code == 401
    token = client.post('/admin/sessions', json={**original, 'password': 'valid new password'}).json()['token']
    auth = {'Authorization': 'Bearer ' + token}
    logs = client.get('/admin/audit', headers=auth).json()
    assert any(row['action'] == 'admin.recover' and row['actor'] == 'operator' and row['target_id'] == '1' for row in logs)
    assert 'valid new password' not in str(logs)
    def failed_audit(*args, **kwargs):
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(recovery, 'audit', failed_audit)
    with Session(db) as session:
        with pytest.raises(RuntimeError):
            recovery.recover(session, original['username'], 'another password')
    assert client.get('/admin/providers', headers=auth).status_code == 200
    assert client.post('/admin/sessions', json={**original, 'password': 'valid new password'}).status_code == 201

def mock_vectors(input_value, dimensions=2):
    count = 1 if isinstance(input_value, str) or isinstance(input_value[0], int) else len(input_value)
    return [{'index':i, 'embedding':[0.1] * dimensions} for i in range(count)]


def test_provider_timeout_configuration(monkeypatch):
    monkeypatch.delenv('MAGPIE_PROVIDER_TIMEOUT_SECONDS', raising=False)
    assert providers.provider_timeout() == 60
    monkeypatch.setenv('MAGPIE_PROVIDER_TIMEOUT_SECONDS', '180')
    assert providers.provider_timeout() == 180
    for value in ('0', '3601', 'nan', 'inf', 'invalid'):
        monkeypatch.setenv('MAGPIE_PROVIDER_TIMEOUT_SECONDS', value)
        with pytest.raises(ValueError):
            providers.provider_timeout()


@pytest.mark.parametrize('path', ['/v1/embeddings', '/admin/providers'])
def test_request_body_total_read_deadline(path):
    import asyncio
    import json
    from app.request_limit import BodyLimitMiddleware
    events, called = [], []
    async def downstream(scope, receive, send): called.append(True)
    async def receive():
        await asyncio.sleep(0.01)
        return {'type':'http.request', 'body':b'private', 'more_body':True}
    async def send(message): events.append(message)
    async def run():
        await BodyLimitMiddleware(downstream, max_read_seconds=0.035)({'type':'http','path':path}, receive, send)
    asyncio.run(run())
    assert not called and events[0]['status'] == 408
    result = json.loads(events[1]['body'])
    assert 'private' not in str(result)
    if path.startswith('/v1/'):
        assert result['error']['code'] == 'request_timeout'
    else:
        assert result['detail'] == 'Request body timed out'


def configure(client, operations=None):
    p = client.post('/admin/providers', headers=admin(), json={'name': 'LG', 'provider_type': 'exaone', 'api_key': 'provider-secret'})
    assert p.status_code == 201
    selected = operations or ['generation', 'embedding']
    m = client.post('/admin/models', headers=admin(), json={'alias': 'exaone-chat', 'provider_id': p.json()['id'], 'upstream_model': 'k-exaone_v2.5', 'operations': [selected[0]]})
    assert m.status_code == 201
    # Exercise backward compatibility with pre-group registrations.
    if len(selected) > 1:
        sessions = client.app.dependency_overrides[db_session]()
        session = next(sessions)
        for operation in selected[1:]:
            session.add(ModelCapability(model_id=m.json()['id'], operation=operation, api_mode={'embedding':'embeddings', 'decision':'decisions', 'generation':'chat_completions'}[operation]))
        session.commit()
        sessions.close()
    k = client.post('/admin/api-keys', headers=admin(), json={'name': 'test', 'model_ids': [m.json()['id']]})
    assert k.status_code == 201
    return p.json()['id'], m.json()['id'], k.json()

def test_provider_credential_health_is_read_only_and_never_returns_secrets(context):
    client, db = context
    valid = client.post('/admin/providers', headers=admin(), json={'name':'valid','provider_type':'exaone','api_key':'private-provider-secret'}).json()['id']
    missing = client.post('/admin/providers', headers=admin(), json={'name':'missing','provider_type':'typesafe'}).json()['id']
    wrong = client.post('/admin/providers', headers=admin(), json={'name':'wrong','provider_type':'openai','api_key':'temporary-secret'}).json()['id']
    alien_ciphertext = Fernet(Fernet.generate_key()).encrypt(b'alien-secret').decode()
    with Session(db) as session:
        session.get(ProviderConnection, wrong).encrypted_api_key = alien_ciphertext
        session.commit()
    assert client.get('/admin/provider-credential-health').status_code == 401
    response = client.get('/admin/provider-credential-health', headers=admin())
    assert response.status_code == 200 and response.json()['unreadable_count'] == 1
    status = {item['provider_id']:item['status'] for item in response.json()['providers']}
    assert status == {valid:'decryptable', missing:'not_configured', wrong:'unreadable'}
    assert all(secret not in response.text for secret in ('private-provider-secret','temporary-secret','alien-secret',alien_ciphertext))
    with Session(db) as session:
        assert session.get(ProviderConnection, wrong).encrypted_api_key == alien_ciphertext


def test_sensitive_responses_are_not_cacheable(context, monkeypatch):
    client, _ = context
    _, model, key = configure(client, ['generation'])
    response = client.post('/admin/api-keys', headers=admin(), json={'name':'cache-test','model_ids':[model]})
    assert response.status_code == 201 and response.json()['key'].startswith('mgp_')
    assert 'no-store' in response.headers['cache-control']
    assert 'no-store' in client.get('/admin/api-keys').headers['cache-control']
    assert 'no-store' in client.post('/auth/oidc/start').headers['cache-control']
    assert 'cache-control' not in client.get('/api/catalog').headers
    async def fake(config, data):
        async def chunks():
            yield {'choices':[{'index':0, 'delta':{'content':'mock'}, 'finish_reason':None}]}
            yield {'choices':[{'index':0, 'delta':{}, 'finish_reason':'stop'}]}
        return chunks()
    monkeypatch.setattr(providers, 'completion', fake)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']},
        json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}], 'stream':True})
    assert response.status_code == 200
    assert {'no-cache','no-store'} <= {part.strip() for part in response.headers['cache-control'].split(',')}


def test_example_bootstrap_token_cannot_authenticate(context, monkeypatch):
    from pathlib import Path
    client, _ = context
    example = (Path(__file__).resolve().parents[2] / '.env.example').read_text()
    placeholder = next(line.split('=', 1)[1] for line in example.splitlines() if line.startswith('MAGPIE_ADMIN_TOKEN='))
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', placeholder)
    headers = {'Authorization':'Bearer '+placeholder}
    assert client.get('/admin/providers', headers=headers).status_code == 503
    assert client.post('/admin/users', headers=headers, json={'username':'test-admin','password':'test password longer than twelve'}).status_code == 503
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', 'a' * 40)
    assert client.get('/admin/providers', headers=admin()).status_code == 200


def test_bootstrap_token_length_matches_authentication_limit(context, monkeypatch):
    from app.security import valid_bootstrap_token
    client, _ = context
    assert not valid_bootstrap_token('a' * 31)
    assert valid_bootstrap_token('a' * 512)
    assert not valid_bootstrap_token('a' * 513)
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', 'a' * 513)
    assert client.get('/admin/providers', headers=admin()).status_code == 503


def test_auth_secret_encryption_and_revocation(context):
    client, db = context
    assert client.get('/admin/providers').status_code == 401
    pid, _, key = configure(client)
    assert 'provider-secret' not in str(client.get('/admin/providers', headers=admin()).json())
    with Session(db) as session:
        assert session.get(ProviderConnection, pid).encrypted_api_key != 'provider-secret'
        stored = session.get(ClientKey, key['id'])
        assert stored.key_hash == hashlib.sha256(key['key'].encode()).hexdigest()
        assert key['key'] not in repr(stored.__dict__)
    assert key['key'] not in str(client.get('/admin/api-keys', headers=admin()).json())
    assert client.get('/v1/models', headers={'Authorization': 'Bearer ' + key['key']}).status_code == 200
    assert client.delete('/admin/api-keys/' + str(key['id']), headers=admin()).status_code == 204
    assert client.get('/v1/models', headers={'Authorization': 'Bearer ' + key['key']}).status_code == 401


@pytest.mark.parametrize('missing_secret', [None, ''])
def test_model_discovery_excludes_missing_provider_credentials(context, monkeypatch, missing_secret):
    client, db = context
    provider, model, key = configure(client, ['generation'])
    assert client.post('/admin/routes', headers=admin(), json={'alias':'chat-route','operation':'generation','targets':[{'model_id':model}]}).status_code == 201
    auth = {'Authorization':'Bearer '+key['key']}
    assert {row['id'] for row in client.get('/v1/models', headers=auth).json()['data']} == {'exaone-chat','chat-route'}

    with Session(db) as session:
        session.get(ProviderConnection, provider).encrypted_api_key = missing_secret
        session.commit()
    calls = []
    async def fake(config, data):
        calls.append(True)
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'}}]}
    monkeypatch.setattr(providers, 'completion', fake)
    assert client.get('/v1/models', headers=auth).json()['data'] == []
    payload = {'messages':[{'role':'user','content':'test'}]}
    assert client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat',**payload}).status_code == 503
    assert client.post('/v1/chat/completions', headers=auth, json={'model':'chat-route',**payload}).status_code == 403
    assert not calls
    assert client.put(f'/admin/providers/{provider}/key', headers=admin(), json={'api_key':'new-mock-secret'}).status_code == 200
    assert {row['id'] for row in client.get('/v1/models', headers=auth).json()['data']} == {'exaone-chat','chat-route'}

@pytest.mark.parametrize(('provider_type', 'operation', 'path', 'payload'), [
    ('exaone', 'embedding', '/v1/embeddings', {'model':'deferred','input':'test'}),
    ('typesafe', 'decision', '/v1/decisions', {'model':'deferred','input':'test','questions':[{'type':'predicate','name':'ok','instructions':'Is this ok?'}]}),
    ('openai', 'generation', '/v1/chat/completions', {'model':'deferred','messages':[{'role':'user','content':'test'}]}),
])
def test_provider_key_can_be_registered_after_model(context, monkeypatch, provider_type, operation, path, payload):
    client, db = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'deferred-provider','provider_type':provider_type})
    assert provider.status_code == 201 and provider.json()['configured'] is False
    provider_id = provider.json()['id']
    with Session(db) as session:
        assert session.get(ProviderConnection, provider_id).encrypted_api_key is None
    model = client.post('/admin/models', headers=admin(), json={'alias':'deferred','provider_id':provider_id,'upstream_model':'mock','operations':[operation]})
    assert model.status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test-key','model_ids':[model.json()['id']]}).json()['key']
    auth = {'Authorization':'Bearer '+key}
    assert client.get('/v1/models', headers=auth).json()['data'] == []
    assert client.post(path, headers=auth, json=payload).status_code == 503
    calls = []
    async def fake(config, data):
        calls.append(config)
        if operation == 'embedding': return {'data':mock_vectors(data['input'])}
        if operation == 'decision': return {'answers':[{'type':'predicate','name':'ok','probability':0.8}]}
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'}}]}
    monkeypatch.setattr(providers, {'embedding':'embedding','decision':'decision','generation':'completion'}[operation], fake)
    assert client.put(f'/admin/providers/{provider_id}/key', headers=admin(), json={'api_key':'later-test-secret'}).status_code == 200
    assert client.get('/admin/providers', headers=admin()).json()[0]['configured'] is True
    assert client.get('/v1/models', headers=auth).json()['data'][0]['id'] == 'deferred'
    assert client.post(path, headers=auth, json=payload).status_code == 200
    assert len(calls) == 1 and calls[0]['api_key'] == 'later-test-secret'
    assert 'later-test-secret' not in str(client.get('/admin/audit', headers=admin()).json())



def test_remove_provider_key_invalidates_evidence_and_blocks_calls(context, monkeypatch):
    client, db = context
    provider, model, key = configure(client, ['generation'])
    row = next(m for m in client.get('/admin/models', headers=admin()).json() if m['id'] == model)
    version = row['verification_version']
    assert client.put(f'/admin/models/{model}/capabilities/generation/verification', headers=admin(), json={'status':'mock_verified','note':'fixture','expected_version':version}).status_code == 200
    auth = {'Authorization':'Bearer '+key['key']}
    calls = []
    async def fake(config, data):
        calls.append(True)
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'}}]}
    monkeypatch.setattr(providers, 'completion', fake)
    assert client.delete(f'/admin/providers/{provider}/key', headers=admin()).status_code == 204
    assert client.get('/admin/providers', headers=admin()).json()[0]['configured'] is False
    updated = next(m for m in client.get('/admin/models', headers=admin()).json() if m['id'] == model)
    assert updated['verification_version'] == version + 1 and updated['capabilities'][0]['verification_status'] == 'unverified'
    assert client.get('/v1/models', headers=auth).json()['data'] == []
    assert client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}]}).status_code == 503
    assert not calls
    assert client.delete(f'/admin/providers/{provider}/key', headers=admin()).status_code == 204
    assert next(m for m in client.get('/admin/models', headers=admin()).json() if m['id'] == model)['verification_version'] == version + 1
    audit = client.get('/admin/audit', headers=admin()).json()
    assert sum(a['action'] == 'provider.key.remove' for a in audit) == 1 and 'provider-secret' not in str(audit)
    with Session(db) as session:
        assert session.get(ProviderConnection, provider).encrypted_api_key is None
    assert client.put(f'/admin/providers/{provider}/key', headers=admin(), json={'api_key':'replacement-fake'}).status_code == 200
    assert client.get('/v1/models', headers=auth).json()['data'][0]['id'] == 'exaone-chat'
    assert client.delete('/admin/providers/999999/key', headers=admin()).status_code == 404


def test_authenticated_admin_failures_are_audited_without_request_data(context):
    client, _ = context
    secret = 'private-value-that-must-not-appear'
    assert client.post('/admin/providers', headers=admin(), json={'name':'bad', 'provider_type':'missing', 'api_key':secret}).status_code == 422
    assert client.put('/admin/providers/987654/key', headers=admin(), json={'api_key':secret}).status_code == 404
    # Unknown or invalid credentials cannot anonymously flood the audit table.
    assert client.get('/admin/providers', headers={'Authorization':'Bearer '+secret}).status_code == 401
    audit = client.get('/admin/audit', headers=admin()).json()
    failures = [item for item in audit if item['action'] == 'admin.request.failed']
    assert len(failures) == 2
    assert all(item['actor'] == 'bootstrap' and item['target_type'] == 'admin_endpoint' for item in failures)
    assert any('POST /admin/providers 422' == item['target_id'] for item in failures)
    assert any('PUT /admin/providers/{provider_id}/key 404' == item['target_id'] for item in failures)
    assert secret not in str(audit) and '987654' not in str(audit)


def test_unexpected_admin_failure_rolls_back_and_audits(context, monkeypatch, caplog):
    import importlib
    main = importlib.import_module('app.main')
    client, _ = context
    def broken(_): raise RuntimeError('sensitive-internal-error')
    monkeypatch.setattr(main, 'encrypt_secret', broken)
    response = client.post('/admin/providers', headers=admin(), json={'name':'broken','provider_type':'exaone','api_key':'secret-value'})
    assert response.status_code == 500 and 'sensitive-internal-error' not in response.text
    assert client.get('/admin/providers', headers=admin()).json() == []
    audit = client.get('/admin/audit', headers=admin()).json()
    assert any(a['action'] == 'admin.request.failed' and a['target_id'] == 'POST /admin/providers 500' for a in audit)
    assert 'sensitive-internal-error' not in str(audit) and 'secret-value' not in str(audit)
    assert 'Unhandled request failure' in caplog.text
    assert 'sensitive-internal-error' not in caplog.text and 'secret-value' not in caplog.text


def test_database_error_is_sanitized_and_returns_503(context):
    from sqlalchemy.exc import OperationalError
    client, _ = context
    original = app.dependency_overrides[db_session]
    def failed_db():
        raise OperationalError('secret sql', {'password':'secret-password'}, RuntimeError('secret reason'))
    app.dependency_overrides[db_session] = failed_db
    try:
        response = client.post('/v1/embeddings', headers={'Authorization':'Bearer mgp_example'}, json={'model':'x','input':'x'})
        assert response.status_code == 503 and response.json()['error']['code'] == 'database_unavailable'
        assert 'secret' not in response.text
        response = client.get('/admin/providers', headers=admin())
        assert response.status_code == 503 and response.json()['detail'] == 'Database unavailable'
    finally:
        app.dependency_overrides[db_session] = original


def test_started_response_does_not_expose_unhandled_exception(caplog):
    import asyncio
    from app.main import SanitizedUnhandledErrors
    sent = []
    async def downstream(scope, receive, send):
        await send({'type':'http.response.start','status':200,'headers':[]})
        raise RuntimeError('sensitive-stream-exception')
    async def receive(): return {'type':'http.disconnect'}
    async def send(message): sent.append(message)
    asyncio.run(SanitizedUnhandledErrors(downstream)({'type':'http','path':'/v1/chat/completions'}, receive, send))
    assert len(sent) == 1 and sent[0]['status'] == 200
    assert 'Unhandled request failure' in caplog.text and 'sensitive-stream-exception' not in caplog.text


def test_usage_finalization_does_not_log_exception_details(monkeypatch, caplog):
    import time
    from app import observability
    def broken(*args, **kwargs): raise RuntimeError('sensitive-database-detail')
    monkeypatch.setattr(observability, 'Session', broken)
    observability.end(None, 'test-request-id', time.monotonic(), 'error')
    assert 'Could not finalize usage record test-request-id' in caplog.text
    assert 'sensitive-database-detail' not in caplog.text

def test_chat_and_embeddings_route_to_mock_exaone(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client)
    calls = []
    async def fake_chat(config, data):
        calls.append((config, data))
        return {'id': 'chat-1', 'model': 'upstream', 'choices': [{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    async def fake_embedding(config, data):
        calls.append((config, data))
        return {'object': 'list', 'model': 'upstream', 'data': [{'embedding': [0.1, 0.2], 'index': 0}]}
    monkeypatch.setattr(providers, 'completion', fake_chat)
    monkeypatch.setattr(providers, 'embedding', fake_embedding)
    auth = {'Authorization': 'Bearer ' + key['key']}
    chat = client.post('/v1/chat/completions', headers=auth, json={'model': 'exaone-chat', 'messages': [{'role': 'user', 'content': 'hello'}]})
    embed = client.post('/v1/embeddings', headers=auth, json={'model': 'exaone-chat', 'input': 'hello'})
    assert chat.status_code == embed.status_code == 200
    assert chat.json()['model'] == embed.json()['model'] == 'exaone-chat'
    assert embed.json()['data'][0]['embedding'] == [0.1, 0.2]
    assert calls[0][0] == {'model': 'openai/k-exaone_v2.5', 'api_key': 'provider-secret', 'api_base': 'https://api.exaone.ai/v1', 'timeout': 60.0, 'num_retries': 0}
    assert calls[1][1]['input'] == 'hello'
    assert client.post('/v1/embeddings', headers=auth, json={'model': 'no-access', 'input': 'x'}).status_code == 403
    assert client.post('/v1/embeddings', headers=auth, json={'model': 'exaone-chat', 'input': 'x', 'api_base': 'https://evil.invalid'}).status_code == 400


@pytest.mark.parametrize('invalid_input', ['', ['hello',''], [True], [1.0], [-1], [[1],[-1]], [[1],[]]])
def test_embedding_invalid_inputs_are_rejected_before_dispatch(context, monkeypatch, invalid_input):
    client, _ = context
    _, _, key = configure(client, ['embedding'])
    calls = []
    async def fake(config, data):
        calls.append(True)
        return {'data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', fake)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':invalid_input})
    assert response.status_code == 400 and not calls
    assert client.get('/admin/usage/requests', headers=admin()).json() == []


def test_embedding_batch_metadata_and_token_input_limits(context, monkeypatch):
    client, _ = context
    provider_id, model_id, key = configure(client, ['embedding'])
    url = '/admin/models/' + str(model_id)
    model = {'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'k-exaone_v2.5','operations':['embedding'],
             'supports_embedding_batch':True,'embedding_max_batch_size':2,'max_input_tokens':3}
    response = client.put(url, headers=admin(), json=model)
    assert response.status_code == 200 and response.json()['embedding_max_batch_size'] == 2
    assert client.put(url, headers=admin(), json={**model,'supports_embedding_batch':False}).status_code == 422
    assert client.put(url, headers=admin(), json={**model,'operations':['generation']}).status_code == 422
    calls = []
    async def fake(config, data):
        calls.append(data)
        return {'model':'upstream','data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    endpoint = '/v1/embeddings'
    for value in ('hello', ['a','b'], [1,2,3], [[1,2,3],[4]]):
        assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','input':value}).status_code == 200
    for value in ([], [[1],[]], ['a','b','c'], [1,2,3,4], [[1],[1,2,3,4]]):
        assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','input':value}).status_code == 400
    assert len(calls) == 4
    assert client.put(url, headers=admin(), json={**model,'supports_embedding_batch':False,'embedding_max_batch_size':1}).status_code == 200
    assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','input':['a','b']}).status_code == 400
    assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','input':[1,2,3]}).status_code == 200

def test_embedding_response_validation_and_budget_reservation(context, monkeypatch):
    import base64
    import struct
    from decimal import Decimal
    client, _ = context
    provider, model, key = configure(client, ['embedding'])
    assert client.put('/admin/models/'+str(model), headers=admin(), json={'alias':'exaone-chat','provider_id':provider,'upstream_model':'embed','operations':['embedding'],'embedding_dimensions':2}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    responses = []
    calls = []
    async def fake(config, data):
        calls.append(data)
        return {'data':responses.pop(0), 'usage':{'prompt_tokens':2}}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    payload = {'model':'exaone-chat','input':['a','b']}
    assert client.post('/v1/embeddings', headers=auth, json={**payload,'dimensions':3}).status_code == 400
    assert not calls and client.get('/admin/usage/requests', headers=admin()).json() == []
    invalid = [[], [{'index':0,'embedding':[1,2]}],
               [{'index':0,'embedding':[1,2]},{'index':0,'embedding':[1,2]}],
               [{'index':0,'embedding':[1]},{'index':1,'embedding':[1,2]}],
               [{'index':0,'embedding':[1,float('nan')]},{'index':1,'embedding':[1,2]}],
               [{'index':0,'embedding':'!!!'},{'index':1,'embedding':[1,2]}],
               [{'index':0,'embedding':base64.b64encode(b'abc').decode()},{'index':1,'embedding':[1,2]}]]
    responses.extend(invalid)
    for _ in invalid:
        assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 502
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['spent_amount']) == 0 and Decimal(budget['held_amount']) == Decimal('0.1') * len(invalid)
    encoded = base64.b64encode(struct.pack('<ff', 0.1, 0.2)).decode()
    responses.append([{'index':1,'embedding':encoded},{'index':0,'embedding':encoded}])
    result = client.post('/v1/embeddings', headers=auth, json={**payload,'dimensions':2,'encoding_format':'base64'})
    assert result.status_code == 200 and result.json()['data'][0]['embedding'] == encoded
    assert len(calls) == len(invalid) + 1


def test_embedding_normalizes_requested_encoding(context, monkeypatch):
    import base64
    import struct
    client, _ = context
    _, _, key = configure(client, ['embedding'])
    encoded = base64.b64encode(struct.pack('<ff', 1.0, -0.5)).decode()
    values = iter([[1.0, -0.5], encoded, encoded])
    async def fake(config, data):
        return {'data':[{'index':0, 'embedding':next(values)}]}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    payload = {'model':'exaone-chat','input':'test'}
    response = client.post('/v1/embeddings', headers=auth, json={**payload, 'encoding_format':'base64'})
    assert response.status_code == 200 and response.json()['data'][0]['embedding'] == encoded
    response = client.post('/v1/embeddings', headers=auth, json={**payload, 'encoding_format':'float'})
    assert response.status_code == 200 and response.json()['data'][0]['embedding'] == [1.0,-0.5]
    response = client.post('/v1/embeddings', headers=auth, json=payload)
    assert response.status_code == 200 and response.json()['data'][0]['embedding'] == [1.0,-0.5]
    async def too_large(config, data):
        return {'data':[{'index':0, 'embedding':[1e40]}]}
    monkeypatch.setattr(providers, 'embedding', too_large)
    response = client.post('/v1/embeddings', headers=auth, json={**payload, 'encoding_format':'base64'})
    assert response.status_code == 502


def test_stream_and_sanitized_errors(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client)
    async def fake_stream(config, data):
        async def chunks():
            yield {'id': 'one', 'choices': [{'index':0,'delta':{},'finish_reason':'stop'}]}
        return chunks()
    monkeypatch.setattr(providers, 'completion', fake_stream)
    auth = {'Authorization': 'Bearer ' + key['key']}
    response = client.post('/v1/chat/completions', headers=auth, json={'model': 'exaone-chat', 'messages': [{'role': 'user', 'content': 'hi'}], 'stream': True})
    assert response.status_code == 200 and 'data: [DONE]' in response.text
    async def fail(config, data):
        raise RuntimeError('sensitive provider-secret')
    monkeypatch.setattr(providers, 'embedding', fail)
    response = client.post('/v1/embeddings', headers=auth, json={'model': 'exaone-chat', 'input': 'hi'})
    assert response.status_code == 502 and 'provider-secret' not in response.text


def test_chat_remote_media_cannot_trigger_server_side_fetch(context, monkeypatch):
    import base64
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data): calls.append(data); return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    endpoint = '/v1/chat/completions'
    def submit(content):
        return client.post(endpoint, headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':content}]})
    unsafe_parts = [
        {'type':'image_url','image_url':{'url':'http://169.254.169.254/latest/meta-data'}},
        {'type':'image_url','image_url':'https://127.0.0.1/internal'},
        {'type':'file','file':{'file_id':'https://127.0.0.1/internal'}},
        {'type':'input_audio','input_audio':{'data':'https://internal'}},
        {'type':'image_url','image_url':{'url':'data:image/png;base64,@@@'}},
        {'type':'image_url','image_url':{'url':'data:image/png;base64,YQ==','unexpected':'https://internal'}},
    ]
    for part in unsafe_parts:
        assert submit([part]).status_code == 400
    assert not calls
    assert submit('Please summarize https://example.com as text').status_code == 200
    encoded = base64.b64encode(b'test image').decode()
    assert submit([{'type':'text','text':'describe'}, {'type':'image_url','image_url':{'url':'data:image/png;base64,'+encoded,'detail':'low'}}]).status_code == 200
    assert len(calls) == 2
    assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'hi','file':'https://127.0.0.1'}]}).status_code == 400
    assert client.post(endpoint, headers=auth, json={'model':'exaone-chat','messages':[{'role':[],'content':'hi'}]}).status_code == 400
    assert len(calls) == 2


@pytest.mark.parametrize('field', ['temperature', 'top_p'])
@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-Infinity', 'true', '"0.5"'])
def test_chat_rejects_invalid_sampling_values_before_provider(context, monkeypatch, field, value):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data):
        calls.append(data)
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    raw = '{"model":"exaone-chat","messages":[{"role":"user","content":"test"}],"'+field+'":'+value+'}'
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key'], 'Content-Type':'application/json'}, content=raw)
    assert response.status_code == 400 and not calls
    assert client.get('/admin/usage/requests', headers=admin()).json() == []


def test_chat_accepts_numeric_sampling_values(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data):
        calls.append(data)
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']},
        json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}], 'temperature':0, 'top_p':0.5})
    assert response.status_code == 200 and calls[0]['temperature'] == 0 and calls[0]['top_p'] == 0.5


@pytest.mark.parametrize('extra', [
    '"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"n":{"type":"number","default":NaN}}}}}]',
    '"tools":[{"type":"function","function":{"name":"f","parameters":{"enum":[1,Infinity]}}}]',
    '"stream_options":{"include_usage":true,"extra":{"value":-Infinity}}',
    '"messages":[{"role":"user","content":"test","name":NaN}]',
])
def test_chat_rejects_nested_nonfinite_json_before_provider(context, monkeypatch, extra):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data):
        calls.append(data)
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    messages = '' if extra.startswith('"messages"') else '"messages":[{"role":"user","content":"test"}],'
    raw = '{"model":"exaone-chat",'+messages+extra+'}'
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key'], 'Content-Type':'application/json'}, content=raw)
    assert response.status_code == 400 and not calls
    assert client.get('/admin/usage/requests', headers=admin()).json() == []


def test_chat_passes_reasoning_history_and_modern_token_limit(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data): calls.append(data); return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    body = {'model':'exaone-chat', 'messages':[{'role':'assistant','content':None,'reasoning_content':'analysis','tool_calls':[{'id':'call_1','type':'function','function':{'name':'lookup','arguments':'{}'}}]},{'role':'tool','tool_call_id':'call_1','content':'result'}], 'max_completion_tokens':128}
    auth = {'Authorization':'Bearer '+key['key']}
    assert client.post('/v1/chat/completions', headers=auth, json=body).status_code == 200
    assert calls[0]['messages'][0]['reasoning_content'] == 'analysis' and calls[0]['max_completion_tokens'] == 128
    assert client.post('/v1/chat/completions', headers=auth, json={**body, 'max_tokens':128}).status_code == 400
    assert len(calls) == 1

def test_auth_and_operation_scoping(context):
    client, _ = context
    _, _, key = configure(client, ['embedding'])
    response = client.post('/v1/chat/completions', headers={'Authorization': 'Bearer '+key['key']}, json={'model': 'exaone-chat', 'messages': [{'role': 'user', 'content': 'hi'}]})
    assert response.status_code == 403
    assert client.post('/v1/embeddings', json={'model': 'exaone-chat', 'input': 'hi'}).status_code == 401

def test_provider_sdk_arguments_are_passed_without_network(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client)
    calls = []
    async def fake_sdk(**kwargs):
        calls.append(kwargs)
        return {'model': 'upstream', 'data':mock_vectors(kwargs['input'])}
    monkeypatch.setattr(providers.litellm, 'aembedding', fake_sdk)
    response = client.post('/v1/embeddings', headers={'Authorization': 'Bearer ' + key['key']}, json={'model': 'exaone-chat', 'input': 'test', 'dimensions': 2})
    assert response.status_code == 200
    assert calls[0]['api_base'] == 'https://api.exaone.ai/v1'
    assert calls[0]['model'] == 'openai/k-exaone_v2.5'
    assert calls[0]['dimensions'] == 2


def test_invalid_provider_secret_is_not_reflected(context):
    client, _ = context
    response = client.post('/admin/providers', headers=admin(), json={'name': 'LG', 'provider_type': 'exaone', 'api_key': 'x' * 4100})
    assert response.status_code == 422
    assert 'x' * 100 not in response.text


def test_chat_sdk_arguments_and_unavailable_admin(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client)
    calls = []
    async def fake_sdk(**kwargs):
        calls.append(kwargs)
        return {"model": "original", "choices": [{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}
    monkeypatch.setattr(providers.litellm, "acompletion", fake_sdk)
    result = client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + key["key"]}, json={"model": "exaone-chat", "messages": [{"role": "user", "content": "test"}], "stream": False})
    assert result.status_code == 200 and result.json()["model"] == "exaone-chat"
    assert calls[0]["model"] == "openai/k-exaone_v2.5"
    assert calls[0]["api_base"] == "https://api.exaone.ai/v1"
    monkeypatch.delenv("MAGPIE_ADMIN_TOKEN")
    assert client.get("/admin/providers", headers=admin()).status_code == 503


def configure_jev(client):
    p = client.post('/admin/providers', headers=admin(), json={'name': 'Jev', 'provider_type': 'typesafe', 'api_key': 'jev-secret'})
    assert p.status_code == 201
    m = client.post('/admin/models', headers=admin(), json={'alias': 'judge', 'provider_id': p.json()['id'], 'upstream_model': 'jev-latest', 'operations': ['decision']})
    assert m.status_code == 201
    k = client.post('/admin/api-keys', headers=admin(), json={'name': 'judge-key', 'model_ids': [m.json()['id']]})
    return p.json(), m.json(), k.json()


def test_jev_decisions_usage_and_atomic_audit(context, monkeypatch):
    from app.models import AuditLog, UsageRecord
    client, db = context
    p, model, key = configure_jev(client)
    calls = []
    async def fake_sdk(config, data):
        calls.append(dict(config, **data))
        return {'model': 'jev-1.14.0', 'answers': [{'type': 'predicate', 'name': 'refund', 'probability': 0.9}], 'usage': {'input_tokens': 13, 'output_tokens': 0, 'total_tokens': 13}}
    monkeypatch.setattr(providers, 'decision', fake_sdk)
    payload = {'model': 'judge', 'input': 'private customer text', 'questions': [{'type': 'predicate', 'name': 'refund', 'instructions': 'Refund?'}]}
    response = client.post('/v1/decisions', headers={'Authorization': 'Bearer '+key['key']}, json=payload)
    assert response.status_code == 200
    assert response.json()['answers'][0]['probability'] == 0.9
    assert calls[0]['model'] == 'typesafe/jev-latest' and calls[0]['api_key'] == 'jev-secret'
    assert calls[0]['questions'] == payload['questions']
    usage = client.get('/admin/usage', headers=admin()).json()
    assert usage == [{'operation': 'decision', 'status': 'success', 'model_id': model['id'], 'client_key_id': key['id'], 'requests': 1, 'input_tokens': 13, 'output_tokens': None, 'input_token_records': 1, 'output_token_records': 0, 'question_count': 1, 'currency': None, 'estimated_cost': None, 'cost_records': 0}]
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert records[0]['request_id'] == response.headers['x-request-id']
    audit = client.get('/admin/audit', headers=admin()).json()
    assert {x['action'] for x in audit} == {'provider.create', 'model.create', 'api_key.create'}
    assert 'jev-secret' not in str(audit) and 'private customer text' not in str(records)
    assert client.get('/admin/audit').status_code == 401
    with Session(db) as session:
        assert len(session.query(AuditLog).all()) == 3
        assert session.get(UsageRecord, response.headers['x-request-id']).status == 'success'
    bad = client.post('/v1/decisions', headers={'Authorization': 'Bearer '+key['key']}, json={'model': 'judge', 'input': 'x', 'questions': [{'type':'choice','name':'x','instructions':'pick','choices':[{'value':'only'}]}]})
    assert bad.status_code == 400 and len(calls) == 1
    assert client.post('/v1/decisions', headers={'Authorization': 'Bearer '+key['key']}, json={**payload, 'safety_identifier':'user'}).status_code == 400
    assert client.post('/admin/providers', headers=admin(), json={'name': 'Jev', 'provider_type': 'typesafe', 'api_key': 'secret'}).status_code == 409
    audit_after = client.get('/admin/audit', headers=admin()).json()
    assert len(audit_after) == 4 and audit_after[0]['action'] == 'admin.request.failed'


@pytest.mark.parametrize('bad_choices', [[], [{'index':0}], [{'index':-1,'message':{'role':'assistant'}}], [{'index':0,'message':{'role':'user'}}], [{'index':0,'message':{'role':'assistant'}},{'index':0,'message':{'role':'assistant'}}],
    [{'index':0,'message':{'role':'assistant'}}],
    [{'index':0,'message':{'role':'assistant','content':{'text':'invalid'}}}],
    [{'index':0,'message':{'role':'assistant','tool_calls':[{'type':'function','id':'call','function':{'name':'f','arguments':{}}}]}}],
    [{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':False}],
])
def test_invalid_generation_response_never_settles(context, monkeypatch, bad_choices):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    async def malformed(config, data): return {'choices':bad_choices,'usage':{'prompt_tokens':10,'completion_tokens':10}}
    monkeypatch.setattr(providers, 'completion', malformed)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}]})
    assert response.status_code == 502
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


@pytest.mark.parametrize(('message', 'reason'), [
    ({'role':'assistant','content':'ok'}, 'stop'),
    ({'role':'assistant','content':None,'refusal':'no'}, 'stop'),
    ({'role':'assistant','content':None,'tool_calls':[{'id':'call_1','type':'function','function':{'name':'f','arguments':'{}'}}]}, 'tool_calls'),
    ({'role':'assistant','content':None}, 'content_filter'),
])
def test_valid_generation_message_variants(context, monkeypatch, message, reason):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    async def fake(config, data): return {'choices':[{'index':0,'message':message,'finish_reason':reason}]}
    monkeypatch.setattr(providers, 'completion', fake)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}]})
    assert response.status_code == 200, response.text


def test_unserializable_response_is_not_settled_as_success(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    async def malformed(config, data):
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}], 'invalid':float('nan'), 'usage':{'prompt_tokens':10,'completion_tokens':10}}
    monkeypatch.setattr(providers, 'completion', malformed)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}]})
    assert response.status_code == 502
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


@pytest.mark.parametrize('operation', ['embedding', 'decision'])
def test_provider_error_with_apparently_valid_result_is_not_settled(context, monkeypatch, operation):
    from decimal import Decimal
    client, _ = context
    if operation == 'embedding':
        _, model_id, key = configure(client, ['embedding'])
        payload = {'model':'exaone-chat','input':'test'}
        result = {'data':mock_vectors('test'), 'usage':{'prompt_tokens':10}}
        price = {'basis':'tokens','input_per_million':'1','output_per_million':'0'}
        path = '/v1/embeddings'
    else:
        _, model, key = configure_jev(client)
        model_id = model['id']
        payload = {'model':'judge','input':'test','questions':[{'type':'predicate','name':'q','instructions':'test?'}]}
        result = {'answers':[{'type':'predicate','name':'q','probability':0.9}]}
        price = {'basis':'question','per_question':'0.01'}
        path = '/v1/decisions'
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD',**price}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fake(config, data): return {**result, 'error':{'message':'provider-secret-error'}}
    monkeypatch.setattr(providers, operation, fake)
    response = client.post(path, headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 502 and 'provider-secret-error' not in response.text
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


def test_usage_error_and_stream_usage(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client)
    auth = {'Authorization': 'Bearer '+key['key']}
    async def failed(config, data):
        raise RuntimeError('sensitive')
    monkeypatch.setattr(providers, 'embedding', failed)
    assert client.post('/v1/embeddings', headers=auth, json={'model':'exaone-chat','input':'x'}).status_code == 502
    async def stream(config, data):
        async def chunks():
            yield {'model':'upstream','choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
            yield {'choices': [], 'usage': {'prompt_tokens':7, 'completion_tokens':2, 'total_tokens':9}}
        return chunks()
    monkeypatch.setattr(providers, 'completion', stream)
    response = client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'x'}], 'stream':True})
    assert response.status_code == 200 and '[DONE]' in response.text
    rows = client.get('/admin/usage', headers=admin()).json()
    error = next(x for x in rows if x['operation'] == 'embedding')
    success = next(x for x in rows if x['operation'] == 'generation')
    assert error['status'] == 'error' and error['input_tokens'] is None
    assert success['status'] == 'success' and success['input_tokens'] == 7 and success['output_tokens'] == 2


def test_usage_snapshots_survive_model_changes(context, monkeypatch):
    client, _ = context
    provider_id, model_id, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'operation':'embedding','currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fail(config, data): raise TimeoutError()
    monkeypatch.setattr(providers, 'embedding', fail)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'private text'})
    assert response.status_code == 504
    other = client.post('/admin/providers', headers=admin(), json={'name':'new-provider','provider_type':'openai','api_key':'other-fake-secret'}).json()['id']
    assert client.put(f'/admin/models/{model_id}', headers=admin(), json={'alias':'new-alias','provider_id':other,'upstream_model':'different-model','operations':['embedding']}).status_code == 200
    usage = client.get('/admin/usage/requests', headers=admin()).json()[0]
    pending = client.get('/admin/budget-reservations', headers=admin()).json()[0]
    for row in (usage, pending):
        assert (row['provider_id_snapshot'], row['provider_type_snapshot'], row['provider_name_snapshot'], row['upstream_model_snapshot']) == (provider_id, 'exaone', 'LG', 'k-exaone_v2.5')
        assert row['requested_alias'] == 'exaone-chat'
        assert 'private text' not in str(row) and 'provider-secret' not in str(row)


def test_truncated_and_failed_streams_never_emit_done_or_settle(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    cases = ['truncated','error_chunk','exception','no_choices']
    async def fake(config, data):
        case = cases.pop(0)
        async def chunks():
            yield {'model':'upstream','choices':[{'index':0,'delta':{'content':'partial'},'finish_reason':None}]}
            if case == 'error_chunk': yield {'error':{'message':'sensitive upstream error'},'choices':[]}
            if case == 'exception': raise RuntimeError('sensitive upstream exception')
            if case == 'no_choices': yield {'invalid':'chunk'}
        return chunks()
    monkeypatch.setattr(providers, 'completion', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    for _ in range(4):
        response = client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}],'stream':True})
        assert response.status_code == 200 and 'Provider stream failed' in response.text
        assert '[DONE]' not in response.text and 'sensitive' not in response.text
        assert 'partial' in response.text and 'exaone-chat' in response.text
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 4 and all(r['status'] == 'error' and r['estimated_cost'] is None for r in records)
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.4') and Decimal(budget['spent_amount']) == 0


@pytest.mark.parametrize('chunks', [
    [{'choices':[{'index':0,'delta':{'role':'user'},'finish_reason':'stop'}]}],
    [{'choices':[{'index':0,'delta':{'content':{'text':'bad'}},'finish_reason':'stop'}]}],
    [{'choices':[{'index':0,'delta':None,'finish_reason':'stop'}]}],
    [{'choices':[{'index':0,'delta':{},'finish_reason':'stop'}, {'index':0,'delta':{},'finish_reason':'stop'}]}],
    [{'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}, {'choices':[{'index':0,'delta':{'content':'late'},'finish_reason':None}]}],
    [{'choices':[{'index':0,'delta':{'tool_calls':[{'index':0,'function':{'arguments':{}}}]},'finish_reason':'stop'}]}],
    [{'choices':[{'index':0,'delta':{},'finish_reason':True}]}],
])
def test_malformed_stream_is_not_settled(context, monkeypatch, chunks):
    from decimal import Decimal
    client, _ = context
    _, model_id, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fake(config, data):
        async def stream():
            for chunk in chunks:
                yield chunk
            yield {'choices':[], 'usage':{'prompt_tokens':1,'completion_tokens':1}}
        return stream()
    monkeypatch.setattr(providers, 'completion', fake)
    result = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'x'}],'stream':True})
    assert result.status_code == 200 and 'Provider stream failed' in result.text and '[DONE]' not in result.text
    usage = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert usage['status'] == 'error' and usage['estimated_cost'] is None
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


def test_incremental_function_tool_stream(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    async def fake(config, data):
        async def stream():
            yield {'choices':[{'index':0,'delta':{'role':'assistant','tool_calls':[{'index':0,'id':'call_1','type':'function','function':{'name':'lookup','arguments':''}}]},'finish_reason':None}]}
            yield {'choices':[{'index':0,'delta':{'tool_calls':[{'index':0,'function':{'arguments':'{"q":1}'}}]},'finish_reason':None}]}
            yield {'choices':[{'index':0,'delta':{},'finish_reason':'tool_calls'}]}
        return stream()
    monkeypatch.setattr(providers, 'completion', fake)
    result = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'x'}],'stream':True})
    assert result.status_code == 200 and '[DONE]' in result.text and 'Provider stream failed' not in result.text


def test_all_stream_choices_must_finish_before_settlement(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    cases = iter(['complete', 'incomplete', 'missing_index'])
    async def fake(config, data):
        case = next(cases)
        async def chunks():
            yield {'choices':[{'index':0, 'delta':{}, 'finish_reason':'stop'}, {'index':1, 'delta':{'content':'partial'}, 'finish_reason':None}]}
            if case == 'complete':
                yield {'choices':[{'index':1, 'delta':{}, 'finish_reason':'stop'}], 'usage':{'prompt_tokens':10,'completion_tokens':10}}
            if case == 'missing_index':
                yield {'choices':[{'delta':{}, 'finish_reason':'stop'}]}
        return chunks()
    monkeypatch.setattr(providers, 'completion', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    payload = {'model':'exaone-chat','messages':[{'role':'user','content':'test'}],'stream':True}
    responses = [client.post('/v1/chat/completions', headers=auth, json=payload) for _ in range(3)]
    assert '[DONE]' in responses[0].text and 'Provider stream failed' not in responses[0].text
    assert all('[DONE]' not in response.text and 'Provider stream failed' in response.text for response in responses[1:])
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert sum(row['status'] == 'success' for row in records) == 1
    assert sum(row['status'] == 'error' and row['estimated_cost'] is None for row in records) == 2
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.2') and Decimal(budget['spent_amount']) == Decimal('0.00002')


@pytest.mark.parametrize(('operation', 'path', 'payload'), [
    ('embedding', '/v1/embeddings', {'model':'exaone-chat','input':'test'}),
    ('generation', '/v1/chat/completions', {'model':'exaone-chat','messages':[{'role':'user','content':'test'}],'stream':True}),
])
def test_provider_stall_before_response_times_out_without_settlement(context, monkeypatch, operation, path, payload):
    import asyncio
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client)
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'operation':operation,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    cancelled = []
    async def stalled(config, data):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)
    monkeypatch.setattr(providers, 'embedding' if operation == 'embedding' else 'completion', stalled)
    monkeypatch.setattr(providers, 'UPSTREAM_TIMEOUT_SECONDS', 0.05)
    response = client.post(path, headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 504 and response.json()['error']['code'] == 'provider_timeout'
    assert cancelled == [True]
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


@pytest.mark.parametrize('worker_fails', [False, True])
def test_cancelled_model_selection_waits_for_worker_before_session_cleanup(worker_fails):
    import asyncio
    import threading
    from app.main import db_work
    entered, release = threading.Event(), threading.Event()
    def worker():
        entered.set()
        assert release.wait(5)
        if worker_fails: raise RuntimeError('private worker error')
    async def run():
        task = asyncio.create_task(db_work(worker))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
    try:
        asyncio.run(run())
    finally:
        release.set()


def test_cancel_during_reservation_finalizes_without_provider_dispatch(context, monkeypatch):
    import asyncio
    import threading
    from app import observability
    from app.main import EmbeddingIn, invoke
    client, db = context
    _, _, issued = configure(client, ['embedding'])
    entered, release = threading.Event(), threading.Event()
    original_begin = observability.begin
    def delayed_begin(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original_begin(*args, **kwargs)
    monkeypatch.setattr(observability, 'begin', delayed_begin)
    calls = []
    async def fake(config, data):
        calls.append(True)
        return {'data':mock_vectors(data['input'])}
    async def run():
        with Session(db) as session:
            key = session.get(ClientKey, issued['id'])
            task = asyncio.create_task(invoke(EmbeddingIn(model='exaone-chat', input='test'), 'embedding', session, key, fake))
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
    try:
        asyncio.run(run())
    finally:
        release.set()
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert not calls and len(records) == 1 and records[0]['status'] == 'interrupted'


def test_stalled_stream_times_out_and_preserves_reservation(context, monkeypatch):
    import asyncio
    from decimal import Decimal
    from app import observability
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    closed = []
    async def fake(config, data):
        async def chunks():
            try:
                yield {'choices':[{'index':0,'delta':{'content':'partial'},'finish_reason':None}]}
                await asyncio.Event().wait()
            finally:
                closed.append(True)
        return chunks()
    monkeypatch.setattr(providers, 'completion', fake)
    monkeypatch.setattr(observability, 'UPSTREAM_TIMEOUT_SECONDS', 0.05)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}],'stream':True})
    assert response.status_code == 200 and 'partial' in response.text and 'Provider stream failed' in response.text
    assert '[DONE]' not in response.text and closed == [True]
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0


def test_client_stream_close_marks_interrupted_and_closes_provider(monkeypatch):
    import asyncio
    import time
    from app import observability, circuits
    recorded, closed = [], []
    monkeypatch.setattr(observability, 'end', lambda bind, request_id, started, status, usage: recorded.append(status))
    monkeypatch.setattr(circuits, 'record', lambda *args: recorded.append('circuit'))
    async def source():
        try:
            yield {'choices':[{'index':0,'delta':{'content':'partial'},'finish_reason':None}]}
            yield {'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
        finally:
            closed.append(True)
    async def run():
        stream = observability.tracked_stream(source(), 'alias', None, 'id', time.monotonic(), (1,'generation',1))
        assert 'partial' in await anext(stream)
        await stream.aclose()
    asyncio.run(run())
    assert recorded == ['interrupted'] and closed == [True]


def test_stream_cleanup_runs_if_finalization_is_cancelled(monkeypatch):
    import asyncio
    import threading
    import time
    from app import observability, circuits
    entered, release = threading.Event(), threading.Event()
    events = []
    def delayed_end(bind, request_id, started, status, usage):
        entered.set()
        assert release.wait(5)
        events.append(status)
    monkeypatch.setattr(observability, 'end', delayed_end)
    monkeypatch.setattr(circuits, 'record', lambda *args: None)
    class Source:
        sent = False
        def __aiter__(self): return self
        async def __anext__(self):
            if self.sent: raise StopAsyncIteration
            self.sent = True
            return {'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
        async def aclose(self): events.append('closed')
    async def run():
        stream = observability.tracked_stream(Source(), 'alias', None, 'id', time.monotonic(), (1,'generation',1))
        await anext(stream)
        assert '[DONE]' in await anext(stream)
        task = asyncio.create_task(anext(stream))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
    try:
        asyncio.run(run())
    finally:
        release.set()
    assert events == ['success', 'closed']


@pytest.mark.parametrize('cleanup', ['hang', 'raise'])
def test_stream_cleanup_failure_cannot_prevent_finalization(monkeypatch, caplog, cleanup):
    import asyncio
    import time
    from app import observability, circuits
    events = []
    monkeypatch.setattr(observability, 'STREAM_CLOSE_TIMEOUT_SECONDS', 0.03)
    monkeypatch.setattr(observability, 'end', lambda bind, request_id, started, status, usage: events.append(('end', status)))
    monkeypatch.setattr(circuits, 'record', lambda *args: events.append(('circuit', args[-1])))

    class Source:
        def __init__(self): self.sent = False
        def __aiter__(self): return self
        async def __anext__(self):
            if self.sent: raise StopAsyncIteration
            self.sent = True
            return {'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
        async def aclose(self):
            events.append(('close', None))
            if cleanup == 'raise': raise RuntimeError('secret provider detail')
            await asyncio.Event().wait()

    async def run():
        return [part async for part in observability.tracked_stream(Source(), 'alias', None, 'id', time.monotonic(), (1,'generation',1))]

    output = asyncio.run(run())
    assert output[-1] == 'data: [DONE]\n\n'
    assert events == [('end', 'success'), ('circuit', False), ('close', None)]
    assert 'secret provider detail' not in caplog.text


def test_rate_limit_expiration_and_live_access_updates(context, monkeypatch):
    from datetime import datetime, timedelta, timezone
    client, _ = context
    provider_id, model_id, key = configure(client, ['embedding'])
    auth = {'Authorization': 'Bearer '+key['key']}
    calls = []
    async def fake_embedding(config, data):
        calls.append(1)
        return {'model': 'test', 'data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', fake_embedding)
    update = {'name': 'test', 'model_ids': [model_id], 'requests_per_minute': 1}
    assert client.put('/admin/api-keys/'+str(key['id']), headers=admin(), json=update).status_code == 200
    payload = {'model':'exaone-chat', 'input':'text'}
    assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 200
    denied = client.post('/v1/embeddings', headers=auth, json=payload)
    assert denied.status_code == 429 and int(denied.headers['retry-after']) in range(1, 61)
    assert len(calls) == 1
    assert client.put('/admin/providers/'+str(provider_id)+'/active', headers=admin(), json={'active':False}).status_code == 200
    assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 403
    assert client.put('/admin/providers/'+str(provider_id)+'/active', headers=admin(), json={'active':True}).status_code == 200
    assert client.put('/admin/models/'+str(model_id)+'/active', headers=admin(), json={'active':False}).status_code == 200
    assert client.get('/v1/models', headers=auth).json()['data'] == []
    assert client.put('/admin/models/'+str(model_id)+'/active', headers=admin(), json={'active':True}).status_code == 200
    update['expires_at'] = (datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat()
    assert client.put('/admin/api-keys/'+str(key['id']), headers=admin(), json=update).status_code == 200
    assert client.get('/v1/models', headers=auth).status_code == 401
    assert client.put('/admin/api-keys/'+str(key['id']), headers=admin(), json={**update, 'expires_at':'2030-01-01T00:00:00'}).status_code == 422
    actions = [x['action'] for x in client.get('/admin/audit', headers=admin()).json()]
    assert 'api_key.update' in actions and 'model.deactivate' in actions and 'provider.deactivate' in actions


def test_admin_bootstrap_sessions_and_audit(context):
    client, db = context
    payload = {'username': 'admin', 'password': 'correct horse battery staple'}
    assert client.post('/admin/users', json=payload).status_code == 401
    assert client.post('/admin/users', headers=admin(), json=payload).status_code == 201
    assert client.get('/admin/providers', headers=admin()).status_code == 401
    assert client.post('/admin/sessions', json={**payload, 'password':'wrong password for this account'}).status_code == 401
    session = client.post('/admin/sessions', json=payload)
    assert session.status_code == 201 and session.headers['cache-control'] == 'no-store'
    headers = {'Authorization': 'Bearer '+session.json()['token']}
    assert client.get('/admin/providers', headers=headers).status_code == 200
    assert client.post('/admin/providers', headers=headers, json={'name':'test', 'provider_type':'exaone', 'api_key':'sensitive'}).status_code == 201
    audit = client.get('/admin/audit', headers=headers).json()
    assert any(x['action'] == 'provider.create' and x['actor'] == 'admin:1' for x in audit)
    assert any(x['action'] == 'admin.login.failed' for x in audit)
    assert payload['password'] not in str(audit)
    assert client.delete('/admin/sessions/current', headers=headers).status_code == 204
    assert client.get('/admin/providers', headers=headers).status_code == 401


def test_admin_login_throttling(context, monkeypatch):
    from datetime import datetime, timezone
    from sqlalchemy import literal
    from app import rate_limit
    # Avoid crossing a real minute boundary while running the ten Scrypt checks.
    monkeypatch.setattr(rate_limit.func, 'current_timestamp', lambda: literal(datetime(2026, 1, 1, 12, 0, 10, tzinfo=timezone.utc)))
    client, _ = context
    payload = {'username': 'unknown-user', 'password': 'not-the-right-password'}
    for _ in range(10):
        assert client.post('/admin/sessions', json=payload).status_code == 401
    response = client.post('/admin/sessions', json=payload)
    assert response.status_code == 429 and 1 <= int(response.headers['retry-after']) <= 60


def test_cost_uses_registered_price_and_preserves_unknown_usage(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model_id, key = configure(client, ['embedding'])
    response = client.post('/admin/prices', headers=admin(), json={'model_id': model_id, 'currency': 'USD', 'basis':'tokens', 'input_per_million': '1.00', 'output_per_million': '0'})
    assert response.status_code == 201
    auth = {'Authorization': 'Bearer '+key['key']}
    async def known(config, data):
        return {'model':'upstream', 'data':mock_vectors(data['input']), 'usage': {'prompt_tokens': 1000}}
    monkeypatch.setattr(providers, 'embedding', known)
    assert client.post('/v1/embeddings', headers=auth, json={'model':'exaone-chat','input':'x'}).status_code == 200
    async def unknown(config, data):
        return {'model':'upstream', 'data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', unknown)
    assert client.post('/v1/embeddings', headers=auth, json={'model':'exaone-chat','input':'x'}).status_code == 200
    rows = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(rows) == 2
    assert sum(Decimal(str(r['estimated_cost'])) for r in rows if r['estimated_cost'] is not None) == Decimal('0.001')
    assert sum(r['estimated_cost'] is None for r in rows) == 1
    assert any(x['action'] == 'price.create' for x in client.get('/admin/audit', headers=admin()).json())


def test_multi_operation_model_uses_operation_specific_prices(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'openai-pricing','provider_type':'openai','api_key':'fake'}).json()['id']
    model = client.post('/admin/models', headers=admin(), json={'alias':'multi','provider_id':provider,'upstream_model':'model','operations':['generation']}).json()['id']
    # Historical multi-operation model, retained by migration.
    with Session(context[1]) as session:
        session.add_all([ModelCapability(model_id=model, operation='embedding', api_mode='embeddings'), ModelCapability(model_id=model, operation='decision', api_mode='decisions')])
        session.commit()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'multi','model_ids':[model]}).json()
    token_price = {'model_id':model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'2'}
    assert client.post('/admin/prices', headers=admin(), json=token_price).status_code == 422
    assert client.post('/admin/prices', headers=admin(), json={**token_price,'operation':'generation'}).status_code == 201
    assert client.post('/admin/prices', headers=admin(), json={**token_price,'operation':'embedding','input_per_million':'100','output_per_million':'0'}).status_code == 201
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'operation':'decision','currency':'USD','basis':'question','per_question':'0.2'}).status_code == 201
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'operation':'embedding','currency':'USD','basis':'question','per_question':'0.2'}).status_code == 422
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.01'}).status_code == 200
    async def completion(config, data): return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}], 'usage':{'prompt_tokens':100,'completion_tokens':20}}
    async def embedding(config, data): return {'data':mock_vectors(data['input']), 'usage':{'prompt_tokens':100}}
    async def decision(config, data): return {'answers':[{'type':'predicate','name':'q','probability':0.5}], 'usage':{'input_tokens':100,'output_tokens':0}}
    monkeypatch.setattr(providers, 'completion', completion)
    monkeypatch.setattr(providers, 'embedding', embedding)
    monkeypatch.setattr(providers, 'decision', decision)
    auth = {'Authorization':'Bearer '+key['key']}
    assert client.post('/v1/chat/completions', headers=auth, json={'model':'multi','messages':[{'role':'user','content':'hi'}]}).status_code == 200
    assert client.post('/v1/embeddings', headers=auth, json={'model':'multi','input':'hi'}).status_code == 200
    assert client.post('/v1/decisions', headers=auth, json={'model':'multi','input':'hi','questions':[{'type':'predicate','name':'q','instructions':'yes?'}]}).status_code == 200
    records = {r['operation']:r for r in client.get('/admin/usage/requests', headers=admin()).json()}
    assert Decimal(records['generation']['estimated_cost']) == Decimal('0.00014')
    assert Decimal(records['embedding']['estimated_cost']) == Decimal('0.01')
    assert Decimal(records['decision']['estimated_cost']) == Decimal('0.2')
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['spent_amount']) == Decimal('0.21014') and Decimal(budget['held_amount']) == 0
    assert {p['operation'] for p in client.get('/admin/prices', headers=admin()).json()} == {'generation','embedding','decision'}


def test_decision_question_pricing(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure_jev(client)
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'], 'currency':'KRW', 'basis':'question', 'per_question':'1.25'}).status_code == 201
    async def fake(config, data):
        return {'model':'jev', 'answers':[{'type':'predicate','name':q['name'],'probability':0.5} for q in data['questions']]}
    monkeypatch.setattr(providers, 'decision', fake)
    questions = [{'type':'predicate','name':f'q{i}','instructions':'Question?'} for i in range(2)]
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'text','questions':questions}).status_code == 200
    row = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert Decimal(str(row['estimated_cost'])) == Decimal('2.5') and row['currency'] == 'KRW'


def test_decision_validates_answers_and_preserves_refusals(context, monkeypatch):
    from copy import deepcopy
    from decimal import Decimal
    client, _ = context
    _, model, key = configure_jev(client)
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    questions = [
        {'type':'predicate','name':'p','instructions':'yes?'},
        {'type':'choice','name':'c','instructions':'pick','choices':[{'value':True},{'value':'maybe'}]},
        {'type':'score','name':'s','instructions':'rate','levels':[{'label':'low'},{'label':'high'}]},
        {'type':'box','name':'b','instructions':'locate'},
    ]
    good = [
        {'type':'predicate','name':'p','probability':0.7},
        {'type':'choice','name':'c','choice':True,'confidence':0.9,'probabilities':[{'value':True,'probability':0.8},{'value':'maybe','probability':0.2}]},
        {'type':'score','name':'s','score':0.6,'confidence':0.8,'probabilities':[{'value':0,'label':'low','probability':0.4},{'value':1,'label':'high','probability':0.6}]},
        {'type':'box','name':'b','box':{'left':0.1,'top':0.1,'right':0.8,'bottom':0.9},'confidence':None},
    ]
    responses = []
    async def fake(config, data): return {'answers':responses.pop(0),'usage':{'input_tokens':2}}
    monkeypatch.setattr(providers, 'decision', fake)
    headers = {'Authorization':'Bearer '+key['key'],'TypeSafe-Danger-Zone-Images':'true'}
    payload = {'model':'judge','input':'sample','questions':questions}
    responses.append(deepcopy(good))
    assert client.post('/v1/decisions', headers=headers, json=payload).status_code == 200
    refused = deepcopy(good); refused[2] = {'type':'refusal','name':'s'}
    responses.append(refused)
    assert client.post('/v1/decisions', headers=headers, json=payload).json()['answers'][2]['type'] == 'refusal'
    bad = []
    bad.append(good[:-1])
    item = deepcopy(good); item[0]['name'] = 'other'; bad.append(item)
    item = deepcopy(good); item[0]['probability'] = 1.1; bad.append(item)
    item = deepcopy(good); item[1]['choice'] = 'invalid'; bad.append(item)
    item = deepcopy(good); item[1]['probabilities'][1]['value'] = True; bad.append(item)
    item = deepcopy(good); item[2]['score'] = 2; bad.append(item)
    item = deepcopy(good); item[2]['probabilities'][1]['label'] = 'wrong'; bad.append(item)
    item = deepcopy(good); item[3]['box']['left'] = 0.9; bad.append(item)
    item = deepcopy(good); item[3]['confidence'] = float('nan'); bad.append(item)
    responses.extend(bad)
    for _ in bad:
        assert client.post('/v1/decisions', headers=headers, json=payload).status_code == 502
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['spent_amount']) == Decimal('0.08') and Decimal(budget['held_amount']) == Decimal('0.1') * len(bad)
    assert len(client.get('/admin/budget-reservations', headers=admin()).json()) == len(bad)


def test_admin_last_account_and_password_reset(context):
    client, _ = context
    assert client.post('/admin/users', headers=admin(), json={'username':'first', 'password':'a very secure password'}).status_code == 201
    token = client.post('/admin/sessions', json={'username':'first', 'password':'a very secure password'}).json()['token']
    auth = {'Authorization':'Bearer '+token}
    assert client.put('/admin/users/1/active', headers=auth, json={'active':False}).status_code == 409
    assert client.post('/admin/users', headers=auth, json={'username':'second', 'password':'another secure password'}).status_code == 201
    assert client.put('/admin/users/2/active', headers=auth, json={'active':False}).status_code == 200
    assert client.put('/admin/users/1/password', headers=auth, json={'password':'new secure password'}).status_code == 200
    assert client.get('/admin/users', headers=auth).status_code == 401
    assert client.post('/admin/sessions', json={'username':'first', 'password':'new secure password'}).status_code == 201


def test_additional_provider_presets_and_slash_model_ids(context, monkeypatch):
    client, _ = context
    p = client.post('/admin/providers', headers=admin(), json={'name':'router', 'provider_type':'openrouter', 'api_key':'secret'})
    assert p.status_code == 201
    model = {'alias':'router-model','provider_id':p.json()['id'],'upstream_model':'openai/example-model', 'operations':['generation']}
    assert client.post('/admin/models', headers=admin(), json=model).status_code == 201
    assert client.post('/admin/models', headers=admin(), json={**model, 'alias':'bad', 'upstream_model':'openai/../secret'}).status_code == 422
    assert client.post('/admin/providers', headers=admin(), json={'name':'bad', 'provider_type':'arbitrary', 'api_key':'secret'}).status_code == 422
    assert providers.provider_arguments('openrouter', 'openai/example-model', 'secret')['model'] == 'openrouter/openai/example-model'


@pytest.mark.parametrize('provider_type,base,prefix', [
    ('kimi_coding_global','https://api.kimi.ai/coding/v1','openai'),
    ('kimi_coding_china','https://api.kimi.com/coding/v1','openai'),
    ('zai_coding','https://api.z.ai/api/coding/paas/v4','openai'),
    ('bigmodel_coding','https://open.bigmodel.cn/api/coding/paas/v4','openai'),
    ('moonshot_global','https://api.moonshot.ai/v1','moonshot'),
    ('moonshot_china','https://api.moonshot.cn/v1','moonshot'),
    ('qwen_singapore','https://dashscope-intl.aliyuncs.com/compatible-mode/v1','openai'),
    ('qwen_china','https://dashscope.aliyuncs.com/compatible-mode/v1','openai'),
    ('siliconflow_global','https://api.siliconflow.com/v1','openai'),
    ('siliconflow_china','https://api.siliconflow.cn/v1','openai'),
    ('minimax_global','https://api.minimax.io/v1','minimax'),
    ('minimax_china','https://api.minimaxi.com/v1','minimax'),
    ('venice','https://api.venice.ai/api/v1','openai'),
])
def test_regional_provider_preset_is_fixed_and_key_is_not_returned(context, monkeypatch, provider_type, base, prefix):
    client, _ = context
    response = client.post('/admin/providers', headers=admin(), json={'name':'regional','provider_type':provider_type,'api_key':'regional-secret'})
    assert response.status_code == 201
    listing = client.get('/admin/providers', headers=admin()).json()
    assert listing[0]['base_url'] == base and 'regional-secret' not in str(listing)
    model = client.post('/admin/models', headers=admin(), json={'alias':'regional-model','provider_id':response.json()['id'],'upstream_model':'example/test-model','operations':['generation']})
    assert model.status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'regional-key','model_ids':[model.json()['id']]}).json()['key']
    seen = []
    async def fake(config, data): seen.append(config); return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    assert client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key}, json={'model':'regional-model','messages':[{'role':'user','content':'test'}]}).status_code == 200
    assert seen[0]['api_base'] == base and seen[0]['model'] == prefix + '/example/test-model' and seen[0]['api_key'] == 'regional-secret'
    assert client.post('/admin/providers', headers=admin(), json={'name':'bad','provider_type':provider_type,'api_key':'x','base_url':'https://evil.invalid'}).status_code == 422


@pytest.mark.parametrize('provider_type', ['kimi_coding_global','kimi_coding_china','zai_coding','bigmodel_coding'])
def test_coding_model_registration_is_generation_only(context, provider_type):
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'kimi','provider_type':provider_type}).json()
    base = {'alias':'kimi-model','provider_id':provider['id'],'upstream_model':'kimi-model'}
    for operations in (['embedding'], ['decision'], ['generation','embedding']):
        assert client.post('/admin/models', headers=admin(), json={**base,'operations':operations}).status_code == 422
    created = client.post('/admin/models', headers=admin(), json={**base,'operations':['generation']})
    assert created.status_code == 201
    assert client.put('/admin/models/'+str(created.json()['id']), headers=admin(),
                      json={**base,'operations':['embedding']}).status_code == 422


@pytest.mark.parametrize(('provider_type','base'), [
    ('cerebras','https://api.cerebras.ai/v1'), ('sambanova','https://api.sambanova.ai/v1'),
    ('nvidia_nim','https://integrate.api.nvidia.com/v1'), ('novita','https://api.novita.ai/v3/openai'),
    ('moonshot_global','https://api.moonshot.ai/v1'), ('moonshot_china','https://api.moonshot.cn/v1'),
    ('minimax_global','https://api.minimax.io/v1'), ('minimax_china','https://api.minimaxi.com/v1'),
    ('zai','https://api.z.ai/api/paas/v4'), ('bigmodel','https://open.bigmodel.cn/api/paas/v4'),
    ('synthetic','https://api.synthetic.new/openai/v1'), ('chutes','https://llm.chutes.ai/v1'),
    ('perplexity','https://api.perplexity.ai'),
])
def test_native_catalog_generation_transport_without_network(context, monkeypatch, provider_type, base):
    import importlib
    import json
    import httpx
    import httpx2
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':provider_type,'provider_type':provider_type,'api_key':'fake'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'native','provider_id':provider['id'],
                        'upstream_model':'mock-model','operations':['generation']}).json()
    issued = client.post('/admin/api-keys', headers=admin(), json={'name':'native','model_ids':[model['id']]}).json()
    observed, request_models = [], []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            observed.append(str(url))
            body = kwargs.get('json') or json.loads(kwargs.get('data') or kwargs.get('content'))
            request_models.append(body['model'])
            return httpx.Response(200, request=httpx.Request('POST',url), json={'id':'mock', 'object':'chat.completion',
                'created':1, 'model':'mock-model', 'choices':[{'index':0,'message':{'role':'assistant','content':'mock'},'finish_reason':'stop'}],
                'usage':{'prompt_tokens':2,'completion_tokens':1,'total_tokens':3}})
    def handler(request):
        observed.append(str(request.url))
        request_models.append(json.loads(request.content)['model'])
        return httpx2.Response(200, json={'id':'mock','object':'chat.completion','created':1,'model':'mock-model',
            'choices':[{'index':0,'message':{'role':'assistant','content':'mock'},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':2,'completion_tokens':1,'total_tokens':3}})
    openai_adapter = importlib.import_module('litellm.llms.openai.openai').OpenAIChatCompletion
    monkeypatch.setattr(openai_adapter, '_get_async_http_client', staticmethod(lambda **kwargs: httpx2.AsyncClient(transport=httpx2.MockTransport(handler))))
    monkeypatch.setattr(openai_adapter, 'get_cached_openai_client', lambda *args, **kwargs: None)
    monkeypatch.setattr(providers.litellm, 'module_level_aclient', FakeHTTP())
    monkeypatch.setattr(importlib.import_module('litellm.llms.custom_httpx.llm_http_handler'), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+issued['key']},
                           json={'model':'native','messages':[{'role':'user','content':'hello'}]})
    assert response.status_code == 200, (provider_type,response.text)
    assert observed == [base+'/chat/completions']
    assert request_models == ['mock-model']
    assert response.json()['choices'][0]['message']['content'] == 'mock'


def test_oversized_body_is_rejected_before_parsing(context):
    client, _ = context
    response = client.post('/v1/embeddings', content=b'x' * (2 * 1024 * 1024 + 1), headers={'Content-Type':'application/json'})
    assert response.status_code == 413


def test_real_litellm_decision_preparation_without_http(context, monkeypatch):
    import importlib
    client, _ = context
    _, _, key = configure_jev(client)
    decisions_module = importlib.import_module('litellm.decisions.main')
    seen = []
    async def fake_transport(call):
        seen.append(call)
        return {'model':'jev-latest', 'answers':[{'type':'predicate','name':'urgent','probability':0.8}]}
    monkeypatch.setattr(decisions_module, 'asend', fake_transport)
    response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'example','questions':[{'type':'predicate','name':'urgent','instructions':'Is this urgent?'}]})
    assert response.status_code == 200, response.text
    assert seen and response.json()['answers'][0]['probability'] == 0.8


def test_typesafe_image_and_box_contract_without_http(context, monkeypatch):
    import base64
    import importlib
    client, _ = context
    provider_id, model, key = configure_jev(client)
    model_data = {'alias':'judge','provider_id':provider_id['id'],'upstream_model':'jev-1.14.0','operations':['decision']}
    assert client.put('/admin/models/'+str(model['id']), headers=admin(), json=model_data).status_code == 200
    decision_module = importlib.import_module('litellm.decisions.main')
    seen = []
    async def fake_transport(call):
        seen.append(call)
        return {'model':'jev-1.14.0', 'answers':[{'type':'box','name':'object','box':{'left':0.1,'top':0.2,'right':0.7,'bottom':0.8},'confidence':0.9}]}
    monkeypatch.setattr(decision_module, 'asend', fake_transport)
    fake_png = base64.b64encode(b'\x89PNG\r\n\x1a\nmock image').decode()
    payload = {'model':'judge','input':[{'type':'message','role':'user','content':[{'type':'input_text','text':'find the object'}, {'type':'input_image','image_url':'data:image/png;base64,'+fake_png}]}], 'questions':[{'type':'box','name':'object','instructions':'Find the object'}]}
    auth = {'Authorization':'Bearer '+key['key']}
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 400
    opt_in = {**auth, 'TypeSafe-Danger-Zone-Images':'true'}
    response = client.post('/v1/decisions', headers=opt_in, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()['answers'][0]['type'] == 'box'
    call = seen[0]
    assert any(k.lower() == 'typesafe-danger-zone-images' and v == 'true' for k,v in call.headers.items())
    upstream = call.provider_config.transform_decisions_request(call.model, call.ir_request, call.custom_llm_provider)
    assert fake_png in str(upstream['assets']) and 'find the object' in str(upstream['state'])
    payload['input'][0]['content'][1]['image_url'] = 'https://127.0.0.1/secret'
    assert client.post('/v1/decisions', headers=opt_in, json=payload).status_code == 400
    payload['input'][0]['content'][1]['image_url'] = 'data:image/png;base64,@@@'
    assert client.post('/v1/decisions', headers=opt_in, json=payload).status_code == 400
    payload['input'][0]['content'][1]['image_url'] = 'data:image/jpeg;base64,' + fake_png
    assert client.post('/v1/decisions', headers=opt_in, json=payload).status_code == 400
    assert len(seen) == 1


def test_typesafe_image_complete_adapter_roundtrip_without_http(context, monkeypatch):
    import base64
    import importlib
    import httpx
    client, _ = context
    provider, model, key = configure_jev(client)
    assert client.put('/admin/models/'+str(model['id']), headers=admin(), json={'alias':'judge','provider_id':provider['id'],'upstream_model':'jev-1.14.0','operations':['decision']}).status_code == 200
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    seen = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            seen.append((url, kwargs))
            return httpx.Response(200, json={'model':'jev-1.14.0','answers':{'object':{'type':'box','box':{'left':0.1,'top':0.2,'right':0.7,'bottom':0.8},'confidence':0.9}},'usage':{'input_tokens':20,'output_tokens':0}})
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    encoded = base64.b64encode(b'\x89PNG\r\n\x1a\nmock image').decode()
    payload = {'model':'judge','input':[{'type':'message','role':'user','content':[{'type':'input_text','text':'find object'}, {'type':'input_image','image_url':'data:image/png;base64,'+encoded}]}], 'questions':[{'type':'box','name':'object','instructions':'Find the object'}]}
    response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key'],'TypeSafe-Danger-Zone-Images':'true'}, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()['answers'][0]['box']['right'] == 0.7
    assert len(seen) == 1 and seen[0][0] == 'https://api.typesafe.ai/v1/systemone'
    sent = seen[0][1]
    assert encoded in str(sent['json']['assets'])
    assert any(k.lower() == 'typesafe-danger-zone-images' and v == 'true' for k,v in sent['headers'].items())
    assert encoded not in str(client.get('/admin/usage/requests', headers=admin()).json())


def test_typesafe_choice_score_and_refusal_roundtrip_without_http(context, monkeypatch):
    import importlib
    import socket
    import httpx
    client, _ = context
    _, _, key = configure_jev(client)
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    captured = []
    mock_answers = {
        'predicate':{'type':'noul','noul':0.6},
        'pick':{'type':'choice','choice':'true','confidence':0.9,'probabilities':{'true':0.8,'maybe':0.2}},
        'rate':{'type':'score','score':0.7,'confidence':0.8,'legend':{'0':'low','1':'high'},'probabilities':{'0':0.3,'1':0.7}},
    }
    class FakeHTTP:
        async def post(self, url, **kwargs):
            captured.append((url, kwargs['json']))
            return httpx.Response(200, request=httpx.Request('POST',url), json={'model':'jev-latest','answers':mock_answers, 'usage':{'input_tokens':14,'output_tokens':0}})
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    questions = [
        {'type':'predicate','name':'predicate','instructions':'yes?'},
        {'type':'choice','name':'pick','instructions':'pick','choices':[{'value':True},{'value':'maybe'}]},
        {'type':'score','name':'rate','instructions':'rate','levels':[{'label':'low'},{'label':'high'}]},
        {'type':'predicate','name':'declined','instructions':'can you answer?'},
    ]
    result = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'sample','questions':questions})
    assert result.status_code == 200, result.text
    answers = result.json()['answers']
    assert [a['type'] for a in answers] == ['predicate','choice','score','refusal']
    assert answers[1]['choice'] is True and answers[1]['probabilities'][0]['value'] is True
    assert answers[2]['score'] == 0.7 and answers[2]['probabilities'][1]['label'] == 'high'
    assert answers[3]['name'] == 'declined'
    assert len(captured) == 1 and captured[0][0] == 'https://api.typesafe.ai/v1/systemone'
    assert captured[0][1]['questions']['pick']['criteria'] == {'true':None,'maybe':None}
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['status'] == 'success' and record['question_count'] == 4 and record['input_tokens'] == 14
    mock_answers['pick']['choice'] = 'unlisted'
    invalid = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'sample','questions':questions})
    assert invalid.status_code == 502 and len(captured) == 2
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert sorted(r['status'] for r in records) == ['error', 'success']


def test_typesafe_missing_usage_is_not_fabricated_or_settled(context, monkeypatch):
    import importlib
    import socket
    import httpx
    from decimal import Decimal
    client, _ = context
    _, model, key = configure_jev(client)
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'1000000','output_per_million':'1000000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'100','reserve_per_request':'1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    usage_responses = [None, {'input_tokens':5}, {'input_tokens':5,'output_tokens':2}, {'input_tokens':0,'output_tokens':0}]
    class FakeHTTP:
        async def post(self, url, **kwargs):
            usage = usage_responses.pop(0)
            payload = {'model':'jev-latest','answers':{'q':{'type':'noul','noul':0.9}}}
            if usage is not None: payload['usage'] = usage
            return httpx.Response(200, request=httpx.Request('POST',url), json=payload)
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    auth = {'Authorization':'Bearer '+key['key']}
    body = {'model':'judge','input':'test','questions':[{'type':'predicate','name':'q','instructions':'yes?'}]}
    first = client.post('/v1/decisions', headers=auth, json=body)
    second = client.post('/v1/decisions', headers=auth, json=body)
    third = client.post('/v1/decisions', headers=auth, json=body)
    fourth = client.post('/v1/decisions', headers=auth, json=body)
    assert [r.status_code for r in (first,second,third,fourth)] == [200,200,200,200]
    assert 'usage' not in first.json()
    assert second.json()['usage']['input_tokens'] == 5 and 'output_tokens' not in second.json()['usage'] and 'total_tokens' not in second.json()['usage']
    assert third.json()['usage']['input_tokens'] == 5 and third.json()['usage']['output_tokens'] == 2
    assert fourth.json()['usage'] == {'input_tokens':0,'output_tokens':0}
    records = {r['request_id']:r for r in client.get('/admin/usage/requests', headers=admin()).json()}
    assert records[first.headers['x-request-id']]['input_tokens'] is None
    assert records[second.headers['x-request-id']]['output_tokens'] is None and records[second.headers['x-request-id']]['estimated_cost'] is None
    assert Decimal(records[third.headers['x-request-id']]['estimated_cost']) == Decimal(7)
    assert Decimal(records[fourth.headers['x-request-id']]['estimated_cost']) == 0
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == 2 and Decimal(budget['spent_amount']) == 7


@pytest.mark.parametrize('upstream_status,expected_status,raise_status', [(429, 429, True), (429, 429, False), (500, 502, True), (500, 502, False), (200, 502, False)])
@pytest.mark.parametrize('provider_type', ['typesafe', 'openai'])
def test_decision_upstream_failure_records_no_sensitive_data(context, monkeypatch, upstream_status, expected_status, raise_status, provider_type):
    import importlib
    import socket
    import httpx
    client, _ = context
    from decimal import Decimal
    if provider_type == 'typesafe':
        _, model, key = configure_jev(client)
    else:
        provider = client.post('/admin/providers', headers=admin(), json={'name':'openai-test','provider_type':'openai','api_key':'jev-secret'}).json()
        model = client.post('/admin/models', headers=admin(), json={'alias':'judge','provider_id':provider['id'],'upstream_model':'gpt-test','operations':['decision']}).json()
        key = client.post('/admin/api-keys', headers=admin(), json={'name':'judge-key','model_ids':[model['id']]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'operation':'decision','currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'1'}).status_code == 200
    def no_network(*args, **kwargs):
        raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    class FakeHTTP:
        async def post(self, url, **kwargs):
            request = httpx.Request('POST', url)
            answers = ({'q':{'type':'noul','noul':0.9}} if provider_type == 'typesafe'
                       else [{'type':'predicate','name':'q','probability':0.9}])
            response = httpx.Response(upstream_status, request=request, json={'model':'jev-latest',
                'answers':answers, 'usage':{'input_tokens':1,'output_tokens':0},
                'error':'private provider error'})
            if raise_status:
                raise httpx.HTTPStatusError('private provider error', request=request, response=response)
            return response
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']},
        json={'model':'judge','input':'private customer text','questions':[{'type':'predicate','name':'q','instructions':'yes?'}]})
    assert response.status_code == expected_status
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'error' and records[0]['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == 1 and Decimal(budget['spent_amount']) == 0
    audit = client.get('/admin/audit', headers=admin()).json()
    assert all(secret not in str([response.json(), records, audit]) for secret in
               ('private customer text', 'private provider error', 'jev-secret', key['key']))


def test_typesafe_reported_zero_is_conservatively_unknown():
    value = {'usage':{'input_tokens':5,'output_tokens':0,'total_tokens':5}}
    providers.normalize_decision_usage(value)
    assert value['usage'] == {'input_tokens':5}


@pytest.mark.parametrize(('usage','expected'), [
    (None, None), ({'input_tokens':0, 'output_tokens':0, 'total_tokens':0}, {'input_tokens':0, 'output_tokens':0, 'total_tokens':0}),
    ({'input_tokens':5}, {'input_tokens':5}), ({'input_tokens':True, 'output_tokens':2}, {'output_tokens':2}),
    ({'input_tokens':5,'output_tokens':2,'total_tokens':9}, {'input_tokens':5,'output_tokens':2}),
    ({'input_tokens':5,'output_tokens':2,'input_tokens_details':{'cached_tokens':1}}, {'output_tokens':2}),
    ({'input_tokens':5,'output_tokens':2,'cached_tokens':1}, {'output_tokens':2}),
    ({'input_tokens':5,'output_tokens':2,'output_tokens_details':{'reasoning_tokens':1}}, {'input_tokens':5}),
    ({'input_tokens':-1,'output_tokens':2147483648}, None),
])
def test_decision_raw_usage_validation(usage, expected):
    assert providers.reported_decision_counts(usage) == expected


def test_decision_usage_provenance_is_request_scoped(monkeypatch):
    import asyncio
    import importlib
    import socket
    import httpx
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    class FakeHTTP:
        async def post(self, url, **kwargs):
            value = kwargs['headers']['X-Usage-Test']
            await asyncio.sleep(0)
            payload = {'model':'jev-latest','answers':{'q':{'type':'noul','noul':0.9}}}
            if value != 'missing': payload['usage'] = {'input_tokens':int(value),'output_tokens':0}
            return httpx.Response(200, request=httpx.Request('POST',url), json=payload)
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    async def run():
        async def one(value):
            result = await providers.decision({'model':'typesafe/jev-latest','api_key':'fake','extra_headers':{'X-Usage-Test':value}},
                {'input':'test','questions':[{'type':'predicate','name':'q','instructions':'yes?'}]})
            data = providers.as_dict(result)
            providers.apply_decision_usage(data, result)
            return data.get('usage')
        return await asyncio.gather(*(one(value) for value in ('0','9','missing','3')))
    assert asyncio.run(run()) == [
        {'input_tokens':0,'output_tokens':0}, {'input_tokens':9,'output_tokens':0}, None, {'input_tokens':3,'output_tokens':0}]


def test_openai_decision_adapter_roundtrip_without_network(context, monkeypatch):
    import base64
    import importlib
    import socket
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'openai-mock','provider_type':'openai','api_key':'fake-key'}).json()['id']
    model = client.post('/admin/models', headers=admin(), json={'alias':'openai-judge','provider_id':provider,'upstream_model':'gpt-6-luna','operations':['decision']})
    assert model.status_code == 201
    issued = client.post('/admin/api-keys', headers=admin(), json={'name':'openai','model_ids':[model.json()['id']]}).json()
    key = issued['key']
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model.json()['id'],'operation':'decision','currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{issued['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    handler = importlib.import_module('litellm.llms.custom_httpx.llm_http_handler')
    captured = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            captured.append((url, kwargs))
            return httpx.Response(200, request=httpx.Request('POST',url), json={'model':'gpt-6-luna','answers':[{'type':'predicate','name':'safe','probability':0.9}], 'usage':{'input_tokens':12,'output_tokens':0,'total_tokens':12}})
    monkeypatch.setattr(handler, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    png = base64.b64encode(b'\x89PNG\r\n\x1a\nmock').decode()
    payload = {'model':'openai-judge','input':[{'type':'message','role':'user','content':[{'type':'input_text','text':'test'},{'type':'input_image','image_url':'data:image/png;base64,'+png}]}], 'questions':[{'type':'predicate','name':'safe','instructions':'safe?'}]}
    response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key}, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()['answers'][0]['probability'] == 0.9
    assert captured[0][0] == 'https://api.openai.com/v1/decisions'
    assert captured[0][1]['json']['model'] == 'gpt-6-luna'
    assert not any(name.lower().startswith('typesafe-danger') for name in captured[0][1]['headers'])
    row = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert row['input_tokens'] == 12 and row['output_tokens'] == 0 and row['question_count'] == 1
    assert row['estimated_cost'] is not None
    blocked = client.post('/v1/decisions', headers={'Authorization':'Bearer '+key}, json={**payload,'questions':[{'type':'box','name':'b','instructions':'find'}]})
    assert blocked.status_code == 400 and len(captured) == 1


def test_decision_route_selects_eligible_provider_before_dispatch(context, monkeypatch):
    import base64
    client, _ = context
    tp, jev, _ = configure_jev(client)
    op = client.post('/admin/providers', headers=admin(), json={'name':'openai','provider_type':'openai','api_key':'fake'}).json()['id']
    other = client.post('/admin/models', headers=admin(), json={'alias':'openai-judge','provider_id':op,'upstream_model':'gpt-6-luna','operations':['decision']}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'judges','operation':'decision','targets':[{'model_id':jev['id'],'priority':0},{'model_id':other,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'both','model_ids':[jev['id'],other]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append(config)
        if data['questions'][0]['type'] == 'box':
            return {'answers':[{'type':'box','name':'box','box':{'left':0.1,'right':0.9,'top':0.1,'bottom':0.9},'confidence':0.8}]}
        return {'answers':[{'type':'predicate','name':'q','probability':0.9}]}
    monkeypatch.setattr(providers, 'decision', fake)
    png = base64.b64encode(b'\x89PNG\r\n\x1a\nmock').decode()
    body = {'model':'judges','input':[{'type':'message','role':'user','content':[{'type':'input_image','image_url':'data:image/png;base64,'+png}]}], 'questions':[{'type':'predicate','name':'q','instructions':'yes?'}]}
    auth = {'Authorization':'Bearer '+key}
    assert client.post('/v1/decisions', headers=auth, json=body).status_code == 200
    assert calls[-1]['model'] == 'openai/gpt-6-luna' and 'extra_headers' not in calls[-1]
    assert client.post('/v1/decisions', headers={**auth,'TypeSafe-Danger-Zone-Images':'true'}, json=body).status_code == 200
    assert calls[-1]['model'] == 'typesafe/jev-latest' and calls[-1]['extra_headers']['TypeSafe-Danger-Zone-Images'] == 'true'
    box_body = {**body, 'questions':[{'type':'box','name':'box','instructions':'locate'}]}
    assert client.post('/v1/decisions', headers=auth, json=box_body).status_code == 400
    assert client.post('/v1/decisions', headers={**auth,'TypeSafe-Danger-Zone-Images':'true'}, json=box_body).status_code == 200
    assert calls[-1]['model'] == 'typesafe/jev-latest' and len(calls) == 3
    anthropic = client.post('/admin/providers', headers=admin(), json={'name':'anthropic','provider_type':'anthropic','api_key':'fake'}).json()['id']
    assert client.post('/admin/models', headers=admin(), json={'alias':'not-supported','provider_id':anthropic,'upstream_model':'mock','operations':['decision']}).status_code == 422


def test_openai_compatible_error_and_timeout(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client, ['embedding'])
    async def timeout(config, data):
        raise TimeoutError('sensitive')
    monkeypatch.setattr(providers, 'embedding', timeout)
    auth = {'Authorization': 'Bearer ' + key['key']}
    response = client.post('/v1/embeddings', headers=auth, json={'model': 'exaone-chat', 'input': 'x'})
    assert response.status_code == 504
    assert response.json()['error']['code'] == 'provider_timeout'
    assert 'sensitive' not in response.text and response.headers['x-request-id']
    assert client.get('/v1/models').json()['error']['type'] == 'authentication_error'


def test_model_updates_preserve_grants_and_usage_filters(context, monkeypatch):
    from datetime import datetime, timezone, timedelta
    client, _ = context
    provider_id, model_id, key = configure(client, ['embedding'])
    auth = {'Authorization': 'Bearer ' + key['key']}
    model = {'alias':'new-embedding','provider_id':provider_id,'upstream_model':'embed-v2','operations':['embedding']}
    response = client.put('/admin/models/'+str(model_id), headers=admin(), json=model)
    assert response.status_code == 200 and response.json()['alias'] == 'new-embedding'
    async def fake(config, data):
        return {'model':'embed-v2','data':mock_vectors(data['input']), 'usage':{'prompt_tokens':4}}
    monkeypatch.setattr(providers, 'embedding', fake)
    assert client.post('/v1/embeddings', headers=auth, json={'model':'new-embedding', 'input':'x'}).status_code == 200
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=1)).isoformat()
    end = (now + timedelta(days=1)).isoformat()
    assert len(client.get('/admin/usage', headers=admin(), params={'start': start, 'end': end, 'model_id':model_id, 'operation':'embedding'}).json()) == 1
    assert client.get('/admin/usage/requests', headers=admin(), params={'model_id': model_id+1}).json() == []
    assert client.get('/admin/usage', headers=admin(), params={'start':'2026-01-01T00:00:00'}).status_code == 422
    assert any(a['action'] == 'model.update' for a in client.get('/admin/audit', headers=admin()).json())


def test_custom_provider_is_strictly_allowlisted(context, monkeypatch):
    client, _ = context
    monkeypatch.setenv('MAGPIE_ALLOWED_PROVIDER_BASES', 'https://allowed.example/v1,https://127.0.0.1/v1')
    body = {'name':'custom', 'provider_type':'openai_compatible', 'api_key':'secret', 'base_url':'https://allowed.example/v1'}
    assert client.post('/admin/providers', headers=admin(), json=body).status_code == 201
    assert providers.provider_arguments('openai_compatible', 'model', 'key', body['base_url'])['api_base'] == body['base_url']
    assert client.post('/admin/providers', headers=admin(), json={**body, 'name':'other', 'base_url':'https://evil.example/v1'}).status_code == 422
    assert client.post('/admin/providers', headers=admin(), json={**body, 'name':'private', 'base_url':'https://127.0.0.1/v1'}).status_code == 422
    monkeypatch.delenv('MAGPIE_ALLOWED_PROVIDER_BASES')
    with pytest.raises(ValueError):
        providers.provider_arguments('openai_compatible', 'model', 'key', body['base_url'])


def test_pricing_is_invalidated_when_model_deployment_changes(context, monkeypatch):
    client, _ = context
    provider_id, model_id, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id, 'currency':'USD', 'basis':'tokens', 'input_per_million':'5', 'output_per_million':'0'}).status_code == 201
    async def fake(config, data):
        return {'model':'upstream','data':mock_vectors(data['input']), 'usage':{'prompt_tokens':1000}}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    assert client.post('/v1/embeddings', headers=auth, json={'model':'exaone-chat','input':'x'}).status_code == 200
    assert client.put('/admin/models/'+str(model_id), headers=admin(), json={'alias':'exaone-chat','upstream_model':'new-model','provider_id':provider_id,'operations':['embedding']}).status_code == 200
    assert client.post('/v1/embeddings', headers=auth, json={'model':'exaone-chat','input':'x'}).status_code == 200
    rows = client.get('/admin/usage/requests', headers=admin()).json()
    assert len([x for x in rows if x['estimated_cost'] is None]) == 1
    assert len([x for x in rows if x['estimated_cost'] is not None]) == 1


def test_encryption_key_rotation_is_atomic(context, monkeypatch):
    from app.rotate_key import rotate
    client, db = context
    pid, _, _ = configure(client)
    old = __import__('os').environ['MAGPIE_ENCRYPTION_KEY']
    new = Fernet.generate_key().decode()
    with Session(db) as session:
        original = session.get(ProviderConnection, pid).encrypted_api_key
        with pytest.raises(ValueError):
            rotate(session, Fernet.generate_key().decode(), new)
        assert session.get(ProviderConnection, pid).encrypted_api_key == original
        assert rotate(session, old, new) == 1
        changed = session.get(ProviderConnection, pid).encrypted_api_key
        assert Fernet(new.encode()).decrypt(changed.encode()) == b'provider-secret'
    monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', new)


def test_encryption_rotation_preserves_pending_sso_and_rejects_mixed_keys(context, monkeypatch):
    import os
    from datetime import datetime, timedelta, timezone
    from app import oidc
    from app.models import OIDCTransaction
    from app.rotate_key import rotate
    from app.security import hash_key
    client, db = context
    provider_id, _, _ = configure(client)
    old = os.environ['MAGPIE_ENCRYPTION_KEY']
    new = Fernet.generate_key().decode()
    settings = oidc.OIDCConfig('https://id.example','https://id.example/auth','https://id.example/token','https://id.example/keys','client','https://app.example/callback',None)
    with Session(db) as session:
        started = oidc.start(session, settings)
        state_hash = hash_key(started['state'])
        original_provider = session.get(ProviderConnection, provider_id).encrypted_api_key
        original_verifier = session.get(OIDCTransaction, state_hash).encrypted_verifier
        alien = Fernet.generate_key()
        session.add(OIDCTransaction(state_hash='invalid-active', browser_hash='x', nonce_hash='x',
            encrypted_verifier=Fernet(alien).encrypt(b'other').decode(), expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), used=False))
        session.add(OIDCTransaction(state_hash='expired', browser_hash='x', nonce_hash='x',
            encrypted_verifier=Fernet(alien).encrypt(b'expired').decode(), expires_at=datetime.now(timezone.utc) - timedelta(minutes=5), used=False))
        session.commit()
        expired_verifier = session.get(OIDCTransaction, 'expired').encrypted_verifier
        with pytest.raises(ValueError): rotate(session, old, new)
        assert session.get(ProviderConnection, provider_id).encrypted_api_key == original_provider
        assert session.get(OIDCTransaction, state_hash).encrypted_verifier == original_verifier
        session.delete(session.get(OIDCTransaction, 'invalid-active'))
        session.commit()
        assert rotate(session, old, new) == 1
        assert Fernet(new.encode()).decrypt(session.get(ProviderConnection, provider_id).encrypted_api_key.encode()) == b'provider-secret'
        monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', new)
        verifier, _ = oidc.consume(session, started['state'], started['browser_secret'])
        assert verifier and session.get(OIDCTransaction, state_hash).used is True
        assert session.get(OIDCTransaction, 'expired').encrypted_verifier == expired_verifier


def test_provider_key_rotation_invalidates_model_evidence_atomically(context, monkeypatch):
    from app import circuits
    client, db = context
    provider_id, first, key = configure(client)
    second = client.post('/admin/models', headers=admin(), json={'alias':'second','provider_id':provider_id,'upstream_model':'second','operations':['embedding']}).json()['id']
    other_provider = client.post('/admin/providers', headers=admin(), json={'name':'other','provider_type':'openai','api_key':'other-key'}).json()['id']
    other = client.post('/admin/models', headers=admin(), json={'alias':'unrelated','provider_id':other_provider,'upstream_model':'test','operations':['generation']}).json()['id']
    initial = {m['id']:m for m in client.get('/admin/models', headers=admin()).json()}
    for model_id, operation in [(first,'generation'),(first,'embedding'),(second,'embedding'),(other,'generation')]:
        result = client.put(f'/admin/models/{model_id}/capabilities/{operation}/verification', headers=admin(), json={'status':'mock_verified','note':'fixture','expected_version':initial[model_id]['verification_version']})
        assert result.status_code == 200
    for _ in range(circuits.FAILURE_THRESHOLD):
        circuits.record(db, first, 'generation', initial[first]['verification_version'], True)
    assert client.get('/admin/model-circuits', headers=admin()).json()[0]['cooling_down']
    assert client.put(f'/admin/providers/{provider_id}/key', headers=admin(), json={'api_key':'new-provider-secret'}).status_code == 200
    models = {m['id']:m for m in client.get('/admin/models', headers=admin()).json()}
    for model_id in (first,second):
        assert models[model_id]['verification_version'] == initial[model_id]['verification_version'] + 1
        assert all(c['verification_status'] == 'unverified' for c in models[model_id]['capabilities'])
    assert models[other]['verification_version'] == initial[other]['verification_version']
    assert models[other]['capabilities'][0]['verification_status'] == 'mock_verified'
    assert client.get('/admin/model-circuits', headers=admin()).json() == []
    assert client.put(f'/admin/models/{first}/capabilities/generation/verification', headers=admin(), json={'status':'mock_verified','note':'stale','expected_version':initial[first]['verification_version']}).status_code == 409
    history = client.get(f'/admin/models/{first}/verification-history', headers=admin()).json()
    assert sum(event['note'] == 'Provider credential changed' and event['status'] == 'unverified' for event in history) == 2
    assert 'new-provider-secret' not in str(history)
    calls = []
    async def fake(config, data): calls.append(config); return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    assert client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'hello'}]}).status_code == 200
    assert calls[0]['api_key'] == 'new-provider-secret'


def test_capability_verification_history_and_invalidation(context):
    client, _ = context
    provider_id, model_id, _ = configure(client, ['generation', 'embedding'])
    models = client.get('/admin/models', headers=admin()).json()
    model = next(m for m in models if m['id'] == model_id)
    assert {c['operation']: c['verification_status'] for c in model['capabilities']} == {'generation':'unverified', 'embedding':'unverified'}
    url = f'/admin/models/{model_id}/capabilities/embedding/verification'
    body = {'status':'mock_verified', 'note':'Contract fixtures', 'expected_version':model['verification_version']}
    assert client.put(url, json=body).status_code == 401
    assert client.put(url, headers=admin(), json=body).status_code == 200
    assert client.put(f'/admin/models/{model_id}/capabilities/decision/verification', headers=admin(), json=body).status_code == 404
    model_body = {'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'k-exaone_v2.5','operations':['generation','embedding'], 'description':'Only description changed'}
    updated = client.put(f'/admin/models/{model_id}', headers=admin(), json=model_body).json()
    assert updated['verification_version'] == model['verification_version']
    assert next(c for c in updated['capabilities'] if c['operation'] == 'embedding')['verification_status'] == 'mock_verified'
    updated = client.put(f'/admin/models/{model_id}', headers=admin(), json={**model_body,'embedding_max_batch_size':10}).json()
    assert updated['verification_version'] == model['verification_version'] + 1
    assert next(c for c in updated['capabilities'] if c['operation'] == 'embedding')['verification_status'] == 'unverified'
    assert client.put(url, headers=admin(), json=body).status_code == 409
    body['expected_version'] = updated['verification_version']
    assert client.put(url, headers=admin(), json={**body, 'status':'provider_verified', 'note':'operator evidence'}).status_code == 200
    changed = client.put(f'/admin/models/{model_id}', headers=admin(), json={**model_body, 'upstream_model':'other', 'operations':['embedding']}).json()
    assert next(c for c in changed['capabilities'] if c['operation'] == 'embedding')['verification_status'] == 'unverified'
    events = client.get(f'/admin/models/{model_id}/verification-history', headers=admin()).json()
    assert [event['status'] for event in events] == ['unverified','provider_verified','unverified','mock_verified']
    assert any(a['action'] == 'capability.verification' for a in client.get('/admin/audit', headers=admin()).json())


def test_model_capability_metadata_and_declared_feature_rejection(context):
    client, _ = context
    provider_id, model_id, key = configure(client, ['generation'])
    body = {'alias':'exaone-chat', 'provider_id':provider_id, 'upstream_model':'k-exaone_v2.5', 'operations':['generation'], 'supports_streaming':False, 'supports_tools':False, 'max_input_tokens':1000}
    result = client.put('/admin/models/'+str(model_id), headers=admin(), json=body)
    assert result.status_code == 200 and result.json()['max_input_tokens'] == 1000
    auth = {'Authorization':'Bearer '+key['key']}
    response = client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'x'}],'stream':True})
    assert response.status_code == 400
    response = client.post('/v1/chat/completions', headers=auth, json={'model':'exaone-chat','messages':[{'role':'user','content':'x'}],'tools':[{'type':'function','function':{'name':'test'}}]})
    assert response.status_code == 400
    assert client.get('/admin/usage/requests', headers=admin()).json() == []
    assert client.put('/admin/models/'+str(model_id), headers=admin(), json={**body, 'embedding_dimensions':768}).status_code == 422


def test_metrics_report_counts_and_require_admin(context, monkeypatch):
    client, _ = context
    _, model_id, key = configure(client, ['embedding'])
    async def fake(config, data): return {'model':'upstream','data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', fake)
    assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'x'}).status_code == 200
    assert client.get('/admin/metrics').status_code == 401
    metrics = client.get('/admin/metrics', headers=admin(), params={'model_id':model_id}).json()
    assert metrics['requests'] == 1 and metrics['success'] == 1 and metrics['errors'] == 0
    assert metrics['average_duration_ms'] is not None


def test_request_reservation_and_audit_cursor_pagination(context, monkeypatch):
    from datetime import datetime, timezone
    from app.models import UsageRecord
    client, db = context
    _, model, key = configure_jev(client)
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'10','reserve_per_request':'0.1'}).status_code == 200
    async def fail(config, data): raise TimeoutError()
    monkeypatch.setattr(providers, 'decision', fail)
    body = {'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'yes?'}]}
    for _ in range(5):
        assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json=body).status_code == 504
    with Session(db) as session:
        for row in session.query(UsageRecord): row.started_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        session.commit()
    def all_pages(path, params=None):
        params = dict(params or {}, limit=2)
        results = []
        while True:
            page = client.get(path, headers=admin(), params=params)
            assert page.status_code == 200, page.text
            rows = page.json()
            if not rows: break
            results.extend(rows)
            last = rows[-1]
            timestamp = last['started_at']
            if not timestamp.endswith('Z') and '+' not in timestamp[10:]: timestamp += '+00:00'
            params.update(before_started_at=timestamp, before_request_id=last['request_id'])
        return results
    records = all_pages('/admin/usage/requests', {'status':'error'})
    reservations = all_pages('/admin/budget-reservations')
    ids = [row['request_id'] for row in records]
    assert len(ids) == len(set(ids)) == 5 and ids == sorted(ids, reverse=True)
    assert [row['request_id'] for row in reservations] == ids
    for path in ['/admin/usage/requests','/admin/budget-reservations']:
        assert client.get(path, headers=admin(), params={'before_request_id':'x'}).status_code == 422
        assert client.get(path, headers=admin(), params={'before_started_at':'2026-01-01T00:00:00','before_request_id':'x'}).status_code == 422
    first = client.get('/admin/audit', headers=admin(), params={'limit':2}).json()
    second = client.get('/admin/audit', headers=admin(), params={'limit':2,'before_id':first[-1]['id']}).json()
    assert len(first) == len(second) == 2 and first[-1]['id'] > second[0]['id']
    assert client.get('/admin/audit', headers=admin(), params={'before_id':0}).status_code == 422


def test_operational_status_thresholds_and_stale_reservations(context, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.models import UsageRecord
    client, db = context
    _, model, key = configure_jev(client)
    assert client.get('/admin/operational-status').status_code == 401
    assert client.put('/admin/operational-policy', headers=admin(), json={'size_warning_bytes':1,'stale_after_minutes':10,'stale_count_warning':1}).status_code == 200
    assert client.put('/admin/operational-policy', headers=admin(), json={'size_warning_bytes':0,'stale_after_minutes':10,'stale_count_warning':1}).status_code == 422
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def fail(config, data): raise TimeoutError()
    monkeypatch.setattr(providers, 'decision', fail)
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'test?'}]}).status_code == 504
    with Session(db) as session:
        usage = session.query(UsageRecord).one()
        usage.started_at = datetime.now(timezone.utc) - timedelta(minutes=11)
        usage.status = 'started'
        session.commit()
    status = client.get('/admin/operational-status', headers=admin()).json()
    assert status['database_size_bytes'] is None and status['size_warning'] is None
    assert status['stale_started_requests'] == status['stale_pending_reservations'] == 1 and status['stale_warning'] is True
    assert client.put('/admin/operational-policy', headers=admin(), json={'size_warning_bytes':None,'stale_after_minutes':30,'stale_count_warning':1}).status_code == 200
    assert client.get('/admin/operational-status', headers=admin()).json()['stale_warning'] is False
    assert any(a['action'] == 'operational.policy.update' for a in client.get('/admin/audit', headers=admin()).json())


@pytest.mark.parametrize('usage', [
    {'prompt_tokens': 2147483648},
    {'prompt_tokens': -1},
    {'prompt_tokens': True},
    {'prompt_tokens': [1]},
    {'prompt_tokens': 2, 'input_tokens': 3},
    {'prompt_tokens': 2, 'total_tokens': 1},
    {'prompt_tokens': 2, 'total_tokens': 2147483648},
])
def test_invalid_provider_usage_keeps_budget_reserved(context, monkeypatch, usage):
    from decimal import Decimal
    client, _ = context
    _, model_id, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id, 'currency':'USD', 'basis':'tokens', 'input_per_million':'10000', 'output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fake(config, data):
        return {'model':'mock', 'data':mock_vectors(data['input']), 'usage':usage}
    monkeypatch.setattr(providers, 'embedding', fake)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'x'})
    assert response.status_code == 200
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['status'] == 'success' and record['input_tokens'] is None and record['total_tokens'] is None and record['estimated_cost'] is None
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.1') and Decimal(budget['spent_amount']) == 0
    assert len(client.get('/admin/budget-reservations', headers=admin()).json()) == 1


def test_budget_reservation_settlement_and_manual_reconciliation(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    _, model, key = configure_jev(client)
    auth = {'Authorization': 'Bearer ' + key['key']}
    assert client.put('/admin/api-keys/'+str(key['id'])+'/budget', headers=admin(), json={'currency':'USD','limit_amount':'0.04','reserve_per_request':'0.02'}).status_code == 200
    payload = {'model':'judge','input':'sample','questions':[{'type':'predicate','name':'x','instructions':'yes?'}]}
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 503  # No price configured.
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def success(config, data): return {'model':'jev','answers':[{'type':'predicate','name':q['name'],'probability':0.5} for q in data['questions']]}
    monkeypatch.setattr(providers, 'decision', success)
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 200
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(str(budget['spent_amount'])) == Decimal('0.01') and Decimal(str(budget['held_amount'])) == 0
    async def fail(config, data): raise RuntimeError('timeout')
    monkeypatch.setattr(providers, 'decision', fail)
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 502
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 429
    pending = client.get('/admin/budget-reservations', headers=admin()).json()
    assert len(pending) == 1 and pending[0]['request_status'] == 'error' and pending[0]['pending_reason'] == 'request_failed'
    url = '/admin/budget-reservations/'+pending[0]['request_id']+'/reconcile'
    assert client.post(url, headers=admin(), json={'settled_amount':'0','note':'Provider confirmed no charge'}).status_code == 200
    history = client.get('/admin/budget-reservations/'+pending[0]['request_id']+'/adjustments', headers=admin()).json()
    assert history['reconciliation_note'] == 'Provider confirmed no charge'
    assert history['reconciliation_actor'] == 'bootstrap' and history['reconciled_at'] is not None
    assert history['reconciliation_forced'] is False
    assert client.post(url, headers=admin(), json={'settled_amount':'0','note':'Duplicate'}).status_code == 409
    assert client.post('/v1/decisions', headers=auth, json=payload).status_code == 502
    assert any(x['action'] == 'budget.reconcile' for x in client.get('/admin/audit', headers=admin()).json())


def test_budget_failed_request_reservation_requires_explicit_force_if_started(context, monkeypatch):
    client, db = context
    _, model, key = configure_jev(client)
    assert client.put('/admin/api-keys/'+str(key['id'])+'/budget', headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def fail(config, data): raise RuntimeError('test')
    monkeypatch.setattr(providers, 'decision', fail)
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'test?'}]}).status_code == 502
    pending = client.get('/admin/budget-reservations', headers=admin()).json()[0]
    from app.models import UsageRecord
    with Session(db) as session:
        row = session.get(UsageRecord, pending['request_id']); row.status = 'started'; session.commit()
    assert client.get('/admin/budget-reservations', headers=admin()).json()[0]['pending_reason'] == 'in_progress_or_unfinished'
    url = '/admin/budget-reservations/'+pending['request_id']+'/reconcile'
    assert client.post(url, headers=admin(), json={'settled_amount':'0','note':'operator review'}).status_code == 409
    assert client.post(url, headers=admin(), json={'settled_amount':'0','note':'operator review','force_started':True}).status_code == 200
    history = client.get('/admin/budget-reservations/'+pending['request_id']+'/adjustments', headers=admin()).json()
    assert history['reconciliation_forced'] is True and history['reconciliation_actor'] == 'bootstrap'
    assert client.get('/admin/audit', headers=admin()).json()[0]['action'] == 'budget.reconcile_forced'


def test_indeterminate_usage_resolution_and_late_completion(context, monkeypatch):
    import time
    from app import observability
    from app.models import UsageRecord
    client, db = context
    _, model, key = configure_jev(client)
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def fail(config, data): raise TimeoutError()
    monkeypatch.setattr(providers, 'decision', fail)
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'test?'}]}).status_code == 504
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    request_id = record['request_id']
    url = '/admin/usage/requests/'+request_id+'/resolve'
    assert client.post(url, headers=admin(), json={'note':'checked'}).status_code == 409
    with Session(db) as session:
        row = session.get(UsageRecord, request_id); row.status = 'started'; row.finished_at = None; session.commit()
    assert client.post(url, json={'note':'checked'}).status_code == 401
    assert client.post(url, headers=admin(), json={'note':'  '}).status_code == 422
    assert client.post(url, headers=admin(), json={'note':'worker stopped'}).status_code == 200
    assert client.post(url, headers=admin(), json={'note':'duplicate'}).status_code == 409
    assert client.get('/admin/metrics', headers=admin()).json()['unknown'] == 1
    record = client.get('/admin/usage/requests', headers=admin(), params={'status':'unknown'}).json()[0]
    assert record['resolution_note'] == 'worker stopped' and record['resolution_actor'] == 'bootstrap'
    pending = client.get('/admin/budget-reservations', headers=admin()).json()[0]
    assert pending['request_status'] == 'unknown' and pending['pending_reason'] == 'result_unknown'
    reconcile = '/admin/budget-reservations/'+request_id+'/reconcile'
    assert client.post(reconcile, headers=admin(), json={'settled_amount':'0','note':'checked'}).status_code == 409
    assert any(row['action'] == 'usage.resolve_unknown' for row in client.get('/admin/audit', headers=admin()).json())
    observability.end(db, request_id, time.monotonic(), 'success', {'input_tokens':3})
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['status'] == 'success' and record['resolution_note'] == 'worker stopped'
    assert client.get('/admin/metrics', headers=admin()).json()['unknown'] == 0
    assert client.get('/admin/budget-reservations', headers=admin()).json() == []


def test_budget_adjustments_are_audited_idempotent_and_optimistic(context, monkeypatch):
    from decimal import Decimal
    from app.models import UsageRecord
    client, db = context
    _, model, key = configure_jev(client)
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def success(config, data): return {'model':'jev','answers':[{'type':'predicate','name':q['name'],'probability':0.5} for q in data['questions']]}
    monkeypatch.setattr(providers, 'decision', success)
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'test?'}]}).status_code == 200
    with Session(db) as session:
        request_id = session.query(UsageRecord).one().request_id
    url = f'/admin/budget-reservations/{request_id}/adjustments'
    adjustment = {'id':'invoice-1','expected_amount':'0.01','revised_amount':'0.025','note':'Invoice 1'}
    assert client.post(url, json=adjustment).status_code == 401
    assert client.post(url, headers=admin(), json=adjustment).status_code == 200
    assert client.post(url, headers=admin(), json=adjustment).status_code == 200
    assert client.post(url, headers=admin(), json={**adjustment, 'revised_amount':'0.03'}).status_code == 409
    assert client.post(url, headers=admin(), json={**adjustment, 'id':'invoice-2'}).status_code == 409
    assert Decimal(client.get('/admin/budgets', headers=admin()).json()[0]['spent_amount']) == Decimal('0.025')
    history = client.get(url, headers=admin()).json()
    assert len(history['adjustments']) == 1 and Decimal(history['settled_amount']) == Decimal('0.025')
    assert history['reconciliation_note'] is None and history['reconciliation_actor'] is None and history['reconciled_at'] is None
    assert client.post(url, headers=admin(), json={'id':'invoice-2','expected_amount':'0.025','revised_amount':'0','note':'Credit'}).status_code == 200
    assert Decimal(client.get('/admin/budgets', headers=admin()).json()[0]['spent_amount']) == 0
    assert any(a['action'] == 'budget.adjust' for a in client.get('/admin/audit', headers=admin()).json())


def test_retention_preserves_pending_and_budget_history(context, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.models import AuditLog, UsageRecord
    client, db = context
    _, model, key = configure_jev(client)
    assert client.put('/admin/api-keys/'+str(key['id'])+'/budget', headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'question','per_question':'0.01'}).status_code == 201
    async def fake(config, data): return {'model':'jev','answers':[{'type':'predicate','name':q['name'],'probability':0.5} for q in data['questions']]}
    monkeypatch.setattr(providers, 'decision', fake)
    assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'judge','input':'x','questions':[{'type':'predicate','name':'q','instructions':'?'}]}).status_code == 200
    old = datetime.now(timezone.utc)-timedelta(days=50)
    with Session(db) as session:
        budgeted = session.query(UsageRecord).one()
        budgeted_id = budgeted.request_id
        budgeted.started_at = old; budgeted.finished_at = old
        session.add(UsageRecord(request_id='old-finished',client_key_id=key['id'],model_id=model['id'],operation='decision',status='success',started_at=old,finished_at=old))
        session.add(UsageRecord(request_id='old-pending',client_key_id=key['id'],model_id=model['id'],operation='decision',status='started',started_at=old))
        session.add(AuditLog(created_at=old, actor='test',action='old',target_type='test',target_id='1'))
        session.commit()
    payload = {'usage_days':30, 'audit_days':30}
    preview = client.post('/admin/retention/preview', headers=admin(), json=payload).json()
    assert preview['usage_records'] == 1 and preview['audit_records'] == 1
    result = client.post('/admin/retention/apply', headers=admin(), json=payload).json()
    assert result == {'usage_records_deleted':1, 'audit_records_deleted':1}
    with Session(db) as session:
        assert session.get(UsageRecord, 'old-pending') is not None
        assert session.get(UsageRecord, budgeted_id) is not None
        assert session.get(UsageRecord, 'old-finished') is None
    assert any(x['action'] == 'retention.apply' for x in client.get('/admin/audit', headers=admin()).json())


@pytest.fixture
def oidc_setup(context, monkeypatch):
    import os
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt
    client, db = context
    for name, value in {
        'ISSUER':'https://identity.example', 'AUTHORIZATION_URL':'https://identity.example/authorize',
        'TOKEN_URL':'https://identity.example/token', 'JWKS_URL':'https://identity.example/keys',
        'CLIENT_ID':'magpie', 'REDIRECT_URI':'https://magpie.example/oidc/callback',
    }.items(): monkeypatch.setenv('MAGPIE_OIDC_'+name, value)
    account = {'username':'admin','password':'a good admin password'}
    assert client.post('/admin/users', headers=admin(), json=account).status_code == 201
    token = client.post('/admin/sessions', json=account).json()['token']
    auth = {'Authorization':'Bearer '+token}
    assert client.post('/admin/oidc-identities', headers=auth, json={'user_id':1,'subject':'subject-1'}).status_code == 201
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    public_jwk.update({'kid':'test-key','use':'sig'})
    return client, db, auth, private, {'keys':[public_jwk]}


def test_oidc_pkce_signed_token_binding_and_replay(oidc_setup, monkeypatch):
    import base64, time
    from urllib.parse import urlparse, parse_qs
    import jwt
    from app import oidc
    client, _, auth, private, jwks = oidc_setup
    start = client.post('/auth/oidc/start').json()
    params = parse_qs(urlparse(start['authorization_url']).query)
    assert params['code_challenge_method'] == ['S256'] and params['state'] == [start['state']]
    nonce = params['nonce'][0]
    async def fake_exchange(settings, code, verifier):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        assert challenge == params['code_challenge'][0] and code == 'fake-code'
        signed = jwt.encode({'iss':settings.issuer,'sub':'subject-1','aud':settings.client_id,'iat':int(time.time()),'exp':int(time.time())+300,'nonce':nonce}, private, algorithm='RS256', headers={'kid':'test-key'})
        return signed, jwks
    monkeypatch.setattr(oidc, 'exchange', fake_exchange)
    callback = {'state':start['state'], 'browser_secret':start['browser_secret'], 'code':'fake-code'}
    assert client.post('/auth/oidc/callback', json={**callback, 'browser_secret':'wrong-secret-'*4}).status_code == 400
    result = client.post('/auth/oidc/callback', json=callback)
    assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
    assert client.get('/admin/providers', headers={'Authorization':'Bearer '+result.json()['token']}).status_code == 200
    assert client.post('/auth/oidc/callback', json=callback).status_code == 400
    identity_id = client.get('/admin/oidc-identities', headers=auth).json()[0]['id']
    assert client.delete('/admin/oidc-identities/'+str(identity_id), headers=auth).status_code == 204
    assert client.get('/admin/providers', headers={'Authorization':'Bearer '+result.json()['token']}).status_code == 401
    assert client.get('/admin/providers', headers=auth).status_code == 200
    assert any(x['action']=='admin.oidc.login' for x in client.get('/admin/audit', headers=auth).json())


@pytest.mark.parametrize('claim_change', ['bad_issuer','bad_audience','bad_nonce','expired','unknown_subject','bad_signature','bad_azp'])
def test_oidc_rejects_invalid_id_tokens(oidc_setup, monkeypatch, claim_change):
    import time
    from urllib.parse import urlparse, parse_qs
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from app import oidc
    client, _, _, private, jwks = oidc_setup
    start = client.post('/auth/oidc/start').json()
    nonce = parse_qs(urlparse(start['authorization_url']).query)['nonce'][0]
    async def fake_exchange(settings, code, verifier):
        claims = {'iss':settings.issuer,'sub':'subject-1','aud':settings.client_id,'iat':int(time.time()),'exp':int(time.time())+300,'nonce':nonce}
        if claim_change == 'bad_issuer': claims['iss'] = 'https://evil.example'
        if claim_change == 'bad_audience': claims['aud'] = 'another-app'
        if claim_change == 'bad_nonce': claims['nonce'] = 'another-nonce'
        if claim_change == 'expired': claims['exp'] = int(time.time())-100
        if claim_change == 'unknown_subject': claims['sub'] = 'not-linked'
        if claim_change == 'bad_azp': claims['aud'] = ['magpie','other']; claims['azp'] = 'other'
        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048) if claim_change == 'bad_signature' else private
        return jwt.encode(claims, signer, algorithm='RS256', headers={'kid':'test-key'}), jwks
    monkeypatch.setattr(oidc, 'exchange', fake_exchange)
    response = client.post('/auth/oidc/callback', json={'state':start['state'],'browser_secret':start['browser_secret'],'code':'fake'})
    assert response.status_code == (403 if claim_change == 'unknown_subject' else 401)
    assert 'token' not in response.json()


@pytest.mark.parametrize('client_id,secret,expected_basic', [
    ('magpie', None, None),
    ('magpie', 'client-secret', 'magpie:client-secret'),
    ('id: +%', 'secret: +%/한', 'id%3A+%2B%25:secret%3A+%2B%25%2F%ED%95%9C'),
])
def test_oidc_real_exchange_with_mock_http_transport(oidc_setup, monkeypatch, client_id, secret, expected_basic):
    import base64
    import time
    from urllib.parse import urlparse, parse_qs
    import httpx, jwt
    from app import oidc
    client, _, _, private, jwks = oidc_setup
    monkeypatch.setenv('MAGPIE_OIDC_CLIENT_ID', client_id)
    if secret is not None:
        monkeypatch.setenv('MAGPIE_OIDC_CLIENT_SECRET', secret)
    else:
        monkeypatch.delenv('MAGPIE_OIDC_CLIENT_SECRET', raising=False)
    start = client.post('/auth/oidc/start').json()
    nonce = parse_qs(urlparse(start['authorization_url']).query)['nonce'][0]
    signed = jwt.encode({'iss':'https://identity.example','sub':'subject-1','aud':client_id,'iat':int(time.time()),'exp':int(time.time())+300,'nonce':nonce}, private, algorithm='RS256', headers={'kid':'test-key'})
    calls = []
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path == '/token':
            form = parse_qs(request.content.decode())
            assert form['code'] == ['offline-code'] and form['code_verifier'] and form['client_id'] == [client_id]
            if expected_basic is None:
                assert 'authorization' not in request.headers
            else:
                scheme, credentials = request.headers['authorization'].split(' ', 1)
                assert scheme == 'Basic' and base64.b64decode(credentials).decode('ascii') == expected_basic
            return httpx.Response(200, json={'id_token':signed})
        if request.url.path == '/keys': return httpx.Response(200, json=jwks)
        return httpx.Response(404)
    original = oidc.httpx.AsyncClient
    monkeypatch.setattr(oidc.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    result = client.post('/auth/oidc/callback', json={'state':start['state'],'browser_secret':start['browser_secret'],'code':'offline-code'})
    assert result.status_code == 200 and calls == [('POST','/token'),('GET','/keys')]


def test_route_respects_grants_priority_and_no_retry(context, monkeypatch):
    client, _ = context
    provider_id, first, restricted = configure(client, ['embedding'])
    client.put('/admin/models/'+str(first), headers=admin(), json={'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'k-exaone_v2.5','operations':['embedding'],'embedding_space':'space-a','embedding_dimensions':768})
    second = client.post('/admin/models', headers=admin(), json={'alias':'backup','upstream_model':'embed-v2','provider_id':provider_id,'operations':['embedding'],'embedding_space':'space-a','embedding_dimensions':768}).json()['id']
    body = {'alias':'shared-embed','operation':'embedding','targets':[{'model_id':first,'priority':0,'weight':1},{'model_id':second,'priority':1,'weight':1}]}
    route = client.post('/admin/routes', headers=admin(), json=body)
    assert route.status_code == 201
    both = client.post('/admin/api-keys', headers=admin(), json={'name':'both','model_ids':[first,second]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append(config['model'])
        return {'model':config['model'],'data':mock_vectors(data['input'], 768),'usage':{'prompt_tokens':1}}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+both}
    assert 'shared-embed' in [x['id'] for x in client.get('/v1/models', headers=auth).json()['data']]
    response = client.post('/v1/embeddings', headers=auth, json={'model':'shared-embed','input':'x'})
    assert response.status_code == 200 and response.json()['model'] == 'shared-embed'
    assert calls == ['openai/k-exaone_v2.5']
    row = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert row['model_id'] == first and row['requested_alias'] == 'shared-embed'
    assert client.put('/admin/models/'+str(first)+'/active', headers=admin(), json={'active':False}).status_code == 200
    assert client.post('/v1/embeddings', headers=auth, json={'model':'shared-embed','input':'x'}).status_code == 200
    assert calls[-1] == 'openai/embed-v2'
    assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+restricted['key']}, json={'model':'shared-embed','input':'x'}).status_code == 403
    async def fail(config, data):
        calls.append(config['model']); raise RuntimeError('failed')
    monkeypatch.setattr(providers, 'embedding', fail)
    before = len(calls)
    assert client.post('/v1/embeddings', headers=auth, json={'model':'shared-embed','input':'x'}).status_code == 502
    assert len(calls) == before + 1
    assert client.post('/admin/models', headers=admin(), json={'alias':'shared-embed','provider_id':provider_id,'upstream_model':'x','operations':['embedding']}).status_code == 409
    assert client.post('/admin/routes', headers=admin(), json={**body,'alias':'backup'}).status_code == 409


def test_route_cooldown_skips_failed_target_without_replaying_request(context, monkeypatch):
    from app import circuits
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    metadata = {'operations':['embedding'],'provider_id':provider_id,'embedding_space':'shared','embedding_dimensions':768}
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**metadata,'alias':'exaone-chat','upstream_model':'first'}).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'second','upstream_model':'second'}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'fail-route','operation':'embedding','targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'fail-key','model_ids':[first,second]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append(config['model'])
        if config['model'].endswith('/first'): raise RuntimeError('mock failure')
        return {'data':mock_vectors(data['input'], 768)}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key}
    payload = {'model':'fail-route','input':'sample'}
    for _ in range(circuits.FAILURE_THRESHOLD):
        assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 502
    assert calls == ['openai/first'] * circuits.FAILURE_THRESHOLD
    state = client.get('/admin/model-circuits', headers=admin()).json()
    assert state[0]['model_id'] == first and state[0]['cooling_down']
    assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 200
    assert calls[-1] == 'openai/second'
    assert client.delete(f'/admin/models/{first}/capabilities/embedding/circuit', headers=admin()).status_code == 204
    assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 502
    assert calls[-1] == 'openai/first'
    assert any(a['action'] == 'model.circuit.reset' for a in client.get('/admin/audit', headers=admin()).json())


def test_opt_in_route_retry_tracks_each_attempt_and_budget(context, monkeypatch):
    from decimal import Decimal
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    metadata = {'operations':['embedding'],'provider_id':provider_id,'embedding_space':'shared','embedding_dimensions':768}
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**metadata,'alias':'exaone-chat','upstream_model':'first'}).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'second','upstream_model':'second'}).json()['id']
    for model_id in [first, second]:
        assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    route = client.post('/admin/routes', headers=admin(), json={'alias':'retry-route','operation':'embedding','retry_on_failure':True,'targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]})
    assert route.status_code == 201 and route.json()['retry_on_failure'] is True
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'retry-key','model_ids':[first,second]}).json()
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'0.1','reserve_per_request':'0.02'}).status_code == 200
    calls = []
    async def fake(config, data):
        calls.append(config['model'])
        if config['model'].endswith('/first'): raise TimeoutError()
        return {'model':'second','data':mock_vectors(data['input'], 768),'usage':{'prompt_tokens':1}}
    monkeypatch.setattr(providers, 'embedding', fake)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'retry-route','input':'sample'})
    assert response.status_code == 200 and calls == ['openai/first','openai/second']
    assert response.headers['x-request-id'] != response.headers['x-attempt-id']
    records = client.get('/admin/usage/requests', headers=admin()).json()
    records = sorted([r for r in records if r['root_request_id'] == response.headers['x-request-id']], key=lambda r:r['attempt_number'])
    assert [(r['model_id'], r['status'], r['attempt_number']) for r in records] == [(first, 'error', 1), (second, 'success', 2)]
    filtered = client.get('/admin/usage/requests', headers=admin(), params={'root_request_id':response.headers['x-request-id']}).json()
    assert len(filtered) == 2 and all(r['root_request_id'] == response.headers['x-request-id'] for r in filtered)
    assert client.get('/admin/usage/requests', headers=admin(), params={'root_request_id':'invalid'}).status_code == 422
    metrics = client.get('/admin/metrics', headers=admin(), params={'key_id':key['id']}).json()
    assert metrics['unique_requests'] == 1 and metrics['attempts'] == metrics['requests'] == 2 and metrics['retry_attempts'] == 1
    assert metrics['success'] == 1 and metrics['errors'] == 1
    metrics = client.get('/admin/metrics', headers=admin(), params={'key_id':key['id'], 'status':'error'}).json()
    assert metrics['unique_requests'] == metrics['attempts'] == 1 and metrics['retry_attempts'] == 0
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    assert Decimal(budget['held_amount']) == Decimal('0.02') and Decimal(budget['spent_amount']) == Decimal('0.01')
    pending = client.get('/admin/budget-reservations', headers=admin()).json()[0]
    assert pending['request_id'] == records[0]['request_id']
    assert pending['root_request_id'] == response.headers['x-request-id'] and pending['attempt_number'] == 1
    assert pending['model_id'] == first and pending['requested_alias'] == 'retry-route'
    assert pending['currency'] == 'USD' and pending['operation'] == 'embedding' and pending['finished_at'] is not None


def test_retry_does_not_bypass_budget_or_retry_bad_request(context, monkeypatch):
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    metadata = {'operations':['embedding'],'provider_id':provider_id,'embedding_space':'same','embedding_dimensions':16}
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**metadata,'alias':'exaone-chat','upstream_model':'first'}).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'backup','upstream_model':'second'}).json()['id']
    for model_id in (first, second):
        assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'0','output_per_million':'0'}).status_code == 201
    assert client.post('/admin/routes', headers=admin(), json={'alias':'retry','operation':'embedding','retry_on_failure':True,'targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'budget','model_ids':[first,second]}).json()
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'0.02','reserve_per_request':'0.02'}).status_code == 200
    calls = []
    async def fail(config, data): calls.append(config['model']); raise TimeoutError()
    monkeypatch.setattr(providers, 'embedding', fail)
    auth = {'Authorization':'Bearer '+key['key']}
    response = client.post('/v1/embeddings', headers=auth, json={'model':'retry','input':'x'})
    assert response.status_code == 429 and len(calls) == 1 and response.headers['x-request-id']
    assert len(client.get('/admin/usage/requests', headers=admin()).json()) == 1
    class Invalid(Exception): status_code = 400
    async def invalid(config, data): calls.append(config['model']); raise Invalid()
    monkeypatch.setattr(providers, 'embedding', invalid)
    another = client.post('/admin/api-keys', headers=admin(), json={'name':'unlimited','model_ids':[first,second]}).json()
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+another['key']}, json={'model':'retry','input':'x'})
    assert response.status_code == 400 and len(calls) == 2


def test_retry_respects_revocation_and_streaming_boundary(context, monkeypatch):
    client, db = context
    provider_id, first, _ = configure(client, ['generation'])
    second = client.post('/admin/models', headers=admin(), json={'alias':'backup','provider_id':provider_id,'upstream_model':'backup','operations':['generation']}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'chat-retry','operation':'generation','retry_on_failure':True,'targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'revoked','model_ids':[first,second]}).json()
    calls = []
    async def revoke_then_fail(config, data):
        calls.append(config['model'])
        with Session(db) as session:
            session.get(ClientKey, key['id']).active = False
            session.commit()
        raise TimeoutError()
    monkeypatch.setattr(providers, 'completion', revoke_then_fail)
    payload = {'model':'chat-retry','messages':[{'role':'user','content':'hello'}]}
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 504 and len(calls) == 1
    another = client.post('/admin/api-keys', headers=admin(), json={'name':'stream','model_ids':[first,second]}).json()
    async def fail(config, data): calls.append(config['model']); raise TimeoutError()
    monkeypatch.setattr(providers, 'completion', fail)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+another['key']}, json={**payload,'stream':True})
    assert response.status_code == 504 and len(calls) == 2


def test_retry_does_not_switch_to_replacement_route(context, monkeypatch):
    from app.models import ModelRoute, RouteTarget
    client, db = context
    provider_id, first, _ = configure(client, ['generation'])
    second = client.post('/admin/models', headers=admin(), json={'alias':'backup','provider_id':provider_id,'upstream_model':'backup','operations':['generation']}).json()['id']
    route = client.post('/admin/routes', headers=admin(), json={'alias':'retry-route','operation':'generation','retry_on_failure':True,'targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'route-key','model_ids':[first,second]}).json()['key']
    calls = []
    async def rename_replace_and_fail(config, data):
        calls.append(config['model'])
        with Session(db) as session:
            session.get(ModelRoute, route['id']).alias = 'renamed-route'
            session.flush()
            session.add(ModelRoute(alias='retry-route', operation='generation', active=True, retry_on_failure=True,
                targets=[RouteTarget(model_id=second, priority=0, weight=1)]))
            session.commit()
        raise TimeoutError()
    monkeypatch.setattr(providers, 'completion', rename_replace_and_fail)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key}, json={'model':'retry-route','messages':[{'role':'user','content':'hello'}]})
    assert response.status_code == 504 and calls == ['openai/k-exaone_v2.5']
    records = client.get('/admin/usage/requests', headers=admin(), params={'root_request_id':response.headers['x-request-id']}).json()
    assert len(records) == 1 and records[0]['status'] == 'error'


def test_circuit_ignores_bad_requests_recovers_and_is_versioned(context, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.models import ModelCircuit
    client, db = context
    provider_id, model_id, key = configure(client, ['embedding'])
    auth = {'Authorization':'Bearer '+key['key']}
    payload = {'model':'exaone-chat','input':'sample'}
    class UpstreamError(Exception):
        status_code = 400
    async def bad(config, data): raise UpstreamError()
    monkeypatch.setattr(providers, 'embedding', bad)
    for _ in range(4): assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 400
    assert client.get('/admin/model-circuits', headers=admin()).json() == []
    async def fail(config, data): raise TimeoutError()
    monkeypatch.setattr(providers, 'embedding', fail)
    for _ in range(3): assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 504
    assert client.get('/admin/model-circuits', headers=admin()).json()[0]['cooling_down']
    with Session(db) as session:
        state = session.query(ModelCircuit).one()
        state.open_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    async def success(config, data): return {'data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', success)
    assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 200
    state = client.get('/admin/model-circuits', headers=admin()).json()[0]
    assert state['failure_count'] == 0 and state['open_until'] is None
    monkeypatch.setattr(providers, 'embedding', fail)
    for _ in range(3): assert client.post('/v1/embeddings', headers=auth, json=payload).status_code == 504
    assert client.put('/admin/models/'+str(model_id), headers=admin(), json={'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'new-model','operations':['embedding']}).status_code == 200
    assert client.get('/admin/model-circuits', headers=admin()).json() == []


def test_weighted_route_selection(context, monkeypatch):
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    client.put('/admin/models/'+str(first), headers=admin(), json={'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'k-exaone_v2.5','operations':['embedding'],'embedding_space':'space-a','embedding_dimensions':768})
    second = client.post('/admin/models', headers=admin(), json={'alias':'other','upstream_model':'other','provider_id':provider_id,'operations':['embedding'],'embedding_space':'space-a','embedding_dimensions':768}).json()['id']
    response = client.post('/admin/routes', headers=admin(), json={'alias':'weighted','operation':'embedding','targets':[{'model_id':first,'weight':1},{'model_id':second,'weight':3}]})
    assert response.status_code == 201
    token = client.post('/admin/api-keys', headers=admin(), json={'name':'weighted-key','model_ids':[first,second]}).json()['key']
    chosen = []
    async def fake(config, data): chosen.append(config['model']); return {'model':'x','data':mock_vectors(data['input'], 768)}
    monkeypatch.setattr(providers, 'embedding', fake)
    monkeypatch.setattr('app.main.secrets.randbelow', lambda total: total-1)
    assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+token}, json={'model':'weighted','input':'x'}).status_code == 200
    assert chosen == ['openai/other']


def test_embedding_route_skips_gemini_for_media_reference(context, monkeypatch):
    client, _ = context
    gemini = client.post('/admin/providers', headers=admin(), json={'name':'gemini','provider_type':'gemini','api_key':'fake'}).json()['id']
    other = client.post('/admin/providers', headers=admin(), json={'name':'other','provider_type':'exaone','api_key':'fake'}).json()['id']
    metadata = {'operations':['embedding'],'embedding_space':'shared','embedding_dimensions':2}
    first = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'first','provider_id':gemini,'upstream_model':'gemini-embedding-001'}).json()['id']
    second = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'second','provider_id':other,'upstream_model':'test'}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'route','operation':'embedding','targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[first,second]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append((config['model'],data['input'])); return {'data':mock_vectors(data['input'])}
    monkeypatch.setattr(providers, 'embedding', fake)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key}, json={'model':'route','input':'files/literal-text'})
    assert response.status_code == 200 and calls == [('openai/test','files/literal-text')]


def test_embedding_route_selects_target_compatible_with_batch(context, monkeypatch):
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    metadata = {'operations':['embedding'],'provider_id':provider_id,'embedding_space':'shared','embedding_dimensions':768}
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**metadata,'alias':'exaone-chat','upstream_model':'first','supports_embedding_batch':False}).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={**metadata,'alias':'second','upstream_model':'second','supports_embedding_batch':True,'embedding_max_batch_size':2}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'batch-route','operation':'embedding','targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'batch-key','model_ids':[first,second]}).json()['key']
    calls = []
    async def fake(config, data): calls.append(config['model']); return {'data':mock_vectors(data['input'], 768)}
    monkeypatch.setattr(providers, 'embedding', fake)
    auth = {'Authorization':'Bearer '+key}
    assert client.post('/v1/embeddings', headers=auth, json={'model':'batch-route','input':['a','b']}).status_code == 200
    assert calls == ['openai/second']
    assert client.post('/v1/embeddings', headers=auth, json={'model':'batch-route','input':['a','b','c']}).status_code == 400
    assert len(calls) == 1


def test_chat_refuses_provider_managed_tools_without_calling_provider(context, monkeypatch):
    client, _ = context
    _, _, key = configure(client, ['generation'])
    calls = []
    async def fake(config, data): calls.append(data); return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    auth = {'Authorization':'Bearer '+key['key']}
    body = {'model':'exaone-chat','messages':[{'role':'user','content':'hello'}]}
    forbidden = [
        {'tools':[{'type':'mcp','mcp':{'server_url':'https://example.com'}}]},
        {'tools':[{'type':'web_search'}]},
        {'tools':[{'type':'computer'}]},
        {'tools':[{'type':'function','function':{'name':'ok'},'mcp':{'server_url':'https://example.com'}}]},
        {'tool_choice':{'type':'mcp','mcp':{'server_label':'server'}}},
        {'tool_choice':'web_search'},
        {'messages':[{'role':'assistant','content':None,'tool_calls':[{'id':'x','type':'mcp','mcp':{}}]}]},
        {'messages':[{'role':'assistant','content':None,'tool_calls':[{'id':'x','type':'function','function':{'name':'x','arguments':'{}','mcp':{'url':'https://example.com'}}}]}]},
        {'messages':[{'role':'assistant','content':None,'function_call':{'name':'x','arguments':'{}','mcp':{'url':'https://example.com'}}}]},
        {'messages':[{'role':'assistant','content':None,'tool_calls':[{'id':'x','type':'function','function':{'name':'x','arguments':{'url':'https://example.com'}}}]}]},
    ]
    for extra in forbidden:
        response = client.post('/v1/chat/completions', headers=auth, json={**body,**extra})
        assert response.status_code == 400
    assert calls == []
    safe = {'tools':[{'type':'function','function':{'name':'lookup','parameters':{'type':'object','properties':{}}}}], 'tool_choice':{'type':'function','function':{'name':'lookup'}}}
    assert client.post('/v1/chat/completions', headers=auth, json={**body,**safe}).status_code == 200
    assert calls[0]['tools'] == safe['tools']
    history = [{'role':'assistant','content':None,'tool_calls':[{'id':'call-1','type':'function','function':{'name':'lookup','arguments':'{}'}}]},
               {'role':'tool','tool_call_id':'call-1','content':'result'}]
    assert client.post('/v1/chat/completions', headers=auth, json={**body,'messages':history,**safe}).status_code == 200
    assert calls[1]['messages'] == history

def test_generation_route_filters_declared_unsupported_features(context, monkeypatch):
    client, _ = context
    provider_id, first, restricted = configure(client, ['generation'])
    first_body = {'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'first','operations':['generation'], 'supports_streaming':False,'supports_tools':False,'supports_reasoning':False}
    assert client.put('/admin/models/'+str(first), headers=admin(), json=first_body).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={'alias':'backup','provider_id':provider_id,'upstream_model':'backup','operations':['generation'], 'supports_streaming':True,'supports_tools':True,'supports_reasoning':True}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'feature-route','operation':'generation','targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1}]}).status_code == 201
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'both','model_ids':[first,second]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append(config['model'])
        if data.get('stream'):
            async def chunks(): yield {'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
            return chunks()
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    base = {'model':'feature-route','messages':[{'role':'user','content':'hi'}]}
    auth = {'Authorization':'Bearer '+key}
    assert client.post('/v1/chat/completions', headers=auth, json=base).status_code == 200
    assert calls[-1] == 'openai/first'
    for option in ({'stream':True}, {'tools':[{'type':'function','function':{'name':'lookup'}}]}, {'tool_choice':'required'}, {'reasoning_effort':'high'}):
        assert client.post('/v1/chat/completions', headers=auth, json={**base,**option}).status_code == 200
        assert calls[-1] == 'openai/backup'
    histories = [
        [{'role':'assistant','content':None,'tool_calls':[{'id':'call','type':'function','function':{'name':'lookup','arguments':'{}'}}]}],
        [{'role':'tool','tool_call_id':'call','content':'result'}],
        [{'role':'assistant','content':None,'function_call':{'name':'lookup','arguments':'{}'}}],
        [{'role':'function','name':'lookup','content':'result'}],
    ]
    for history in histories:
        assert client.post('/v1/chat/completions', headers=auth, json={**base,'messages':history}).status_code == 200
        assert calls[-1] == 'openai/backup'
        before = len(calls)
        assert client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+restricted['key']}, json={'model':'exaone-chat','messages':history}).status_code == 400
        assert len(calls) == before
    before = len(calls)
    assert client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+restricted['key']}, json={**base,'stream':True}).status_code == 400
    assert len(calls) == before
    # Unknown capability is not treated as an explicit denial.
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**first_body,'supports_tools':None}).status_code == 200
    assert client.post('/v1/chat/completions', headers=auth, json={**base,'tools':[{'type':'function','function':{'name':'lookup'}}]}).status_code == 200
    assert calls[-1] == 'openai/first'


def test_generation_retry_skips_unsupported_target(context, monkeypatch):
    client, _ = context
    provider_id, first, _ = configure(client, ['generation'])
    base_model = {'provider_id':provider_id,'operations':['generation']}
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**base_model,'alias':'exaone-chat','upstream_model':'first','supports_tools':True}).status_code == 200
    second = client.post('/admin/models', headers=admin(), json={**base_model,'alias':'no-tools','upstream_model':'second','supports_tools':False}).json()['id']
    third = client.post('/admin/models', headers=admin(), json={**base_model,'alias':'tools-backup','upstream_model':'third','supports_tools':True}).json()['id']
    assert client.post('/admin/routes', headers=admin(), json={'alias':'retry-features','operation':'generation','retry_on_failure':True,'targets':[{'model_id':first,'priority':0},{'model_id':second,'priority':1},{'model_id':third,'priority':2}]}).status_code == 201
    token = client.post('/admin/api-keys', headers=admin(), json={'name':'all','model_ids':[first,second,third]}).json()['key']
    calls = []
    async def fake(config, data):
        calls.append(config['model'])
        if config['model'].endswith('/first'): raise TimeoutError()
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+token}, json={'model':'retry-features','messages':[{'role':'user','content':'hi'}],'tools':[{'type':'function','function':{'name':'lookup'}}]})
    assert response.status_code == 200 and calls == ['openai/first','openai/third']
    calls.clear()
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+token}, json={'model':'retry-features','messages':[{'role':'tool','tool_call_id':'call','content':'result'}]})
    assert response.status_code == 200 and calls == ['openai/first','openai/third']


def test_embedding_routes_require_explicit_same_space(context):
    client, _ = context
    provider_id, first, _ = configure(client, ['embedding'])
    other_body = {'alias':'other','provider_id':provider_id,'upstream_model':'other','operations':['embedding']}
    second = client.post('/admin/models', headers=admin(), json=other_body).json()['id']
    route = {'alias':'emb-route','operation':'embedding','targets':[{'model_id':first},{'model_id':second}]}
    assert client.post('/admin/routes', headers=admin(), json=route).status_code == 422
    first_body = {'alias':'exaone-chat','provider_id':provider_id,'upstream_model':'k-exaone_v2.5','operations':['embedding'], 'embedding_space':'space-a','embedding_dimensions':768}
    assert client.put('/admin/models/'+str(first), headers=admin(), json=first_body).status_code == 200
    assert client.put('/admin/models/'+str(second), headers=admin(), json={**other_body,'embedding_space':'space-b','embedding_dimensions':768}).status_code == 200
    assert client.post('/admin/routes', headers=admin(), json=route).status_code == 422
    assert client.put('/admin/models/'+str(second), headers=admin(), json={**other_body,'embedding_space':'space-a','embedding_dimensions':768}).status_code == 200
    assert client.post('/admin/routes', headers=admin(), json=route).status_code == 201
    assert client.put('/admin/models/'+str(first), headers=admin(), json={**first_body,'embedding_dimensions':1536}).status_code == 409


@pytest.mark.parametrize(('operation','raw_usage','billable'), [
    ('generation', None, False),
    ('generation', {'prompt_tokens':7}, False),
    ('generation', {'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}, True),
    ('embedding', None, False),
    ('embedding', {'prompt_tokens':7}, True),
    ('embedding', {'prompt_tokens':0}, True),
    ('embedding', {'prompt_tokens':0,'total_tokens':0}, True),
    ('embedding', {'total_tokens':7}, False),
    ('embedding', {'prompt_tokens':7,'total_tokens':3}, False),
    ('embedding', {'prompt_tokens':True,'total_tokens':1}, False),
    ('embedding', {'prompt_tokens':'7','total_tokens':7}, False),
    ('embedding', {'prompt_tokens':7,'total_tokens':7,'prompt_tokens_details':{'cached_tokens':3}}, False),
])
def test_exaone_missing_usage_does_not_settle_as_zero(context, monkeypatch, operation, raw_usage, billable):
    import socket
    from decimal import Decimal
    import httpx2
    from openai import AsyncOpenAI
    client, _ = context
    _, model_id, key = configure(client, [operation])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000' if operation == 'generation' else '0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    def handler(request):
        body = {'id':'mock','object':'chat.completion','created':1,'model':'mock','choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]} if operation == 'generation' else {'object':'list','model':'mock','data':[{'object':'embedding','index':0,'embedding':[0.1,0.2]}]}
        if raw_usage is not None: body['usage'] = raw_usage
        return httpx2.Response(200, json=body)
    original = getattr(providers, 'completion' if operation == 'generation' else 'embedding')
    async def fake_transport(config, data):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            config['client'] = AsyncOpenAI(api_key='fake', base_url='https://api.exaone.ai/v1', http_client=http, max_retries=0)
            return await original(config, data)
    monkeypatch.setattr(providers, 'completion' if operation == 'generation' else 'embedding', fake_transport)
    path = '/v1/chat/completions' if operation == 'generation' else '/v1/embeddings'
    payload = {'model':'exaone-chat','messages':[{'role':'user','content':'hello'}]} if operation == 'generation' else {'model':'exaone-chat','input':'hello'}
    response = client.post(path, headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 200, response.text
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    if billable:
        assert record['input_tokens'] == raw_usage['prompt_tokens'] and Decimal(record['estimated_cost']) == Decimal(raw_usage['prompt_tokens']) * Decimal('0.01')
        assert Decimal(budget['held_amount']) == 0
        if operation == 'generation':
            assert record['output_tokens'] == 0 and response.json()['usage']['completion_tokens'] == 0
        else:
            assert response.json()['usage']['prompt_tokens'] == raw_usage['prompt_tokens']
    else:
        assert record['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
        pending = client.get('/admin/budget-reservations', headers=admin()).json()[0]
        assert pending['pending_reason'] == 'usage_unavailable'
        assert pending['missing_input_tokens'] is (operation == 'embedding' or raw_usage is None)
        assert pending['missing_output_tokens'] is (operation == 'generation')


def test_reported_usage_capture_is_isolated_across_concurrent_calls(monkeypatch):
    import asyncio
    import json
    import socket
    import httpx2
    from openai import AsyncOpenAI
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    def handler(request):
        model = json.loads(request.content)['model']
        usage = {'first':{'prompt_tokens':7,'completion_tokens':0,'total_tokens':7},
                 'second':{'prompt_tokens':3,'completion_tokens':2,'total_tokens':5},
                 'zero':{'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}}[model]
        return httpx2.Response(200, json={'id':'mock','object':'chat.completion','created':1,'model':model,'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}],'usage':usage})
    async def run():
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            sdk = AsyncOpenAI(api_key='fake',base_url='https://api.exaone.ai/v1',http_client=http,max_retries=0)
            async def one(model):
                result = await providers.completion({'model':'openai/'+model,'api_key':'fake','client':sdk}, {'messages':[{'role':'user','content':'private'}]})
                data = providers.as_dict(result)
                providers.apply_generation_usage(data, result, 'exaone')
                return data['usage']
            return await asyncio.gather(one('first'), one('second'), one('zero'))
    assert asyncio.run(run()) == [{'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}, {'prompt_tokens':3,'completion_tokens':2,'total_tokens':5}, {'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}]


def test_reported_usage_keeps_relevant_token_details():
    class Result:
        _hidden_params = {'magpie_reported_usage': {'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}}
    data = {'usage': {'prompt_tokens':7,'completion_tokens':0,'total_tokens':7,
                      'prompt_tokens_details':{'cached_tokens':2}}}
    providers.apply_generation_usage(data, Result(), 'exaone')
    assert data['usage']['prompt_tokens_details']['cached_tokens'] == 2
    assert data['usage']['completion_tokens'] == 0


@pytest.mark.parametrize('error,expected', [(None, 200), ({'message':'private provider error'}, 502)])
def test_openai_compatible_generation_rejects_success_status_with_error(context, monkeypatch, error, expected):
    import httpx2
    from openai import AsyncOpenAI
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'operation':'generation','currency':'USD',
        'basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def handler(request):
        body = {'id':'mock','object':'chat.completion','created':1,'model':'mock',
            'choices':[{'index':0,'message':{'role':'assistant','content':'answer'},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':2,'completion_tokens':1,'total_tokens':3},'error':error}
        return httpx2.Response(200,json=body)
    actual = providers.completion
    async def fake_transport(config, data):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            config['client'] = AsyncOpenAI(api_key='fake',base_url=config['api_base'],http_client=http,max_retries=0)
            return await actual(config,data)
    monkeypatch.setattr(providers, 'completion', fake_transport)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']},
        json={'model':'exaone-chat','messages':[{'role':'user','content':'test'}]})
    assert response.status_code == expected and 'private provider error' not in response.text
    row = client.get('/admin/usage/requests',headers=admin()).json()[0]
    budget = client.get('/admin/budgets',headers=admin()).json()[0]
    if error is not None:
        assert row['status'] == 'error' and row['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert row['status'] == 'success' and Decimal(row['estimated_cost']) == Decimal('0.03') and Decimal(budget['held_amount']) == 0


@pytest.mark.parametrize('error,expected', [(None, 200), ({'message':'private provider error'}, 502)])
def test_openai_compatible_embedding_rejects_success_status_with_error(context, monkeypatch, error, expected):
    import httpx2
    from openai import AsyncOpenAI
    from decimal import Decimal
    client, _ = context
    _, model, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model,'operation':'embedding','currency':'USD',
        'basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def handler(request):
        return httpx2.Response(200,json={'object':'list','model':'mock','data':[{'object':'embedding','index':0,'embedding':[0.1,0.2]}],
                                        'usage':{'prompt_tokens':2,'total_tokens':2},'error':error})
    actual = providers.embedding
    async def fake_transport(config, data):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            config['client'] = AsyncOpenAI(api_key='fake',base_url=config['api_base'],http_client=http,max_retries=0)
            return await actual(config,data)
    monkeypatch.setattr(providers, 'embedding', fake_transport)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'test'})
    assert response.status_code == expected and 'private provider error' not in response.text
    row = client.get('/admin/usage/requests',headers=admin()).json()[0]
    budget = client.get('/admin/budgets',headers=admin()).json()[0]
    if error is not None:
        assert row['status'] == 'error' and row['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert row['status'] == 'success' and Decimal(row['estimated_cost']) == Decimal('0.02') and Decimal(budget['held_amount']) == 0


def test_exaone_litellm_wire_format_with_mock_transport():
    import asyncio, json
    import httpx2
    from openai import AsyncOpenAI
    calls = []
    def handler(request):
        calls.append((str(request.url), json.loads(request.content)))
        if request.url.path.endswith('/chat/completions'):
            return httpx2.Response(200, json={'id':'mock-chat','object':'chat.completion','created':1,'model':'k-exaone_v2.5','choices':[{'index':0,'message':{'role':'assistant','content':'hello'},'finish_reason':'stop'}],'usage':{'prompt_tokens':2,'completion_tokens':1,'total_tokens':3}})
        return httpx2.Response(200, json={'object':'list','model':'test-embedding','data':[{'object':'embedding','index':0,'embedding':[0.1,0.2]}],'usage':{'prompt_tokens':1,'total_tokens':1}})
    async def run():
        transport = httpx2.MockTransport(handler)
        async with httpx2.AsyncClient(transport=transport) as http:
            sdk = AsyncOpenAI(api_key='fake', base_url='https://api.exaone.ai/v1', http_client=http, max_retries=0)
            config = providers.provider_arguments('exaone', 'k-exaone_v2.5', 'fake')
            config['client'] = sdk
            result = await providers.completion(config, {'messages':[{'role':'user','content':'hi'}], 'stream':False})
            assert providers.as_dict(result)['choices'][0]['message']['content'] == 'hello'
            config = providers.provider_arguments('exaone', 'test-embedding', 'fake')
            config['client'] = sdk
            result = await providers.embedding(config, {'input':'hello'})
            assert providers.as_dict(result)['data'][0]['embedding'] == [0.1,0.2]
    asyncio.run(run())
    assert calls[0][0] == 'https://api.exaone.ai/v1/chat/completions'
    assert calls[0][1]['model'] == 'k-exaone_v2.5'
    assert calls[1][0] == 'https://api.exaone.ai/v1/embeddings'


@pytest.mark.parametrize('provider_type', ['qwen_singapore','qwen_china','siliconflow_global','siliconflow_china','venice','kimi_coding_global','kimi_coding_china','zai_coding','bigmodel_coding'])
def test_regional_openai_wire_format_without_network(provider_type):
    import asyncio, json
    import httpx2
    from openai import AsyncOpenAI
    config = providers.provider_arguments(provider_type, 'org/example-model', 'fake')
    captured = []
    def handler(request):
        captured.append((str(request.url), json.loads(request.content)))
        return httpx2.Response(200, json={'id':'mock','object':'chat.completion','created':1,'model':'org/example-model','choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]})
    async def run():
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            config['client'] = AsyncOpenAI(api_key='fake', base_url=config['api_base'], http_client=http, max_retries=0)
            result = await providers.completion(config, {'messages':[{'role':'user','content':'hello'}]})
            assert providers.as_dict(result)['choices'][0]['message']['content'] == 'ok'
    asyncio.run(run())
    assert captured[0][0] == config['api_base'] + '/chat/completions'
    assert captured[0][1]['model'] == 'org/example-model'


def test_exaone_litellm_stream_with_mock_transport():
    import asyncio
    import httpx2
    from openai import AsyncOpenAI
    payload = ('data: {"id":"stream-1","object":"chat.completion.chunk","created":1,"model":"k-exaone_v2.5","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}\n\n'
               'data: {"id":"stream-1","object":"chat.completion.chunk","created":1,"model":"k-exaone_v2.5","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
               'data: [DONE]\n\n')
    def handler(request):
        assert request.url.path.endswith('/chat/completions')
        return httpx2.Response(200, text=payload, headers={'content-type':'text/event-stream'})
    async def run():
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            sdk = AsyncOpenAI(api_key='fake', base_url='https://api.exaone.ai/v1', http_client=http, max_retries=0)
            config = providers.provider_arguments('exaone', 'k-exaone_v2.5', 'fake'); config['client'] = sdk
            response = await providers.completion(config, {'messages':[{'role':'user','content':'hi'}], 'stream':True})
            chunks = [providers.as_dict(chunk) async for chunk in response]
            assert any(c['choices'] and c['choices'][0]['delta'].get('content') == 'hello' for c in chunks)
    asyncio.run(run())


@pytest.mark.parametrize('ending_kind', ['complete', 'truncated', 'finish_without_done', 'hybrid_error_with_done', 'error_after_finish_with_done'])
def test_gateway_stream_runs_litellm_over_mock_transport(context, monkeypatch, ending_kind):
    import socket
    import httpx2
    from openai import AsyncOpenAI
    client, _ = context
    _, model_id, key = configure(client, ['generation'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    chunk = 'data: {"id":"stream-1","object":"chat.completion.chunk","created":1,"model":"mock","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}\n\n'
    ending = 'data: {"id":"stream-1","object":"chat.completion.chunk","created":1,"model":"mock","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n' if ending_kind != 'truncated' else ''
    if ending_kind == 'finish_without_done':
        ending = ending.replace('"choices":', '"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10},"choices":')
    if ending_kind == 'complete': ending += 'data: [DONE]\n\n'
    if ending_kind == 'hybrid_error_with_done':
        ending = ending.replace('"choices":', '"error":{"message":"private upstream error"},"choices":') + 'data: [DONE]\n\n'
    if ending_kind == 'error_after_finish_with_done':
        ending += 'data: {"error":{"message":"private upstream error"},"choices":[]}\n\ndata: [DONE]\n\n'
    observed = []
    def handler(request):
        observed.append(str(request.url))
        return httpx2.Response(200, text=chunk+ending, headers={'content-type':'text/event-stream'})
    original = providers.completion
    async def mock_transport(config, data):
        async def chunks():
            async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
                config['client'] = AsyncOpenAI(api_key='fake', base_url='https://api.exaone.ai/v1', http_client=http, max_retries=0)
                stream = await original(config, data)
                async for part in stream:
                    yield part
        return chunks()
    monkeypatch.setattr(providers, 'completion', mock_transport)
    result = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','messages':[{'role':'user','content':'hi'}],'stream':True})
    assert result.status_code == 200 and 'hello' in result.text
    assert ('[DONE]' in result.text) is (ending_kind == 'complete')
    assert ('Provider stream failed' in result.text) is (ending_kind != 'complete')
    assert 'private upstream error' not in result.text
    assert observed == ['https://api.exaone.ai/v1/chat/completions']
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['status'] == ('success' if ending_kind == 'complete' else 'error')
    assert record['input_tokens'] is None and record['output_tokens'] is None and record['estimated_cost'] is None
    assert len(client.get('/admin/budget-reservations', headers=admin()).json()) == 1


@pytest.mark.parametrize(('raw_usage','expected_cost'), [
    (None, None),
    ({'prompt_tokens':7}, None),
    ({'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}, '0.07'),
    ({'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}, '0'),
])
@pytest.mark.parametrize('provider_type', ['exaone'])
def test_openai_sdk_stream_records_only_explicit_reported_usage(context, monkeypatch, raw_usage, expected_cost, provider_type):
    import json
    import socket
    from decimal import Decimal
    import httpx2
    from openai import AsyncOpenAI
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':provider_type,'provider_type':provider_type,'api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'test-chat','provider_id':conn['id'],'upstream_model':'mock','operations':['generation']}).json()
    model_id = model['id']
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model_id]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    chunk = {'id':'stream-1','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{'content':'hello'},'finish_reason':None}]}
    finish = {'id':'stream-1','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
    usage_chunk = {'id':'stream-1','object':'chat.completion.chunk','created':1,'model':'mock','choices':[],'usage':raw_usage}
    wire = ''.join('data: '+json.dumps(value)+'\n\n' for value in ([chunk,finish] + ([usage_chunk] if raw_usage is not None else []))) + 'data: [DONE]\n\n'
    def handler(request): return httpx2.Response(200, text=wire, headers={'content-type':'text/event-stream'})
    original = providers.completion
    async def fake_transport(config, data):
        http = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        config['client'] = AsyncOpenAI(api_key='fake',base_url='https://api.exaone.ai/v1',http_client=http,max_retries=0)
        try:
            stream = await original(config, data)
        except Exception:
            await http.aclose()
            raise
        class OwnedStream:
            @property
            def magpie_usage_tracking(self): return getattr(stream, 'magpie_usage_tracking', False)
            @property
            def magpie_reported_usage(self): return getattr(stream, 'magpie_reported_usage', None)
            def __aiter__(self): return self
            async def __anext__(self): return await anext(stream)
            async def aclose(self):
                try: await stream.aclose()
                finally: await http.aclose()
        return OwnedStream()
    monkeypatch.setattr(providers, 'completion', fake_transport)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'test-chat','messages':[{'role':'user','content':'x'}],'stream':True,'stream_options':{'include_usage':True}})
    assert response.status_code == 200 and '[DONE]' in response.text and 'Provider stream failed' not in response.text
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ') and line != 'data: [DONE]']
    usage_events = [event['usage'] for event in events if event.get('usage') is not None]
    if raw_usage is None:
        assert usage_events == []
    elif expected_cost is not None:
        assert usage_events[-1]['completion_tokens'] == raw_usage['completion_tokens']
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    if expected_cost is None:
        assert record['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert Decimal(record['estimated_cost']) == Decimal(expected_cost) and Decimal(budget['held_amount']) == 0
        assert record['input_tokens'] == raw_usage['prompt_tokens'] and record['output_tokens'] == raw_usage['completion_tokens']


def test_openai_stream_closes_unconsumed_source():
    import asyncio
    class Source:
        closed = 0
        def __aiter__(self): return self
        async def __anext__(self): raise StopAsyncIteration
        async def close(self): self.closed += 1
    class Stream:
        def __init__(self, source): self.completion_stream = source
        async def aclose(self): await self.completion_stream.aclose()
    async def run():
        source = Source()
        stream = providers.OpenAIStreamProvenance(Stream(source), source)
        await stream.aclose()
        await stream.aclose()
        assert source.closed == 1
    asyncio.run(run())


@pytest.mark.parametrize('provider_type', ['exaone', 'groq', 'openrouter', 'anthropic', 'xai', 'mistral', 'together_ai', 'fireworks_ai'])
def test_unknown_stream_source_never_bills_synthetic_usage(context, monkeypatch, provider_type):
    import json
    from decimal import Decimal
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':provider_type,'provider_type':provider_type,'api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'test-chat','provider_id':conn['id'],'upstream_model':'mock','operations':['generation']}).json()
    model_id = model['id']
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model_id]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fake_completion(**kwargs):
        async def chunks():
            yield {'choices':[{'index':0,'delta':{'content':'test'},'finish_reason':None}]}
            yield {'choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
            yield {'choices':[],'usage':{'prompt_tokens':7,'completion_tokens':2,'total_tokens':9}}
        return chunks()
    monkeypatch.setattr(providers.litellm, 'acompletion', fake_completion)
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'test-chat','messages':[{'role':'user','content':'x'}],'stream':True,'stream_options':{'include_usage':True}})
    assert response.status_code == 200
    assert '[DONE]' not in response.text and 'Provider stream failed' in response.text
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ') and line != 'data: [DONE]']
    assert all(event.get('usage') is None for event in events)
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['estimated_cost'] is None
    assert Decimal(client.get('/admin/budgets', headers=admin()).json()[0]['held_amount']) == Decimal('0.1')


@pytest.mark.parametrize(('raw_usage', 'expected_cost'), [
    (None, None),
    ({'prompt_tokens':7}, None),
    ({'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}, '0.07'),
    ({'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}, '0'),
    ({'prompt_tokens':7,'completion_tokens':3,'total_tokens':10}, '0.1'),
])
@pytest.mark.parametrize('include_usage', [True, False])
def test_groq_native_stream_usage_without_network(context, monkeypatch, raw_usage, expected_cost, include_usage):
    import json
    import socket
    import httpx
    from decimal import Decimal
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':'groq','provider_type':'groq','api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'groq-chat','provider_id':conn['id'],'upstream_model':'llama-3.3-70b-versatile','operations':['generation']}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model['id']]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    chunk = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{'content':'hello'},'finish_reason':None}]}
    finish = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
    if raw_usage is not None: finish['x_groq'] = {'usage':raw_usage}
    wire = ''.join('data: '+json.dumps(value)+'\n\n' for value in (chunk,finish)) + 'data: [DONE]\n\n'
    observed = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            observed.append(url)
            return httpx.Response(200, content=wire.encode(), headers={'content-type':'text/event-stream'}, request=httpx.Request('POST',url))
    monkeypatch.setattr(providers.litellm, 'module_level_aclient', FakeHTTP())
    import importlib
    monkeypatch.setattr(importlib.import_module('litellm.llms.custom_httpx.llm_http_handler'), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    payload = {'model':'groq-chat','messages':[{'role':'user','content':'x'}],'stream':True}
    if include_usage: payload['stream_options'] = {'include_usage':True}
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 200 and '[DONE]' in response.text and 'hello' in response.text, response.text
    assert len(observed) == 1 and 'api.groq.com' in observed[0]
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ') and line != 'data: [DONE]']
    usage_events = [event['usage'] for event in events if event.get('usage') is not None]
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    if raw_usage is None:
        assert not usage_events
    elif include_usage:
        assert usage_events and usage_events[-1]['prompt_tokens'] == raw_usage['prompt_tokens']
    if expected_cost is None:
        assert record['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert Decimal(record['estimated_cost']) == Decimal(expected_cost) and Decimal(budget['held_amount']) == 0
        assert record['input_tokens'] == raw_usage['prompt_tokens'] and record['output_tokens'] == raw_usage['completion_tokens']


@pytest.mark.parametrize(('provider_type','upstream_model','host'), [
    ('openrouter','openai/gpt-4o-mini','openrouter.ai'),
    ('deepseek','deepseek-chat','api.deepseek.com'),
    ('xai','grok-4','api.x.ai'),
    ('mistral','mistral-large-latest','api.mistral.ai'),
    ('together_ai','meta-llama/Llama-3.3-70B-Instruct-Turbo','api.together.ai'),
    ('fireworks_ai','accounts/fireworks/models/llama-v3p1-8b-instruct','api.fireworks.ai'),
])
@pytest.mark.parametrize(('raw_usage','expected_cost'), [
    (None, None),
    ({'prompt_tokens':7}, None),
    ({'prompt_tokens':7,'completion_tokens':0,'total_tokens':7}, '0.07'),
    ({'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}, '0'),
    ({'prompt_tokens':7,'completion_tokens':3,'total_tokens':10}, '0.1'),
])
@pytest.mark.parametrize('usage_separate', [True, False])
@pytest.mark.parametrize('progressive', [True, False])
def test_openai_like_native_stream_usage_without_network(context, monkeypatch, provider_type, upstream_model, host, raw_usage, expected_cost, usage_separate, progressive):
    import importlib
    import json
    import socket
    import httpx
    from decimal import Decimal
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':provider_type,'provider_type':provider_type,'api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'test-chat','provider_id':conn['id'],'upstream_model':upstream_model,'operations':['generation']}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model['id']]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    chunk = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{'content':'hello'},'finish_reason':None}]}
    finish = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{},'finish_reason':'stop'}]}
    chunks = [chunk, finish]
    if raw_usage is not None:
        if progressive:
            chunk['usage'] = {'prompt_tokens':1}
        if usage_separate:
            chunks.append({'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[],'usage':raw_usage})
        else:
            finish['usage'] = raw_usage
    wire = ''.join('data: '+json.dumps(value)+'\n\n' for value in chunks) + 'data: [DONE]\n\n'
    observed = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            observed.append(url)
            return httpx.Response(200, content=wire.encode(), headers={'content-type':'text/event-stream'}, request=httpx.Request('POST',url))
    monkeypatch.setattr(providers.litellm, 'module_level_aclient', FakeHTTP())
    monkeypatch.setattr(importlib.import_module('litellm.llms.custom_httpx.llm_http_handler'), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'test-chat','messages':[{'role':'user','content':'x'}],'stream':True,'stream_options':{'include_usage':True}})
    assert response.status_code == 200 and '[DONE]' in response.text and 'hello' in response.text, response.text
    assert len(observed) == 1 and host in observed[0]
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ') and line != 'data: [DONE]']
    usage_events = [event['usage'] for event in events if event.get('usage') is not None]
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    if raw_usage is None:
        assert not usage_events
    else:
        assert usage_events and usage_events[-1]['prompt_tokens'] == raw_usage['prompt_tokens']
    if expected_cost is None:
        assert record['estimated_cost'] is None and Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert Decimal(record['estimated_cost']) == Decimal(expected_cost) and Decimal(budget['held_amount']) == 0
        assert record['input_tokens'] == raw_usage['prompt_tokens'] and record['output_tokens'] == raw_usage['completion_tokens']


@pytest.mark.parametrize(('provider_type','upstream_model'), [('openrouter','openai/gpt-4o-mini'),('deepseek','deepseek-chat'),('groq','llama-3.3-70b-versatile'),('xai','grok-4'),('mistral','mistral-large-latest'),('together_ai','meta-llama/Llama-3.3-70B-Instruct-Turbo'),('fireworks_ai','accounts/fireworks/models/llama-v3p1-8b-instruct')])
@pytest.mark.parametrize('ending', ['truncated', 'finish_without_done', 'error_before_finish', 'error_after_finish', 'hybrid_error_with_done', 'error_after_finish_with_done'])
def test_native_openai_like_stream_failures_without_network(context, monkeypatch, provider_type, upstream_model, ending):
    import importlib
    import json
    import socket
    import httpx
    from decimal import Decimal
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':provider_type,'provider_type':provider_type,'api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'test-chat','provider_id':conn['id'],'upstream_model':upstream_model,'operations':['generation']}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model['id']]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    chunk = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{'content':'hello'},'finish_reason':None}]}
    finish = {'id':'mock','object':'chat.completion.chunk','created':1,'model':'mock','choices':[{'index':0,'delta':{},'finish_reason':'stop'}], 'usage':{'prompt_tokens':7,'completion_tokens':3,'total_tokens':10}}
    error = {'error':{'message':'mock provider error','code':'upstream_error'}, 'choices':[]}
    chunks = [chunk] + ([finish] if ending in ('error_after_finish', 'error_after_finish_with_done', 'finish_without_done') else []) + ([error] if ending.startswith('error_') else [])
    wire = ''.join('data: '+json.dumps(value)+'\n\n' for value in chunks)
    if ending == 'hybrid_error_with_done':
        wire += 'data: '+json.dumps({**finish, 'error':{'message':'private upstream error'}})+'\n\ndata: [DONE]\n\n'
    if ending == 'error_after_finish_with_done':
        wire += 'data: [DONE]\n\n'
    class FakeHTTP:
        async def post(self, url, **kwargs):
            return httpx.Response(200, content=wire.encode(), headers={'content-type':'text/event-stream'}, request=httpx.Request('POST',url))
    monkeypatch.setattr(providers.litellm, 'module_level_aclient', FakeHTTP())
    monkeypatch.setattr(importlib.import_module('litellm.llms.custom_httpx.llm_http_handler'), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key['key']}, json={'model':'test-chat','messages':[{'role':'user','content':'x'}],'stream':True,'stream_options':{'include_usage':True}})
    assert response.status_code == 200 and 'hello' in response.text, response.text
    assert '[DONE]' not in response.text and 'Provider stream failed' in response.text, response.text
    assert 'private upstream error' not in response.text
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['status'] == 'error' and record['estimated_cost'] is None
    assert Decimal(client.get('/admin/budgets', headers=admin()).json()[0]['held_amount']) == Decimal('0.1')


def test_client_key_issuance_idempotency(context):
    from sqlalchemy import select
    from app.models import AuditLog
    client, db = context
    _, model_id, _ = configure(client, ['generation'])
    payload = {'name':'idempotent-key','model_ids':[model_id]}
    request_id = 'idempotency_test_0123456789'
    headers = {**admin(), 'Idempotency-Key':request_id}
    first = client.post('/admin/api-keys', headers=headers, json=payload)
    assert first.status_code == 201
    key_id = first.json()['id']
    replay = client.post('/admin/api-keys', headers=headers, json=payload)
    assert replay.status_code == 409 and 'already processed' in replay.json()['detail']
    assert first.json()['key'] not in replay.text
    different = client.post('/admin/api-keys', headers=headers, json={'name':'different','model_ids':[model_id]})
    assert different.status_code == 409
    assert client.post('/admin/api-keys', headers={**admin(), 'Idempotency-Key':'short'}, json=payload).status_code == 422
    assert client.post('/admin/api-keys', headers={**admin(), 'Idempotency-Key':'another_request_0123456789'}, json=payload).status_code == 201
    with Session(db) as session:
        key = session.get(ClientKey, key_id)
        assert key.creation_request_hash == hashlib.sha256(request_id.encode()).hexdigest()
        assert key.creation_request_hash != request_id
        audits = session.scalars(select(AuditLog).where(AuditLog.action == 'api_key.create', AuditLog.target_id == str(key_id))).all()
        assert len(audits) == 1 and request_id not in str(audits[0].__dict__)


def test_embedding_callback_absent_never_trusts_synthetic_usage(context, monkeypatch):
    client, _ = context
    _, model_id, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    async def fake_sdk(**kwargs):
        return {'object':'list','data':[{'index':0,'embedding':[0.1,0.2]}],'usage':{'prompt_tokens':99,'total_tokens':99}}
    monkeypatch.setattr(providers.litellm, 'aembedding', fake_sdk)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'test'})
    assert response.status_code == 200 and 'usage' not in response.json()
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['input_tokens'] is None and record['estimated_cost'] is None
    assert len(client.get('/admin/budget-reservations', headers=admin()).json()) == 1


def test_embedding_usage_capture_is_request_scoped(monkeypatch):
    import asyncio
    import json
    import socket
    import httpx2
    from openai import AsyncOpenAI
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    def handler(request):
        value = json.loads(request.content)['input']
        usage = {'prompt_tokens':int(value), 'total_tokens':int(value)} if value != 'missing' else None
        body = {'object':'list','model':'mock','data':[{'object':'embedding','index':0,'embedding':[0.1,0.2]}]}
        if usage is not None: body['usage'] = usage
        return httpx2.Response(200, json=body)
    async def run():
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            sdk = AsyncOpenAI(api_key='fake',base_url='https://example.invalid/v1',http_client=http,max_retries=0)
            async def call(value):
                result = await providers.embedding({'model':'openai/mock','api_key':'fake','client':sdk}, {'input':value})
                data = providers.as_dict(result)
                providers.apply_embedding_usage(data, result)
                return data.get('usage')
            return await asyncio.gather(*(call(v) for v in ('0','7','missing','12')))
    values = asyncio.run(run())
    assert values == [{'prompt_tokens':0,'total_tokens':0},{'prompt_tokens':7,'total_tokens':7},None,{'prompt_tokens':12,'total_tokens':12}]


def test_openai_embedding_usage_provenance_with_base64_format(context, monkeypatch):
    import socket
    import httpx2
    from openai import AsyncOpenAI
    client, _ = context
    _, model_id, key = configure(client, ['embedding'])
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model_id,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    def handler(request):
        return httpx2.Response(200,json={'object':'list','model':'mock','data':[{'object':'embedding','index':0,'embedding':'zczMPc3MTD4='}], 'usage':{'prompt_tokens':0,'total_tokens':0}})
    original = providers.embedding
    async def fake_transport(config, data):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as http:
            config['client'] = AsyncOpenAI(api_key='fake',base_url='https://example.invalid/v1',http_client=http,max_retries=0)
            return await original(config, data)
    monkeypatch.setattr(providers, 'embedding', fake_transport)
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'exaone-chat','input':'test','encoding_format':'base64'})
    assert response.status_code == 200 and response.json()['usage']['prompt_tokens'] == 0
    assert response.json()['data'][0]['embedding'] == 'zczMPc3MTD4='
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert record['input_tokens'] == 0 and float(record['estimated_cost']) == 0
    assert not client.get('/admin/budget-reservations', headers=admin()).json()


@pytest.mark.parametrize('batch', [False, True])
@pytest.mark.parametrize('encoding_format', [None, 'base64'])
@pytest.mark.parametrize(('metadata','expected'), [
    (None, None),
    ({}, None),
    ({'promptTokenCount':0}, 0),
    ({'promptTokenCount':7}, 7),
    ({'promptTokenCount':True}, None),
    ({'promptTokenCount':'7'}, None),
    ({'promptTokenCount':7,'cachedContentTokenCount':2}, None),
])
def test_gemini_embedding_native_usage_without_network(context, monkeypatch, batch, metadata, expected, encoding_format):
    import importlib
    import socket
    import httpx
    from decimal import Decimal
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':'Gemini','provider_type':'gemini','api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'gemini-embed','provider_id':conn['id'],'upstream_model':'gemini-embedding-001','operations':['embedding']}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model['id']]}).json()
    assert client.post('/admin/prices', headers=admin(), json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
    assert client.put(f"/admin/api-keys/{key['id']}/budget", headers=admin(), json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    observed = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            observed.append((url, kwargs))
            body = {'embeddings':[{'values':[0.1,0.2]} for _ in range(2 if batch else 1)]}
            if metadata is not None: body['usageMetadata'] = metadata
            return httpx.Response(200,json=body,request=httpx.Request('POST',url))
    module = importlib.import_module('litellm.llms.vertex_ai.gemini_embeddings.batch_embed_content_handler')
    monkeypatch.setattr(module, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    payload = {'model':'gemini-embed','input':['hello','world'] if batch else 'hello','dimensions':2}
    if encoding_format: payload['encoding_format'] = encoding_format
    response = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json=payload)
    assert response.status_code == 200, response.text
    assert len(response.json()['data']) == (2 if batch else 1)
    assert isinstance(response.json()['data'][0]['embedding'], str if encoding_format else list)
    assert len(observed) == 1 and ':batchEmbedContents' in observed[0][0]
    import json
    requests = json.loads(observed[0][1]['data'])['requests']
    assert len(requests) == (2 if batch else 1) and all(item['outputDimensionality'] == 2 for item in requests)
    record = client.get('/admin/usage/requests', headers=admin()).json()[0]
    budget = client.get('/admin/budgets', headers=admin()).json()[0]
    if expected is None:
        assert 'usage' not in response.json() and record['input_tokens'] is None and record['estimated_cost'] is None
        assert Decimal(budget['held_amount']) == Decimal('0.1')
    else:
        assert response.json()['usage'] == {'prompt_tokens':expected} and record['input_tokens'] == expected
        assert Decimal(record['estimated_cost']) == Decimal(expected) * Decimal('0.01') and Decimal(budget['held_amount']) == 0


@pytest.mark.parametrize(('upstream','expected'), [(400,400),(429,429),(503,503),(500,502),(200,502),('timeout',504)])
@pytest.mark.parametrize('raise_status', [True, False])
def test_gemini_embedding_provider_error_is_sanitized(context, monkeypatch, upstream, expected, raise_status):
    import importlib
    import socket
    import httpx
    client, _ = context
    conn = client.post('/admin/providers', headers=admin(), json={'name':'gemini','provider_type':'gemini','api_key':'mock-secret'}).json()
    model = client.post('/admin/models', headers=admin(), json={'alias':'gemini-embed','provider_id':conn['id'],'upstream_model':'gemini-embedding-001','operations':['embedding']}).json()
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'test','model_ids':[model['id']]}).json()
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    class FakeHTTP:
        async def post(self, url, **kwargs):
            if upstream == 'timeout': raise httpx.ReadTimeout('mock-secret private')
            response = httpx.Response(upstream,json={'error':{'message':'mock-secret private'}},request=httpx.Request('POST',url))
            if raise_status and upstream != 200: response.raise_for_status()
            return response
    module = importlib.import_module('litellm.llms.vertex_ai.gemini_embeddings.batch_embed_content_handler')
    monkeypatch.setattr(module, 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    result = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'gemini-embed','input':'hello'})
    assert result.status_code == expected and 'mock-secret' not in result.text and 'private' not in result.text
    assert client.get('/admin/usage/requests', headers=admin()).json()[0]['status'] == 'error'


def test_gemini_embedding_usage_is_request_scoped(monkeypatch):
    import asyncio
    import json
    import socket
    import httpx
    def no_network(*args, **kwargs): raise AssertionError('Unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    class FakeHTTP:
        async def post(self, url, **kwargs):
            value = json.loads(kwargs['data'])['requests'][0]['content']['parts'][0]['text']
            await asyncio.sleep(0)
            body = {'embeddings':[{'values':[0.1,0.2]}]}
            if value != 'missing': body['usageMetadata'] = {'promptTokenCount':int(value)}
            return httpx.Response(200,json=body,request=httpx.Request('POST',url))
    async def run():
        async def one(value):
            result = await providers.embedding({'model':'gemini/gemini-embedding-001','api_key':'fake','client':FakeHTTP(),'timeout':60}, {'input':value})
            data = providers.as_dict(result)
            providers.apply_embedding_usage(data,result)
            return data.get('usage')
        return await asyncio.gather(*(one(v) for v in ('0','7','missing','12')))
    assert asyncio.run(run()) == [{'prompt_tokens':0}, {'prompt_tokens':7}, None, {'prompt_tokens':12}]


def test_documented_api_examples_with_mock_providers(context, monkeypatch):
    """The published requests remain executable without contacting a provider."""
    import json
    import re
    from pathlib import Path

    client, _ = context
    text = (Path(__file__).resolve().parents[2] / 'docs/api-examples.md').read_text()
    bodies = [json.loads(body) for body in re.findall(r"-d '([^']+)'", text)]
    assert [body['model'] for body in bodies] == ['chat-main', 'embed-main', 'judge-main']
    exaone = client.post('/admin/providers', headers=admin(), json={
        'name':'example-exaone', 'provider_type':'exaone', 'api_key':'synthetic'}).json()['id']
    jev = client.post('/admin/providers', headers=admin(), json={
        'name':'example-jev', 'provider_type':'typesafe', 'api_key':'synthetic'}).json()['id']
    model_ids = []
    for alias, provider, operation in [('chat-main', exaone, 'generation'),
                                       ('embed-main', exaone, 'embedding'),
                                       ('judge-main', jev, 'decision')]:
        response = client.post('/admin/models', headers=admin(), json={
            'alias':alias, 'provider_id':provider, 'upstream_model':'example', 'operations':[operation]})
        assert response.status_code == 201
        model_ids.append(response.json()['id'])
    issued = client.post('/admin/api-keys', headers=admin(), json={'name':'example', 'model_ids':model_ids})
    assert issued.status_code == 201
    auth = {'Authorization':'Bearer '+issued.json()['key']}

    async def completion(config, data):
        return {'choices':[{'index':0, 'message':{'role':'assistant','content':'mock'}, 'finish_reason':'stop'}],
                'usage':{'prompt_tokens':2, 'completion_tokens':1}}
    async def embedding(config, data):
        return {'data':mock_vectors(data['input']), 'usage':{'prompt_tokens':2}}
    async def decision(config, data):
        return {'answers':[{'type':'predicate','name':data['questions'][0]['name'],'probability':0.75}],
                'usage':{'input_tokens':2, 'output_tokens':1}}
    monkeypatch.setattr(providers, 'completion', completion)
    monkeypatch.setattr(providers, 'embedding', embedding)
    monkeypatch.setattr(providers, 'decision', decision)
    assert client.get('/v1/models', headers=auth).status_code == 200
    for endpoint, body in zip(('/v1/chat/completions', '/v1/embeddings', '/v1/decisions'), bodies):
        result = client.post(endpoint, headers=auth, json=body)
        assert result.status_code == 200, result.text
    usage = client.get('/admin/usage', headers=admin()).json()
    assert {row['operation'] for row in usage} == {'generation', 'embedding', 'decision'}
    assert all(row['requests'] == 1 and row['status'] == 'success' for row in usage)


@pytest.mark.parametrize(('kind','path','header','payload','expected'), [
    ('openai', 'https://api.openai.com/v1/models', 'authorization', {'data':[{'id':'gpt-test'}]}, 'gpt-test'),
    ('anthropic', 'https://api.anthropic.com/v1/models', 'x-api-key', {'data':[{'id':'claude-test'}], 'has_more':True}, 'claude-test'),
    ('gemini', 'https://generativelanguage.googleapis.com/v1beta/models', 'x-goog-api-key', {'models':[{'name':'models/gemini-test'}]}, 'gemini-test'),
    ('typesafe', 'https://api.typesafe.ai/v1/models', 'authorization', {'models':[{'name':'jev-latest'}]}, 'jev-latest'),
    ('exaone', 'https://api.exaone.ai/v1/models', 'authorization', {'data':[{'id':'k-exaone-test'}]}, 'k-exaone-test'),
    ('cerebras', 'https://api.cerebras.ai/v1/models', 'authorization', {'data':[{'id':'cerebras-test'}]}, 'cerebras-test'),
    ('novita', 'https://api.novita.ai/openai/v1/models', 'authorization', {'data':[{'id':'vendor/novita-test'}]}, 'vendor/novita-test'),
    ('synthetic', 'https://api.synthetic.new/openai/v1/models', 'authorization', {'data':[{'id':'hf:vendor/model'}]}, 'hf:vendor/model'),
    ('sambanova', 'https://api.sambanova.ai/v1/models', 'authorization', {'data':[{'id':'samba-test'}]}, 'samba-test'),
    ('nvidia_nim', 'https://integrate.api.nvidia.com/v1/models', 'authorization', {'data':[{'id':'nvidia/test'}]}, 'nvidia/test'),
    ('fireworks_ai', 'https://api.fireworks.ai/v1/accounts/fireworks/models', 'authorization', {'models':[{'name':'accounts/fireworks/models/test','displayName':'Test'}]}, 'accounts/fireworks/models/test'),
])
def test_provider_discovery_uses_bounded_mock_transport(context, monkeypatch, kind, path, header, payload, expected):
    import httpx
    client, _ = context
    response = client.post('/admin/providers', headers=admin(), json={'name':kind, 'provider_type':kind, 'api_key':'synthetic-secret'})
    assert response.status_code == 201
    provider_id = response.json()['id']
    seen = []
    def handler(request):
        seen.append(request)
        assert str(request.url) == path
        assert request.headers[header].endswith('synthetic-secret')
        if kind == 'anthropic': assert request.headers['anthropic-version'] == '2023-06-01'
        if kind == 'novita': assert request.headers['content-type'] == 'application/json'
        return httpx.Response(200, json=payload)
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    result = client.post(f'/admin/providers/{provider_id}/discover', headers=admin())
    assert result.status_code == 200, result.text
    assert result.json()['models'][0]['id'] == expected
    assert result.json()['partial'] is (kind in ('anthropic', 'fireworks_ai'))
    assert len(seen) == 1 and 'synthetic-secret' not in result.text
    assert any(row['action'] == 'provider.discover' for row in client.get('/admin/audit', headers=admin()).json())
    assert client.post(f'/admin/providers/{provider_id}/discover').status_code == 401


def test_provider_discovery_handles_missing_key_and_sanitizes_failures(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'example', 'provider_type':'exaone'}).json()['id']
    assert client.post(f'/admin/providers/{provider}/discover', headers=admin()).json()['detail'] == 'provider_key_missing'
    assert client.put(f'/admin/providers/{provider}/key', headers=admin(), json={'api_key':'synthetic-secret'}).status_code == 200
    original = providers.httpx.AsyncClient
    for status, detail in [(401, 'provider_authentication'), (404, 'provider_unsupported'), (429, 'provider_rate_limited'), (500, 'provider_unavailable')]:
        def handler(request): return httpx.Response(status, text='synthetic-secret')
        monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
        response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
        assert response.status_code == 502 and response.json()['detail'] == detail
        assert 'synthetic-secret' not in response.text


@pytest.mark.parametrize(('kind','first','second','query'), [
    ('anthropic', {'data':[{'id':'a'}], 'has_more':True, 'last_id':'a'}, {'data':[{'id':'b'}], 'has_more':False}, ('after_id','a')),
    ('gemini', {'models':[{'name':'models/a'}], 'nextPageToken':'cursor'}, {'models':[{'name':'models/b'}]}, ('pageToken','cursor')),
    ('openai', {'data':[{'id':'a'}], 'has_more':True, 'last_id':'a'}, {'data':[{'id':'b'}], 'has_more':False}, ('after','a')),
])
def test_provider_discovery_pagination_is_bounded(context, monkeypatch, kind, first, second, query):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':kind,'provider_type':kind,'api_key':'synthetic'}).json()['id']
    seen = []
    def handler(request):
        seen.append(request)
        if len(seen) == 1: return httpx.Response(200, json=first)
        assert request.url.params[query[0]] == query[1]
        return httpx.Response(200, json=second)
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 200
    assert [item['id'] for item in response.json()['models']] == ['a','b']
    assert response.json()['partial'] is False and len(seen) == 2


def test_fireworks_public_catalog_pagination_without_network(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'fireworks','provider_type':'fireworks_ai','api_key':'synthetic'}).json()['id']
    seen = []
    def handler(request):
        seen.append(request)
        assert request.url.host == 'api.fireworks.ai'
        if len(seen) == 1:
            return httpx.Response(200, json={'models':[{'name':'accounts/fireworks/models/a', 'displayName':'A'}], 'nextPageToken':'next'})
        assert request.url.params['pageToken'] == 'next'
        return httpx.Response(200, json={'models':[{'name':'accounts/fireworks/models/b'}]})
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 200
    assert response.json() == {'models':[{'id':'accounts/fireworks/models/a','name':'A'}, {'id':'accounts/fireworks/models/b','name':'accounts/fireworks/models/b'}], 'partial':True}
    assert len(seen) == 2


def test_provider_discovery_never_follows_redirect(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'redirect','provider_type':'exaone','api_key':'synthetic'}).json()['id']
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={'location':'https://untrusted.invalid/models'})
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 502 and len(requests) == 1


def test_discovered_model_id_with_variant_can_be_registered(context):
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'router','provider_type':'openrouter'}).json()['id']
    response = client.post('/admin/models', headers=admin(), json={'alias':'router-test','provider_id':provider,
        'upstream_model':'vendor/model:variant','operations':['generation']})
    assert response.status_code == 201
    assert response.json()['upstream_model'] == 'vendor/model:variant'


def test_provider_groups_enforce_model_purpose_without_network(context):
    client, _ = context
    def connect(name, provider_type, group):
        return client.post('/admin/providers', headers=admin(), json={'name':name, 'provider_type':provider_type, 'model_group':group})
    assert connect('bad-jev', 'typesafe', 'general').status_code == 422
    assert connect('bad-decision', 'exaone', 'decision').status_code == 422
    assert connect('bad-coding', 'zai_coding', 'embedding').status_code == 422
    general = connect('general', 'openai', 'general').json()['id']
    embedding = connect('embedding', 'openai', 'embedding').json()['id']
    decision = connect('decision', 'typesafe', 'decision').json()['id']
    def register(provider, alias, operations):
        return client.post('/admin/models', headers=admin(), json={'provider_id':provider, 'alias':alias, 'upstream_model':alias, 'operations':operations})
    assert register(general, 'general-gen', ['generation']).status_code == 201
    assert register(general, 'general-embed', ['embedding']).status_code == 201
    assert register(general, 'general-mixed', ['generation', 'embedding']).status_code == 422
    embedded = register(embedding, 'embed', ['embedding'])
    assert embedded.status_code == 201
    assert register(embedding, 'embed-gen', ['generation']).status_code == 422
    jev = register(decision, 'jev', ['decision'])
    assert jev.status_code == 201
    assert register(decision, 'jev-gen', ['generation']).status_code == 422
    groups = {item['name']:item['model_group'] for item in client.get('/admin/providers', headers=admin()).json()}
    assert groups == {'general':'general', 'embedding':'embedding', 'decision':'decision'}
    key = client.post('/admin/api-keys', headers=admin(), json={'name':'purpose-check', 'model_ids':[embedded.json()['id'], jev.json()['id']]}).json()['key']
    auth = {'Authorization':'Bearer '+key}
    for alias in ('embed', 'jev'):
        response = client.post('/v1/chat/completions', headers=auth, json={'model':alias, 'messages':[{'role':'user', 'content':'test'}]})
        assert response.status_code == 403


def test_provider_group_change_preserves_models_and_rejects_conflicts(context):
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'purpose','provider_type':'openai','model_group':'general'}).json()['id']
    def model(alias, operation):
        return client.post('/admin/models', headers=admin(), json={'alias':alias, 'provider_id':provider, 'upstream_model':alias, 'operations':[operation]}).json()['id']
    embedding = model('embed-group-test', 'embedding')
    generation = model('chat-group-test', 'generation')
    endpoint = f'/admin/providers/{provider}/model-group'
    assert client.put(endpoint, json={'model_group':'embedding'}).status_code == 401
    assert client.put(endpoint, headers=admin(), json={'model_group':'embedding'}).status_code == 409
    assert client.put(f'/admin/models/{generation}/active', headers=admin(), json={'active':False}).status_code == 200
    assert client.put(endpoint, headers=admin(), json={'model_group':'embedding'}).status_code == 409
    assert client.get('/admin/providers', headers=admin()).json()[0]['model_group'] == 'general'
    second = client.post('/admin/providers', headers=admin(), json={'name':'general-two','provider_type':'openai','model_group':'general'}).json()['id']
    assert client.put(f'/admin/models/{generation}', headers=admin(), json={'alias':'chat-group-test','provider_id':second,'upstream_model':'chat-group-test','operations':['generation']}).status_code == 200
    assert client.put(endpoint, headers=admin(), json={'model_group':'embedding'}).status_code == 200
    assert client.get('/admin/providers', headers=admin()).json()[0]['model_group'] == 'embedding'
    assert client.post('/admin/models', headers=admin(), json={'alias':'rejected-chat','provider_id':provider,'upstream_model':'chat','operations':['generation']}).status_code == 422
    assert client.get('/admin/models', headers=admin()).json()[0]['id'] in (generation, embedding)
    assert any(row['action'] == 'provider.group.change' for row in client.get('/admin/audit', headers=admin()).json())
    assert client.put(endpoint, headers=admin(), json={'model_group':'general'}).status_code == 200
    jev = client.post('/admin/providers', headers=admin(), json={'name':'jev-group','provider_type':'typesafe'}).json()['id']
    assert client.put(f'/admin/providers/{jev}/model-group', headers=admin(), json={'model_group':'general'}).status_code == 422


def test_gemini_discovery_surfaces_only_explicit_supported_methods(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'gemini-methods','provider_type':'gemini','api_key':'fake'}).json()['id']
    items = [
        {'name':'models/chat', 'supportedGenerationMethods':['countTokens','generateContent']},
        {'name':'models/embed', 'supportedGenerationMethods':['embedContent']},
        {'name':'models/both', 'supportedGenerationMethods':['generateContent','embedContent']},
        {'name':'models/unknown', 'supportedGenerationMethods':['futureMethod']},
        {'name':'models/invalid', 'supportedGenerationMethods':['generateContent', None]},
        {'name':'models/absent'},
    ]
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={'models':items})), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 200
    results = {item['id']:item for item in response.json()['models']}
    assert results['chat']['advertised_operations'] == ['generation']
    assert results['embed']['advertised_operations'] == ['embedding']
    assert results['both']['advertised_operations'] == ['generation', 'embedding']
    assert all('advertised_operations' not in results[name] for name in ('unknown','invalid','absent'))


@pytest.mark.parametrize('operation', ['generation', 'embedding', 'decision'])
def test_admin_model_test_is_audited_and_uses_mock_provider(context, monkeypatch, operation):
    client, _ = context
    kind = 'typesafe' if operation == 'decision' else 'exaone'
    provider = client.post('/admin/providers', headers=admin(), json={'name':operation,'provider_type':kind,'api_key':'synthetic-secret'}).json()['id']
    model = client.post('/admin/models', headers=admin(), json={'alias':'test-model','provider_id':provider,'upstream_model':'mock-model','operations':[operation]}).json()['id']
    calls = []
    async def fake(config, data):
        calls.append((config, data))
        if operation == 'generation':
            return {'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}], 'usage':{'prompt_tokens':2,'completion_tokens':1}}
        if operation == 'embedding':
            return {'data':[{'index':0,'embedding':[0.1,0.2]}], 'usage':{'prompt_tokens':2}}
        return {'answers':[{'type':'predicate','name':'test','probability':0.9}], 'usage':{'input_tokens':2,'output_tokens':1}}
    monkeypatch.setattr(providers, {'generation':'completion','embedding':'embedding','decision':'decision'}[operation], fake)
    url = f'/admin/models/{model}/test'
    assert client.post(url, json={'operation':operation}).status_code == 401
    assert client.post(url, headers=admin(), json={'operation':operation,'extra':'bad'}).status_code == 422
    response = client.post(url, headers=admin(), json={'operation':operation})
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'success' and len(calls) == 1
    assert 'synthetic-secret' not in response.text and 'OK' not in response.text
    usage = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(usage) == 1 and usage[0]['request_id'] == response.json()['request_id']
    assert usage[0]['client_key_id'] is None and usage[0]['status'] == 'success'
    assert usage[0]['input_tokens'] == 2
    aggregate = client.get('/admin/usage', headers=admin()).json()
    assert len(aggregate) == 1 and aggregate[0]['client_key_id'] is None and aggregate[0]['requests'] == 1
    assert client.get('/admin/metrics', headers=admin()).json()['unique_requests'] == 1
    assert any(row['action'] == 'model.test' for row in client.get('/admin/audit', headers=admin()).json())
    assert client.post(url, headers=admin(), json={'operation':'embedding' if operation != 'embedding' else 'generation'}).status_code == 422
    assert len(calls) == 1


def test_admin_model_test_sanitizes_provider_failure(context, monkeypatch):
    client, _ = context
    provider, model, _ = configure(client, ['generation'])
    async def failure(config, data): raise RuntimeError('sensitive-upstream-secret')
    monkeypatch.setattr(providers, 'completion', failure)
    response = client.post(f'/admin/models/{model}/test', headers=admin(), json={'operation':'generation'})
    assert response.status_code == 502 and 'sensitive-upstream-secret' not in response.text
    row = client.get('/admin/usage/requests', headers=admin()).json()[0]
    assert row['status'] == 'error' and row['client_key_id'] is None


def test_admin_model_test_requires_active_model_and_key(context, monkeypatch):
    client, engine = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'no-key','provider_type':'exaone'}).json()['id']
    model = client.post('/admin/models', headers=admin(), json={'alias':'no-key-model','provider_id':provider,'upstream_model':'mock','operations':['generation']}).json()['id']
    calls = []
    async def fake(*args): calls.append(True)
    monkeypatch.setattr(providers, 'completion', fake)
    url = f'/admin/models/{model}/test'
    assert client.post(url, headers=admin(), json={'operation':'generation'}).json()['detail'] == 'provider_key_missing'
    with Session(engine) as session:
        session.get(ProviderConnection, provider).encrypted_api_key = 'unreadable'
        session.commit()
    invalid = client.post(url, headers=admin(), json={'operation':'generation'})
    assert invalid.status_code == 503 and invalid.json()['detail'] == 'provider_config_unavailable'
    assert client.put(f'/admin/providers/{provider}/key', headers=admin(), json={'api_key':'fake'}).status_code == 200
    assert client.put(f'/admin/models/{model}/active', headers=admin(), json={'active':False}).status_code == 200
    assert client.post(url, headers=admin(), json={'operation':'generation'}).status_code == 404
    assert calls == [] and client.get('/admin/usage/requests', headers=admin()).json() == []


def test_admin_model_test_timeout_and_invalid_response(context, monkeypatch):
    client, _ = context
    _, model, _ = configure(client, ['generation'])
    async def timeout(*args): raise TimeoutError('secret')
    monkeypatch.setattr(providers, 'completion', timeout)
    response = client.post(f'/admin/models/{model}/test', headers=admin(), json={'operation':'generation'})
    assert response.status_code == 504 and 'secret' not in response.text and 'x-request-id' in response.headers
    async def invalid(*args): return {'error':'secret'}
    monkeypatch.setattr(providers, 'completion', invalid)
    response = client.post(f'/admin/models/{model}/test', headers=admin(), json={'operation':'generation'})
    assert response.status_code == 502 and 'secret' not in response.text
    assert [record['status'] for record in client.get('/admin/usage/requests', headers=admin()).json()] == ['error', 'error']


def test_admin_model_test_does_not_hold_transaction_during_provider_call(context, monkeypatch):
    import asyncio
    from app.main import ModelTestIn, test_registered_model
    client, engine = context
    _, model_id, _ = configure(client, ['generation'])
    async def run():
        with Session(engine) as session:
            async def fake(config, data):
                assert not session.in_transaction()
                return {'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}]}
            monkeypatch.setattr(providers, 'completion', fake)
            result = await test_registered_model(model_id, ModelTestIn(operation='generation'), session, 'admin')
            assert result['status'] == 'success'
    asyncio.run(run())


def test_admin_model_test_cancellation_during_recording_does_not_dispatch(context, monkeypatch):
    import asyncio
    import threading
    from app import observability
    from app.main import ModelTestIn, test_registered_model
    client, engine = context
    _, model_id, _ = configure(client, ['generation'])
    entered, release = threading.Event(), threading.Event()
    begin = observability.begin
    def delayed_begin(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return begin(*args, **kwargs)
    monkeypatch.setattr(observability, 'begin', delayed_begin)
    calls = []
    async def fake(*args): calls.append(True)
    monkeypatch.setattr(providers, 'completion', fake)
    async def run():
        with Session(engine) as session:
            task = asyncio.create_task(test_registered_model(model_id, ModelTestIn(operation='generation'), session, 'admin'))
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
    try:
        asyncio.run(run())
    finally:
        release.set()
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert not calls and len(records) == 1 and records[0]['status'] == 'interrupted'
    assert records[0]['client_key_id'] is None


def test_admin_model_test_cancellation_during_provider_call_is_recorded(context, monkeypatch):
    import asyncio
    from app.main import ModelTestIn, test_registered_model
    client, engine = context
    _, model_id, _ = configure(client, ['generation'])
    async def run():
        started = asyncio.Event()
        async def fake(*args):
            started.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(providers, 'completion', fake)
        with Session(engine) as session:
            task = asyncio.create_task(test_registered_model(model_id, ModelTestIn(operation='generation'), session, 'admin'))
            await asyncio.wait_for(started.wait(), 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(run())
    records = client.get('/admin/usage/requests', headers=admin()).json()
    assert len(records) == 1 and records[0]['status'] == 'interrupted'


def test_admin_model_test_does_not_call_provider_if_audit_fails(context, monkeypatch):
    import asyncio
    from app import observability
    from app.main import ModelTestIn, test_registered_model
    client, engine = context
    _, model_id, _ = configure(client, ['generation'])
    calls = []
    async def fake(*args): calls.append(True)
    def fail_audit(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr(providers, 'completion', fake)
    monkeypatch.setattr(observability, 'audit', fail_audit)
    async def run():
        with Session(engine) as session:
            with pytest.raises(RuntimeError, match='audit unavailable'):
                await test_registered_model(model_id, ModelTestIn(operation='generation'), session, 'admin')
    asyncio.run(run())
    assert not calls


def test_admin_model_test_success_not_overwritten_by_cancellation_during_finalization(context, monkeypatch):
    import asyncio
    import threading
    from app import observability
    from app.main import ModelTestIn, test_registered_model
    client, engine = context
    _, model_id, _ = configure(client, ['generation'])
    entered, release = threading.Event(), threading.Event()
    original_end = observability.end
    statuses = []
    def delayed_end(bind, request_id, started, status, usage=None):
        statuses.append(status)
        entered.set()
        assert release.wait(5)
        return original_end(bind, request_id, started, status, usage)
    monkeypatch.setattr(observability, 'end', delayed_end)
    async def fake(*args):
        return {'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}]}
    monkeypatch.setattr(providers, 'completion', fake)
    async def run():
        with Session(engine) as session:
            task = asyncio.create_task(test_registered_model(model_id, ModelTestIn(operation='generation'), session, 'admin'))
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
    try:
        asyncio.run(run())
    finally:
        release.set()
    assert statuses == ['success']
    assert client.get('/admin/usage/requests', headers=admin()).json()[0]['status'] == 'success'


@pytest.mark.parametrize('wrapped', [False, True])
def test_together_model_catalog_and_explicit_types_without_network(context, monkeypatch, wrapped):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'together','provider_type':'together_ai','api_key':'synthetic'}).json()['id']
    items = [
        {'id':'example/chat','display_name':'Chat','type':'chat'},
        {'id':'example/embed','display_name':'Embedding','type':'embedding'},
        {'id':'example/image','type':'image'},
        {'id':'example/unknown'},
    ]
    seen = []
    def handler(request):
        seen.append(request)
        assert str(request.url) == 'https://api.together.xyz/v1/models'
        assert request.headers['authorization'] == 'Bearer synthetic'
        return httpx.Response(200, json={'data':items} if wrapped else items)
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 200
    results = {item['id']:item for item in response.json()['models']}
    assert results['example/chat']['name'] == 'Chat'
    assert results['example/chat']['advertised_operations'] == ['generation']
    assert results['example/embed']['advertised_operations'] == ['embedding']
    assert 'advertised_operations' not in results['example/image']
    assert 'advertised_operations' not in results['example/unknown']
    assert len(seen) == 1


def test_chutes_public_catalog_never_sends_or_requires_a_key(context, monkeypatch):
    import httpx
    client, engine = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'chutes-public','provider_type':'chutes'}).json()['id']
    requests = []
    def handler(request):
        requests.append(request)
        assert str(request.url) == 'https://llm.chutes.ai/v1/models'
        assert 'authorization' not in request.headers
        return httpx.Response(200, json={'data':[{'id':'vendor/public-model'}]})
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    result = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert result.status_code == 200 and result.json()['models'][0]['id'] == 'vendor/public-model'
    # An unreadable saved key must not affect or be sent to a public catalog.
    with Session(engine) as session:
        session.get(ProviderConnection, provider).encrypted_api_key = 'not-a-ciphertext'
        session.commit()
    assert client.post(f'/admin/providers/{provider}/discover', headers=admin()).status_code == 200
    assert len(requests) == 2


def test_openrouter_catalog_includes_embeddings_and_follows_bounded_offsets(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'router','provider_type':'openrouter','api_key':'synthetic'}).json()['id']
    requests = []
    def handler(request):
        requests.append(request)
        assert request.url.params['output_modalities'] == 'text,embeddings'
        assert request.url.params['limit'] == '100'
        offset = int(request.url.params['offset'])
        assert offset in (0, 100)
        items = [{'id':f'vendor/chat-{i}','endpoints':['/api/v1/chat/completions']} for i in range(100)] if offset == 0 else [
            {'id':'vendor/embed','endpoints':['/api/v1/embeddings']},
            {'id':'vendor/other','endpoints':['/api/alpha/decisions']},
            {'id':'vendor/unknown','endpoints':['/api/v1/embeddings', None]}]
        return httpx.Response(200, json={'data':items,'total_count':103})
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    response = client.post(f'/admin/providers/{provider}/discover', headers=admin())
    assert response.status_code == 200
    result = response.json()
    assert len(requests) == 2 and len(result['models']) == 103 and result['partial'] is False
    models = {item['id']:item for item in result['models']}
    assert models['vendor/chat-0']['advertised_operations'] == ['generation']
    assert models['vendor/embed']['advertised_operations'] == ['embedding']
    assert 'advertised_operations' not in models['vendor/other']
    assert 'advertised_operations' not in models['vendor/unknown']


def test_openrouter_catalog_reports_incomplete_when_page_limit_is_reached(context, monkeypatch):
    import httpx
    client, _ = context
    provider = client.post('/admin/providers', headers=admin(), json={'name':'router','provider_type':'openrouter','api_key':'synthetic'}).json()['id']
    requests = []
    def handler(request):
        offset = int(request.url.params['offset'])
        requests.append(offset)
        return httpx.Response(200, json={'data':[{'id':f'example/{i}'} for i in range(offset, offset + 100)], 'total_count':1200})
    original = providers.httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    result = client.post(f'/admin/providers/{provider}/discover', headers=admin()).json()
    assert requests == list(range(0, 1000, 100))
    assert len(result['models']) == 1000 and result['partial'] is True


@pytest.mark.parametrize(('upstream_status','detail'), [
    (400,'provider_test_rejected'), (401,'provider_test_authentication'),
    (403,'provider_test_authentication'), (404,'provider_test_model_not_found'),
    (422,'provider_test_rejected'), (429,'provider_test_rate_limited'), (500,'provider_test_failed'),
])
def test_admin_model_test_classifies_upstream_errors_without_leaking_details(context, monkeypatch, upstream_status, detail):
    client, _ = context
    _, model_id, _ = configure(client, ['generation'])
    class FakeProviderError(Exception):
        status_code = upstream_status
    async def fake(*args):
        raise FakeProviderError('private provider error with secret')
    monkeypatch.setattr(providers, 'completion', fake)
    response = client.post(f'/admin/models/{model_id}/test', headers=admin(), json={'operation':'generation'})
    assert response.status_code == 502 and response.json()['detail'] == detail
    assert 'secret' not in response.text and 'X-Request-ID' in response.headers
    assert client.get('/admin/usage/requests', headers=admin()).json()[0]['status'] == 'error'
