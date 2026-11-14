"""Run inside the backend container against an isolated temporary PostgreSQL database.

No provider network calls are made. The DB role must be able to create databases.
"""
import os
import asyncio
import base64
import importlib
import threading
import secrets
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from decimal import Decimal
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from app.main import AdjustmentIn, CapabilityVerificationIn, ModelIn, RouteIn, SecretIn, adjust_budget, app, change_provider_key, create_model, create_route, db_session, rotate_provider_key, set_capability_verification, update_model
from app.models import AdminSession, AdminUser, BootstrapLock, BudgetReservation, ClientKey, KeyBudget, ModelCircuit, ModelRoute, RouteTarget, UsageRecord
from app.rate_limit import consume
from app.database import runtime_engine
from app.recover_admin import recover
from app.rotate_key import rotate
from app import budgets, circuits, observability, oidc, providers

# Permit psycopg's database-host DNS lookup and libpq's connections, while
# blocking Python HTTP clients if a provider mock is accidentally omitted.
_socket_connect = socket.socket.connect
_socket_connect_ex = socket.socket.connect_ex
_socket_getaddrinfo = socket.getaddrinfo
_database_host = make_url(os.environ['DATABASE_URL']).host
def _deny_python_network(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        raise AssertionError('Unexpected Python network access during PostgreSQL smoke test')
    return _socket_connect(sock, address)
def _deny_python_network_ex(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        raise AssertionError('Unexpected Python network access during PostgreSQL smoke test')
    return _socket_connect_ex(sock, address)
def _deny_dns(host, *args, **kwargs):
    if host == _database_host:
        return _socket_getaddrinfo(host, *args, **kwargs)
    raise AssertionError('Unexpected Python DNS lookup during PostgreSQL smoke test')
socket.socket.connect = _deny_python_network
socket.socket.connect_ex = _deny_python_network_ex
socket.getaddrinfo = _deny_dns

url = make_url(os.environ['DATABASE_URL'])
admin_engine = create_engine(url.set(database='postgres'), isolation_level='AUTOCOMMIT')
db_name = 'magpie_test_' + secrets.token_hex(6)
with admin_engine.connect() as connection:
    connection.execute(text(f'CREATE DATABASE "{db_name}"'))
test_url = url.set(database=db_name)
test_engine = create_engine(test_url, pool_size=20, max_overflow=0)
try:
    subprocess.run(['alembic', 'upgrade', '0025_reconciliation_force'], check=True,
                   env=dict(os.environ, DATABASE_URL=test_url.render_as_string(hide_password=False)))
    with test_engine.begin() as connection:
        legacy_id = connection.execute(text("INSERT INTO client_keys (name, key_hash, key_prefix, active) VALUES ('legacy-migration', :hash, 'legacy', true) RETURNING id"), {'hash':'a'*64}).scalar_one()
    subprocess.run(['alembic', 'upgrade', 'head'], check=True,
                   env=dict(os.environ, DATABASE_URL=test_url.render_as_string(hide_password=False)))
    with test_engine.begin() as connection:
        legacy = connection.execute(text('SELECT name, creation_request_hash FROM client_keys WHERE id = :id'), {'id':legacy_id}).one()
        assert legacy.name == 'legacy-migration' and legacy.creation_request_hash is None
        connection.execute(text('DELETE FROM client_keys WHERE id = :id'), {'id':legacy_id})
    def get_test_db():
        with Session(test_engine) as session:
            yield session
    app.dependency_overrides[db_session] = get_test_db
    async def fake_decisions(config, data):
        assert config['model'] == 'typesafe/jev-latest'
        return {'model': 'jev', 'answers': [{'type': 'predicate', 'name': 'ok', 'probability': 0.9}],
                'usage': {'input_tokens': 10, 'output_tokens': 0}}
    providers.decision = fake_decisions
    with TestClient(app) as client:
        bootstrap = {'Authorization': 'Bearer ' + os.environ['MAGPIE_ADMIN_TOKEN']}
        main_module = importlib.import_module('app.main')
        saved_engine = main_module.engine
        saved_encryption = os.environ['MAGPIE_ENCRYPTION_KEY']
        saved_admin_token = os.environ['MAGPIE_ADMIN_TOKEN']
        main_module.engine = lambda: test_engine
        try:
            os.environ['MAGPIE_ENCRYPTION_KEY'] = 'invalid-key'
            assert client.get('/health/ready').status_code == 503
            os.environ['MAGPIE_ENCRYPTION_KEY'] = saved_encryption
            os.environ['MAGPIE_ADMIN_TOKEN'] = 'short'
            assert client.get('/health/ready').status_code == 503
            os.environ['MAGPIE_ADMIN_TOKEN'] = saved_admin_token
            assert client.get('/health/ready').status_code == 200
        finally:
            os.environ['MAGPIE_ENCRYPTION_KEY'] = saved_encryption
            os.environ['MAGPIE_ADMIN_TOKEN'] = saved_admin_token
            main_module.engine = saved_engine
        user = {'username': 'test-admin', 'password': 'this is a test password'}
        assert client.post('/admin/users', headers=bootstrap, json=user).status_code == 201
        main_module.engine = lambda: test_engine
        try:
            os.environ['MAGPIE_ADMIN_TOKEN'] = 'short'
            assert client.get('/health/ready').status_code == 200
        finally:
            os.environ['MAGPIE_ADMIN_TOKEN'] = saved_admin_token
            main_module.engine = saved_engine
        assert client.get('/admin/providers', headers=bootstrap).status_code == 401
        response = client.post('/admin/sessions', json=user); assert response.status_code == 201
        auth = {'Authorization': 'Bearer ' + response.json()['token']}
        deferred = client.post('/admin/providers', headers=auth, json={'name':'deferred','provider_type':'exaone'})
        assert deferred.status_code == 201 and deferred.json()['configured'] is False
        deferred_id = deferred.json()['id']
        deferred_model = client.post('/admin/models', headers=auth, json={'alias':'deferred-embedding','provider_id':deferred_id,'upstream_model':'mock','operations':['embedding']}).json()['id']
        deferred_key = client.post('/admin/api-keys', headers=auth, json={'name':'deferred-key','model_ids':[deferred_model]}).json()['key']
        deferred_auth = {'Authorization':'Bearer '+deferred_key}
        assert client.get('/v1/models', headers=deferred_auth).json()['data'] == []
        assert client.post('/v1/embeddings', headers=deferred_auth, json={'model':'deferred-embedding','input':'test'}).status_code == 503
        assert client.put(f'/admin/providers/{deferred_id}/key', headers=auth, json={'api_key':'fake-later'}).status_code == 200
        assert client.get('/v1/models', headers=deferred_auth).json()['data'][0]['id'] == 'deferred-embedding'
        assert client.get('/admin/provider-credential-health', headers=auth).json()['unreadable_count'] == 0
        try:
            os.environ['MAGPIE_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
            health = client.get('/admin/provider-credential-health', headers=auth).json()
            assert health['unreadable_count'] == 1 and health['providers'][0]['status'] == 'unreadable'
            assert 'fake-later' not in str(health)
        finally:
            os.environ['MAGPIE_ENCRYPTION_KEY'] = saved_encryption
        race_user = client.post('/admin/users', headers=auth, json={'username':'session-race','password':'old secure password'}).json()['id']
        original_verify = main_module.password_verify
        def delayed_login(password, change):
            entered, release = threading.Event(), threading.Event()
            def delayed_verify(candidate, stored):
                entered.set()
                assert release.wait(10)
                return original_verify(candidate, stored)
            main_module.password_verify = delayed_verify
            request = Request({'type':'http','method':'POST','path':'/admin/sessions','headers':[], 'client':('127.0.0.2',12345), 'server':('localhost',80),'scheme':'http','query_string':b''})
            def attempt_login():
                with Session(test_engine) as session:
                    try:
                        main_module.login(main_module.AdminCredentials(username='session-race',password=password), request, session)
                        return 201
                    except HTTPException as error:
                        return error.status_code
            try:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(attempt_login)
                    assert entered.wait(10)
                    try:
                        change()
                    finally:
                        release.set()
                    assert pending.result(timeout=10) == 401
            finally:
                main_module.password_verify = original_verify
        delayed_login('old secure password', lambda: client.put(f'/admin/users/{race_user}/password', headers=auth, json={'password':'new secure password'}).raise_for_status())
        delayed_login('new secure password', lambda: client.put(f'/admin/users/{race_user}/active', headers=auth, json={'active':False}).raise_for_status())
        assert client.post('/admin/sessions', json={'username':'session-race','password':'new secure password'}).status_code == 401
        gemini = client.post('/admin/providers', headers=auth, json={'name':'gemini-mock','provider_type':'gemini','api_key':'fake'}).json()['id']
        gemini_model = client.post('/admin/models', headers=auth, json={'alias':'embed-gemini','provider_id':gemini,'upstream_model':'gemini-embedding-001','operations':['embedding']}).json()['id']
        gemini_key = client.post('/admin/api-keys', headers=auth, json={'name':'gemini','model_ids':[gemini_model]}).json()['key']
        gemini_calls = []
        async def fake_gemini(config, data):
            gemini_calls.append(data)
            return {'data':[]}
        providers.embedding = fake_gemini
        for value in ('files/private', 'gs://private/object', 'data:image/png;base64,YQ=='):
            assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+gemini_key}, json={'model':'embed-gemini','input':value}).status_code == 400
        assert not gemini_calls
        assert client.put('/admin/operational-policy', headers=auth, json={'size_warning_bytes':1,'stale_after_minutes':60,'stale_count_warning':1}).status_code == 200
        operational = client.get('/admin/operational-status', headers=auth).json()
        assert operational['database_size_bytes'] > 0 and operational['size_warning'] is True and operational['stale_warning'] is False
        assert client.put('/admin/providers/123456/key', headers=auth, json={'api_key':'do-not-log'}).status_code == 404
        failure_audit = client.get('/admin/audit', headers=auth).json()
        assert any(a['action'] == 'admin.request.failed' and a['target_id'] == 'PUT /admin/providers/{provider_id}/key 404' for a in failure_audit)
        assert 'do-not-log' not in str(failure_audit)
        rotating = client.post('/admin/providers', headers=auth, json={'name':'rotate-race','provider_type':'exaone','api_key':'old-fake'}).json()['id']
        race = client.post('/admin/models', headers=auth, json={'alias':'rotate-race','provider_id':rotating,'upstream_model':'mock','operations':['generation']}).json()
        def rotate_or_verify(action):
            with Session(test_engine) as session:
                try:
                    if action == 'rotate':
                        rotate_provider_key(rotating, SecretIn(api_key='new-fake'), session, 'admin:1')
                    else:
                        set_capability_verification(race['id'], 'generation', CapabilityVerificationIn(status='mock_verified', note='fixture', expected_version=race['verification_version']), session, 'admin:1')
                    return 200
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(rotate_or_verify, ['rotate','verify']))
        assert outcomes[0] == 200 and outcomes[1] in (200, 409), outcomes
        rotated_model = next(m for m in client.get('/admin/models', headers=auth).json() if m['id'] == race['id'])
        assert rotated_model['verification_version'] == race['verification_version'] + 1
        assert rotated_model['capabilities'][0]['verification_status'] == 'unverified'
        def remove_or_verify(action):
            with Session(test_engine) as session:
                try:
                    if action == 'remove':
                        change_provider_key(rotating, None, session, 'admin:1')
                    else:
                        set_capability_verification(race['id'], 'generation', CapabilityVerificationIn(status='mock_verified', note='fixture', expected_version=rotated_model['verification_version']), session, 'admin:1')
                    return 200
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(remove_or_verify, ['remove','verify']))
        assert outcomes[0] == 200 and outcomes[1] in (200, 409), outcomes
        removed_model = next(m for m in client.get('/admin/models', headers=auth).json() if m['id'] == race['id'])
        assert removed_model['verification_version'] == rotated_model['verification_version'] + 1
        assert removed_model['capabilities'][0]['verification_status'] == 'unverified'
        exa_provider = client.post('/admin/providers', headers=auth, json={'name':'EXAONE-mock','provider_type':'exaone','api_key':'fake'}).json()['id']
        exa_model = client.post('/admin/models', headers=auth, json={'alias':'chat-mock','provider_id':exa_provider,'upstream_model':'mock','operations':['generation']}).json()['id']
        exa_key = client.post('/admin/api-keys', headers=auth, json={'name':'chat','model_ids':[exa_model]}).json()['key']
        chat_calls = []
        async def fake_chat(config, data):
            chat_calls.append(config['model'])
            return {'choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}]}
        providers.completion = fake_chat
        rejected = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+exa_key}, json={'model':'chat-mock','messages':[{'role':'user','content':[{'type':'file','file':{'file_id':'https://127.0.0.1/internal'}}]}]})
        assert rejected.status_code == 400 and not chat_calls
        assert client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+exa_key}, json={'model':'chat-mock','messages':[{'role':'user','content':'ordinary text'}]}).status_code == 200
        assert client.post('/admin/prices', headers=auth, json={'model_id':exa_model,'currency':'USD','basis':'tokens','input_per_million':'1','output_per_million':'1'}).status_code == 201
        stream_key = client.post('/admin/api-keys', headers=auth, json={'name':'truncated-stream','model_ids':[exa_model]}).json()
        assert client.put(f"/admin/api-keys/{stream_key['id']}/budget", headers=auth, json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
        async def incomplete_stream(config, data):
            async def chunks():
                yield {'choices':[{'index':0,'delta':{'content':'partial'},'finish_reason':None}]}
            return chunks()
        providers.completion = incomplete_stream
        truncated = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+stream_key['key']}, json={'model':'chat-mock','messages':[{'role':'user','content':'test'}],'stream':True})
        assert truncated.status_code == 200 and 'Provider stream failed' in truncated.text and '[DONE]' not in truncated.text
        record = client.get('/admin/usage/requests', headers=auth, params={'root_request_id':truncated.headers['x-request-id']}).json()[0]
        assert record['status'] == 'error' and record['estimated_cost'] is None
        reservation = next(r for r in client.get('/admin/budget-reservations', headers=auth).json() if r['request_id'] == record['request_id'])
        assert Decimal(reservation['reserved_amount']) == Decimal('0.1') and reservation['pending_reason'] == 'request_failed'
        providers.completion = fake_chat
        assert client.put('/admin/models/'+str(exa_model), headers=auth, json={'alias':'chat-mock','provider_id':exa_provider,'upstream_model':'mock','operations':['generation'],'supports_tools':False}).status_code == 200
        chat_backup = client.post('/admin/models', headers=auth, json={'alias':'chat-backup','provider_id':exa_provider,'upstream_model':'backup','operations':['generation'],'supports_tools':True}).json()['id']
        assert client.post('/admin/routes', headers=auth, json={'alias':'feature-route','operation':'generation','targets':[{'model_id':exa_model,'priority':0},{'model_id':chat_backup,'priority':1}]}).status_code == 201
        route_token = client.post('/admin/api-keys', headers=auth, json={'name':'feature','model_ids':[exa_model,chat_backup]}).json()['key']
        result = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+route_token}, json={'model':'feature-route','messages':[{'role':'user','content':'hi'}],'tools':[{'type':'function','function':{'name':'lookup'}}]})
        assert result.status_code == 200 and chat_calls[-1] == 'openai/backup'
        response = client.post('/admin/providers', headers=auth, json={'name':'Jev', 'provider_type':'typesafe', 'api_key':'fake'}); assert response.status_code == 201
        provider_id = response.json()['id']
        race_model = client.post('/admin/models', headers=auth, json={'alias':'verify-race', 'provider_id':provider_id, 'upstream_model':'jev-latest', 'operations':['decision']}).json()
        def verify_or_edit(action):
            with Session(test_engine) as session:
                try:
                    if action == 'verify':
                        set_capability_verification(race_model['id'], 'decision', CapabilityVerificationIn(status='mock_verified', note='fixture', expected_version=race_model['verification_version']), session, 'admin:1')
                    else:
                        update_model(race_model['id'], ModelIn(alias='verify-race', provider_id=provider_id, upstream_model='jev-preview', operations=['decision']), session, 'admin:1')
                    return 200
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(verify_or_edit, ['verify', 'edit']))
        assert outcomes[1] == 200 and outcomes[0] in (200, 409), outcomes
        race_model = next(m for m in client.get('/admin/models', headers=auth).json() if m['alias'] == 'verify-race')
        assert race_model['capabilities'][0]['verification_status'] == 'unverified'
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda _: circuits.record(test_engine, race_model['id'], 'decision', race_model['verification_version'], True), range(10)))
        with Session(test_engine) as session:
            state = session.get(ModelCircuit, (race_model['id'], 'decision', race_model['verification_version']))
            assert state is not None and state.failure_count == 3 and state.open_until is not None
        response = client.post('/admin/models', headers=auth, json={'alias':'judge', 'provider_id':provider_id, 'upstream_model':'jev-latest', 'operations':['decision']}); assert response.status_code == 201
        model_id = response.json()['id']
        response = client.post('/admin/prices', headers=auth, json={'model_id':model_id, 'currency':'USD', 'basis':'question', 'per_question':'0.01'}); assert response.status_code == 201
        backup = client.post('/admin/models', headers=auth, json={'alias':'judge-backup','provider_id':provider_id,'upstream_model':'jev-backup','operations':['decision']}).json()['id']
        route_response = client.post('/admin/routes', headers=auth, json={'alias':'retry-judge','operation':'decision','retry_on_failure':True,'targets':[{'model_id':model_id,'priority':0},{'model_id':backup,'priority':1}]})
        assert route_response.status_code == 201
        retry_route_id = route_response.json()['id']
        retry_key = client.post('/admin/api-keys', headers=auth, json={'name':'retry-key','model_ids':[model_id,backup]}).json()['key']
        async def retry_decisions(config, data):
            if config['model'] == 'typesafe/jev-latest': raise TimeoutError()
            return {'model':'jev-backup','answers':[{'type':'predicate','name':'ok','probability':0.9}]}
        providers.decision = retry_decisions
        retried = client.post('/v1/decisions', headers={'Authorization':'Bearer '+retry_key}, json={'model':'retry-judge','input':'x','questions':[{'type':'predicate','name':'ok','instructions':'test?'}]})
        assert retried.status_code == 200 and retried.headers['x-request-id'] != retried.headers['x-attempt-id']
        attempts = [r for r in client.get('/admin/usage/requests', headers=auth).json() if r['root_request_id'] == retried.headers['x-request-id']]
        assert sorted((r['attempt_number'], r['status']) for r in attempts) == [(1, 'error'), (2, 'success')]
        selected = client.get('/admin/usage/requests', headers=auth, params={'root_request_id':retried.headers['x-request-id']}).json()
        assert len(selected) == 2
        retry_key_id = next(k['id'] for k in client.get('/admin/api-keys', headers=auth).json() if k['name'] == 'retry-key')
        metrics = client.get('/admin/metrics', headers=auth, params={'key_id':retry_key_id}).json()
        assert metrics['unique_requests'] == 1 and metrics['attempts'] == 2 and metrics['retry_attempts'] == 1
        route_calls = []
        async def replace_route_then_timeout(config, data):
            route_calls.append(config['model'])
            with Session(test_engine) as session:
                session.get(ModelRoute, retry_route_id).alias = 'renamed-judge'
                session.flush()
                session.add(ModelRoute(alias='retry-judge', operation='decision', active=True, retry_on_failure=True,
                    targets=[RouteTarget(model_id=backup, priority=0, weight=1)]))
                session.commit()
            raise TimeoutError()
        old_decision = providers.decision
        providers.decision = replace_route_then_timeout
        try:
            result = client.post('/v1/decisions', headers={'Authorization':'Bearer '+retry_key}, json={'model':'retry-judge','input':'x','questions':[{'type':'predicate','name':'ok','instructions':'test?'}]})
            assert result.status_code == 504 and len(route_calls) == 1
        finally:
            providers.decision = old_decision
        providers.decision = fake_decisions
        openai = client.post('/admin/providers', headers=auth, json={'name':'openai-decision','provider_type':'openai','api_key':'fake'}).json()['id']
        openai_model = client.post('/admin/models', headers=auth, json={'alias':'openai-decision','provider_id':openai,'upstream_model':'gpt-6-luna','operations':['decision']}).json()['id']
        assert client.post('/admin/routes', headers=auth, json={'alias':'multi-judge','operation':'decision','targets':[{'model_id':model_id,'priority':0},{'model_id':openai_model,'priority':1}]}).status_code == 201
        multi_key = client.post('/admin/api-keys', headers=auth, json={'name':'multi-decision','model_ids':[model_id,openai_model]}).json()['key']
        original_decision = providers.decision
        dispatched = []
        async def mock_decision(config, data):
            dispatched.append(config)
            return {'answers':[{'type':'predicate','name':'ok','probability':0.9}]}
        providers.decision = mock_decision
        image = base64.b64encode(b'\x89PNG\r\n\x1a\nmock').decode()
        body = {'model':'multi-judge','input':[{'type':'message','role':'user','content':[{'type':'input_image','image_url':'data:image/png;base64,'+image}]}],'questions':[{'type':'predicate','name':'ok','instructions':'test?'}]}
        assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+multi_key}, json=body).status_code == 200
        assert dispatched[-1]['model'] == 'openai/gpt-6-luna'
        assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+multi_key,'TypeSafe-Danger-Zone-Images':'true'}, json=body).status_code == 200
        assert dispatched[-1]['model'] == 'typesafe/jev-latest'
        providers.decision = original_decision
        # Avoid a fixed-window rollover during the concurrency assertion.
        with test_engine.connect() as connection:
            second = int(connection.execute(text('SELECT EXTRACT(SECOND FROM now())')).scalar_one())
        if second >= 55:
            time.sleep(61 - second)
        response = client.post('/admin/api-keys', headers=auth, json={'name':'test', 'model_ids':[model_id], 'requests_per_minute': 5}); assert response.status_code == 201
        key_id, raw = response.json()['id'], response.json()['key']
        payload = {'model':'judge','input':'sample','questions':[{'type':'predicate','name':'ok','instructions':'Is this ok?'}]}
        response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+raw}, json=payload); assert response.status_code == 200
        assert response.json()['usage']['input_tokens'] == 10 and 'output_tokens' not in response.json()['usage']
        rows = client.get('/admin/usage/requests', headers=auth).json()
        assert rows[0]['input_tokens'] == 10 and rows[0]['output_tokens'] is None and Decimal(str(rows[0]['estimated_cost'])) == Decimal('0.01')
        assert any(x['action']=='price.create' for x in client.get('/admin/audit', headers=auth).json())
        # One request already consumed; concurrent upserts must admit exactly four more.
        def attempt(_):
            with Session(test_engine) as session:
                key = session.get(ClientKey, key_id)
                try:
                    consume(session, key); session.commit(); return 200
                except HTTPException as error:
                    return error.status_code
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))
        assert results.count(200) == 4 and results.count(429) == 8, results
        for setting_name, value in {'ISSUER':'https://identity.example','AUTHORIZATION_URL':'https://identity.example/authorize',
                            'TOKEN_URL':'https://identity.example/token','JWKS_URL':'https://identity.example/keys',
                            'CLIENT_ID':'magpie','REDIRECT_URI':'https://magpie.example/oidc/callback'}.items():
            os.environ['MAGPIE_OIDC_' + setting_name] = value
        linked = client.post('/admin/oidc-identities', headers=auth, json={'user_id': 1, 'subject': 'linked-subject'})
        assert linked.status_code == 201, linked.text
        link_user = client.post('/admin/users', headers=auth, json={'username':'link-race','password':'valid test password'}).json()['id']
        with Session(test_engine) as locker, ThreadPoolExecutor(max_workers=1) as pool:
            locked_user = locker.scalar(select(AdminUser).where(AdminUser.id == link_user).with_for_update())
            locked_user.active = False
            locker.flush()
            future = pool.submit(client.post, '/admin/oidc-identities', headers=auth, json={'user_id':link_user,'subject':'link-race-subject'})
            try:
                try:
                    future.result(timeout=0.25)
                    raise AssertionError('Identity linking did not wait for administrator lock')
                except FutureTimeout:
                    pass
            finally:
                locker.commit()
            assert future.result(timeout=10).status_code == 404
        assert not any(identity['subject'] == 'link-race-subject' for identity in client.get('/admin/oidc-identities', headers=auth).json())
        assert client.put(f'/admin/users/{race_user}/active', headers=auth, json={'active':True}).status_code == 200
        assert client.post('/admin/oidc-identities', headers=auth, json={'user_id':race_user,'subject':'race-subject'}).status_code == 201
        race_start = client.post('/auth/oidc/start').json()
        verified = threading.Event()
        original_exchange, original_oidc_verify = oidc.exchange, oidc.verify
        async def fake_exchange(settings, code, verifier): return ('test-token', {})
        def fake_verify(settings, token, keys, nonce_hash):
            verified.set()
            return 'race-subject'
        oidc.exchange, oidc.verify = fake_exchange, fake_verify
        try:
            with Session(test_engine) as locker, ThreadPoolExecutor(max_workers=1) as pool:
                locked_user = locker.scalar(select(AdminUser).where(AdminUser.id == race_user).with_for_update())
                locked_user.active = False
                locker.flush()
                future = pool.submit(client.post, '/auth/oidc/callback', json={'state':race_start['state'],'browser_secret':race_start['browser_secret'],'code':'mock'})
                try:
                    assert verified.wait(10)
                    try:
                        future.result(timeout=0.25)
                        raise AssertionError('SSO callback did not wait for the administrator row lock')
                    except FutureTimeout:
                        pass
                finally:
                    locker.commit()
                assert future.result(timeout=10).status_code == 403
        finally:
            oidc.exchange, oidc.verify = original_exchange, original_oidc_verify
        start = client.post('/auth/oidc/start').json()
        nonce = parse_qs(urlparse(start['authorization_url']).query)['nonce'][0]
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
        public.update({'kid': 'test-key', 'use': 'sig'})
        async def fake_oidc_exchange(settings, code, verifier):
            token = jwt.encode({'iss': settings.issuer, 'sub':'linked-subject', 'aud':settings.client_id,
                                'iat':int(time.time()), 'exp':int(time.time())+300, 'nonce':nonce},
                               private, algorithm='RS256', headers={'kid':'test-key'})
            return token, {'keys': [public]}
        oidc.exchange = fake_oidc_exchange
        sso = client.post('/auth/oidc/callback', json={'state':start['state'], 'browser_secret':start['browser_secret'], 'code':'offline'})
        assert sso.status_code == 200, sso.text
        sso_headers = {'Authorization': 'Bearer '+sso.json()['token']}
        assert client.get('/admin/providers', headers=sso_headers).status_code == 200
        # One state must remain single-use even when multiple workers receive
        # the same callback concurrently; only the winner may exchange a code.
        concurrent_start = client.post('/auth/oidc/start').json()
        nonce = parse_qs(urlparse(concurrent_start['authorization_url']).query)['nonce'][0]
        exchanges = []
        async def counted_exchange(settings, code, verifier):
            exchanges.append(True)
            await asyncio.sleep(0.05)
            return await fake_oidc_exchange(settings, code, verifier)
        oidc.exchange = counted_exchange
        callback = {'state':concurrent_start['state'], 'browser_secret':concurrent_start['browser_secret'], 'code':'offline'}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: client.post('/auth/oidc/callback', json=callback).status_code, range(8)))
        assert results.count(200) == 1 and results.count(400) == 7, results
        assert len(exchanges) == 1
        assert client.delete('/admin/oidc-identities/'+str(linked.json()['id']), headers=auth).status_code == 204
        assert client.get('/admin/providers', headers=sso_headers).status_code == 401
        routed = client.post('/admin/routes', headers=auth, json={'alias':'jev-route','operation':'decision',
            'targets':[{'model_id':model_id,'priority':0,'weight':1}]})
        assert routed.status_code == 201, routed.text
        route_key = client.post('/admin/api-keys', headers=auth, json={'name':'route-key','model_ids':[model_id]}).json()['key']
        route_call = client.post('/v1/decisions', headers={'Authorization':'Bearer '+route_key},
            json={'model':'jev-route','input':'sample','questions':[{'type':'predicate','name':'ok','instructions':'Is this ok?'}]})
        assert route_call.status_code == 200 and route_call.json()['model'] == 'jev-route'
        route_records = client.get('/admin/usage/requests', headers=auth).json()
        assert any(item['requested_alias'] == 'jev-route' and item['model_id'] == model_id for item in route_records)
        def alias_race(kind):
            with Session(test_engine) as session:
                try:
                    if kind == 'model':
                        create_model(ModelIn(alias='race-alias', provider_id=provider_id, upstream_model='jev-race', operations=['decision']), session, 'admin:1')
                    else:
                        create_route(RouteIn(alias='race-alias', operation='decision', targets=[{'model_id':model_id}]), session, 'admin:1')
                    return 201
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            race = list(pool.map(alias_race, ['model','route']))
        assert sorted(race) == [201, 409], race
        budget_response = client.put('/admin/api-keys/'+str(key_id)+'/budget', headers=auth,
            json={'currency':'USD','limit_amount':'0.10','reserve_per_request':'0.02'})
        assert budget_response.status_code == 200
        # A locked budget must not hold a request indefinitely or dispatch a
        # provider call before the reservation transaction commits.
        lock_key = client.post('/admin/api-keys', headers=auth, json={'name':'lock-test','model_ids':[model_id]}).json()
        assert client.put(f"/admin/api-keys/{lock_key['id']}/budget", headers=auth, json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.02'}).status_code == 200
        bounded_engine = runtime_engine(test_url, lock_timeout_ms=2000, statement_timeout_ms=5000)
        def get_bounded_db():
            with Session(bounded_engine) as session:
                yield session
        app.dependency_overrides[db_session] = get_bounded_db
        dispatched_lock = []
        original_decision = providers.decision
        async def lock_decision(config, data):
            dispatched_lock.append(True)
            return {'answers':[{'type':'predicate','name':'ok','probability':0.9}]}
        providers.decision = lock_decision
        try:
            # Catalog DDL locks can block even a SELECT. Model lookup must not
            # block the ASGI loop while this unrelated request waits.
            with Session(test_engine) as holder, ThreadPoolExecutor(max_workers=1) as pool:
                holder.execute(text('LOCK TABLE model_routes IN ACCESS EXCLUSIVE MODE'))
                waiting = pool.submit(client.post, '/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload)
                try:
                    deadline = time.monotonic() + 1.5
                    while time.monotonic() < deadline:
                        with test_engine.connect() as connection:
                            blocked = connection.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%model_routes%'"))
                        if blocked: break
                        time.sleep(0.02)
                    assert blocked, 'request did not reach the route lock'
                    before = time.monotonic()
                    assert client.get('/health/live').status_code == 200
                    assert time.monotonic() - before < 1, 'model selection blocked the event loop'
                finally:
                    holder.rollback()
                assert waiting.result(timeout=5).status_code == 200
            with Session(test_engine) as holder:
                holder.scalar(select(KeyBudget).where(KeyBudget.client_key_id == lock_key['id']).with_for_update())
                started = time.monotonic()
                locked_response = client.post('/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload)
                assert locked_response.status_code == 503 and time.monotonic() - started < 3
                assert dispatched_lock == [True]
                with Session(test_engine) as check:
                    records = check.scalars(select(UsageRecord).where(UsageRecord.client_key_id == lock_key['id'])).all()
                    assert len(records) == 1 and records[0].status == 'success'
                holder.rollback()
            with Session(test_engine) as holder, ThreadPoolExecutor(max_workers=1) as pool:
                holder.scalar(select(KeyBudget).where(KeyBudget.client_key_id == lock_key['id']).with_for_update())
                waiting = pool.submit(client.post, '/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload)
                try:
                    deadline = time.monotonic() + 1.5
                    while time.monotonic() < deadline:
                        with test_engine.connect() as connection:
                            blocked = connection.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%key_budgets%'"))
                        if blocked:
                            break
                        time.sleep(0.02)
                    assert blocked, 'request did not reach the budget lock'
                    before = time.monotonic()
                    assert client.get('/health/live').status_code == 200
                    assert time.monotonic() - before < 1, 'lock wait blocked the event loop'
                finally:
                    holder.rollback()
                assert waiting.result(timeout=5).status_code == 200
            assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload).status_code == 200
            assert dispatched_lock == [True, True, True]
            provider_entered, provider_release = threading.Event(), threading.Event()
            async def delayed_result(config, data):
                provider_entered.set()
                assert await asyncio.to_thread(provider_release.wait, 5)
                return {'answers':[{'type':'predicate','name':'ok','probability':0.9}]}
            providers.decision = delayed_result
            with Session(test_engine) as holder, ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(client.post, '/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload)
                try:
                    assert provider_entered.wait(5)
                    row = holder.scalar(select(UsageRecord).where(UsageRecord.client_key_id == lock_key['id'], UsageRecord.status == 'started').with_for_update())
                    assert row is not None
                    provider_release.set()
                    deadline = time.monotonic() + 1.5
                    while time.monotonic() < deadline:
                        with test_engine.connect() as connection:
                            blocked = connection.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%usage_records%'"))
                        if blocked: break
                        time.sleep(0.02)
                    assert blocked, 'finalization did not reach the usage record lock'
                    before = time.monotonic()
                    assert client.get('/health/live').status_code == 200
                    assert time.monotonic() - before < 1, 'finalization blocked the event loop'
                finally:
                    provider_release.set()
                    holder.rollback()
                assert pending.result(timeout=5).status_code == 200
        finally:
            providers.decision = original_decision
            app.dependency_overrides[db_session] = get_test_db
            bounded_engine.dispose()
        # Requests already handed to the adapter may finish, while requests
        # arriving after the administrative change must never reach it.
        for change in ('key', 'model', 'provider'):
            held_provider = client.post('/admin/providers', headers=auth, json={'name':'held-'+change,'provider_type':'typesafe','api_key':'fake'}).json()
            held_model = client.post('/admin/models', headers=auth, json={'alias':'held-'+change,'provider_id':held_provider['id'],
                'upstream_model':'jev-latest','operations':['decision']}).json()
            held_key = client.post('/admin/api-keys', headers=auth, json={'name':'held-'+change,'model_ids':[held_model['id']]}).json()
            entered, release, calls = threading.Event(), threading.Event(), []
            async def held_decision(config, data):
                calls.append(config['model'])
                entered.set()
                await asyncio.to_thread(release.wait, 5)
                return {'answers':[{'type':'predicate','name':'ok','probability':0.9}]}
            providers.decision = held_decision
            request_body = {'model':'held-'+change,'input':'test','questions':[{'type':'predicate','name':'ok','instructions':'yes?'}]}
            key_headers = {'Authorization':'Bearer '+held_key['key']}
            try:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(client.post, '/v1/decisions', headers=key_headers, json=request_body)
                    try:
                        assert entered.wait(5), change
                        if change == 'key':
                            changed = client.delete('/admin/api-keys/'+str(held_key['id']), headers=auth)
                        elif change == 'model':
                            changed = client.put('/admin/models/'+str(held_model['id'])+'/active', headers=auth, json={'active':False})
                        else:
                            changed = client.put('/admin/providers/'+str(held_provider['id'])+'/active', headers=auth, json={'active':False})
                        assert changed.status_code in (200, 204), (change, changed.text)
                        denied = client.post('/v1/decisions', headers=key_headers, json=request_body)
                        assert denied.status_code in (401, 403), (change, denied.status_code)
                    finally:
                        release.set()
                    assert pending.result(timeout=5).status_code == 200
                    assert len(calls) == 1, change
            finally:
                release.set()
                providers.decision = original_decision
        def reserve_attempt(_):
            with Session(test_engine) as session:
                try:
                    request_id, _started = observability.begin(session, key_id, model_id, 'decision', 1, 1)
                    return request_id
                except HTTPException as error:
                    assert error.status_code == 429
                    return None
        with ThreadPoolExecutor(max_workers=12) as pool:
            reservations = list(pool.map(reserve_attempt, range(12)))
        accepted = [r for r in reservations if r]
        assert len(accepted) == 5, reservations
        with Session(test_engine) as session:
            for request_id in accepted:
                session.execute(text("UPDATE usage_records SET started_at = '2099-01-01T00:00:00Z' WHERE request_id = :request_id"), {'request_id':request_id})
            session.commit()
        for path, extra in [('/admin/usage/requests', {'key_id':key_id}), ('/admin/budget-reservations', {})]:
            cursor = dict(extra, limit=2)
            paged = []
            for _ in range(3):
                page = client.get(path, headers=auth, params=cursor)
                assert page.status_code == 200, page.text
                items = page.json()
                assert items
                paged.extend(item['request_id'] for item in items)
                cursor.update(before_started_at=items[-1]['started_at'], before_request_id=items[-1]['request_id'])
            assert paged[:5] == sorted(accepted, reverse=True)
        def reconcile_once(_):
            with Session(test_engine) as session:
                existing = session.get(BudgetReservation, accepted[0])
                result = budgets.settle(session, existing, Decimal('0.01'), 'manual', 'concurrent test', 'admin:1', True)
                session.commit()
                return result
        with ThreadPoolExecutor(max_workers=2) as pool:
            reconciled = list(pool.map(reconcile_once, range(2)))
        assert sorted(reconciled) == [False, True], reconciled
        history = client.get('/admin/budget-reservations/'+accepted[0]+'/adjustments', headers=auth).json()
        assert history['reconciliation_note'] == 'concurrent test' and history['reconciliation_actor'] == 'admin:1' and history['reconciled_at'] is not None
        assert history['reconciliation_forced'] is True
        def adjust_once(number):
            with Session(test_engine) as session:
                try:
                    adjust_budget(accepted[0], AdjustmentIn(id='adjust-'+str(number), expected_amount=Decimal('0.01'),
                        revised_amount=Decimal('0.03'), note='invoice'), session, 'admin:1')
                    return 200
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            adjusted = list(pool.map(adjust_once, range(2)))
        assert sorted(adjusted) == [200, 409], adjusted
        with Session(test_engine) as session:
            budget = session.get(KeyBudget, key_id)
            assert budget.spent_amount == Decimal('0.03') and budget.held_amount == Decimal('0.08')
        # A completion can hold the usage row while deciding its final status.
        # Reconciliation must wait, then use that committed status instead of
        # rejecting based on the pre-completion "started" snapshot.
        with Session(test_engine) as holder, ThreadPoolExecutor(max_workers=1) as pool:
            row = holder.scalar(select(UsageRecord).where(UsageRecord.request_id == accepted[1]).with_for_update())
            assert row.status == 'started'
            row.status = 'error'
            row.finished_at = datetime.now(timezone.utc)
            holder.flush()
            pending = pool.submit(client.post, '/admin/budget-reservations/'+accepted[1]+'/reconcile',
                headers=auth, json={'settled_amount':'0.01','note':'provider receipt','force_started':False})
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with test_engine.connect() as connection:
                        blocked = connection.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%usage_records%'"))
                    if blocked: break
                    time.sleep(0.02)
                assert blocked, 'manual reconciliation did not wait for usage finalization'
            finally:
                holder.commit()
            result = pending.result(timeout=5)
            assert result.status_code == 200, result.text
        record = client.get('/admin/budget-reservations/'+accepted[1]+'/adjustments', headers=auth).json()
        assert record['status'] == 'manual' and record['reconciliation_forced'] is False
        with Session(test_engine) as session:
            session.execute(text("UPDATE usage_records SET finished_at = now() - interval '60 days' WHERE request_id = :request_id"), {'request_id': accepted[0]})
            session.execute(text("INSERT INTO usage_records (request_id, client_key_id, model_id, operation, status, started_at, finished_at) VALUES ('old-no-reservation', :key, :model, 'decision', 'success', now() - interval '60 days', now() - interval '60 days')"), {'key': key_id, 'model': model_id})
            session.commit()
        preview = client.post('/admin/retention/preview', headers=auth, json={'usage_days': 30, 'audit_days': 30})
        assert preview.status_code == 200 and preview.json()['usage_records'] == 1, preview.text
        applied = client.post('/admin/retention/apply', headers=auth, json={'usage_days': 30, 'audit_days': 30})
        assert applied.status_code == 200 and applied.json()['usage_records_deleted'] == 1, applied.text
        with Session(test_engine) as session:
            assert session.get(UsageRecord, accepted[0]) is not None
            assert session.get(UsageRecord, 'old-no-reservation') is None
        with Session(test_engine) as session:
            assert recover(session, user['username'], 'recovered test password') == 1
        assert client.get('/admin/providers', headers=auth).status_code == 401
        recovered = client.post('/admin/sessions', json={'username':user['username'], 'password':'recovered test password'})
        assert recovered.status_code == 201
        recovered_auth = {'Authorization':'Bearer '+recovered.json()['token']}
        assert any(row['action'] == 'admin.recover' and row['actor'] == 'operator' for row in client.get('/admin/audit', headers=recovered_auth).json())
        assert client.delete('/admin/sessions/current', headers=recovered_auth).status_code == 204
        assert client.get('/admin/providers', headers=recovered_auth).status_code == 401
        new_encryption_key = Fernet.generate_key().decode()
        try:
            with Session(test_engine) as session:
                pending_sso = oidc.start(session, oidc.config())
                assert rotate(session, saved_encryption, new_encryption_key) > 0
                os.environ['MAGPIE_ENCRYPTION_KEY'] = new_encryption_key
                verifier, _ = oidc.consume(session, pending_sso['state'], pending_sso['browser_secret'])
                assert verifier
        finally:
            os.environ['MAGPIE_ENCRYPTION_KEY'] = saved_encryption
        key_barrier = threading.Barrier(2)
        def issue_same_key(_):
            with Session(test_engine) as session:
                key_barrier.wait(timeout=10)
                try:
                    main_module.create_key(main_module.KeyIn(name='deduplicated', model_ids=[exa_model]), session,
                                           'admin:1', idempotency_key='offline_test_request_0123456789')
                    return 201
                except HTTPException as error:
                    return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            issue_results = list(pool.map(issue_same_key, range(2)))
        assert sorted(issue_results) == [201, 409], issue_results
        with Session(test_engine) as session:
            assert len(session.scalars(select(ClientKey).where(ClientKey.name == 'deduplicated')).all()) == 1
        # Two operators can deactivate different users at the same time. The
        # shared bootstrap row must serialize the final-active-user check.
        with Session(test_engine) as session:
            main_module.set_admin_active(race_user, main_module.ActiveIn(active=True), session, 'admin:1')
            for number, user_id in enumerate((1, race_user)):
                session.add(AdminSession(token_hash=f'{number + 1:064x}', user_id=user_id,
                                         expires_at=datetime.now(timezone.utc) + timedelta(hours=1), revoked=False))
            session.commit()
        barrier = threading.Barrier(2)
        def deactivate_last_admin(user_id):
            with Session(test_engine) as session:
                barrier.wait(timeout=10)
                try:
                    main_module.set_admin_active(user_id, main_module.ActiveIn(active=False), session, 'admin:1')
                    return 200
                except HTTPException as error:
                    session.rollback()
                    return error.status_code
        with Session(test_engine) as locker, ThreadPoolExecutor(max_workers=2) as pool:
            locker.scalar(select(BootstrapLock).where(BootstrapLock.id == 1).with_for_update())
            futures = [pool.submit(deactivate_last_admin, user_id) for user_id in (1, race_user)]
            try:
                for future in futures:
                    try:
                        future.result(timeout=0.25)
                        raise AssertionError('Administrator change did not wait for shared lock')
                    except FutureTimeout:
                        pass
            finally:
                locker.commit()
            result = [future.result(timeout=10) for future in futures]
        assert sorted(result) == [200, 409], result
        with Session(test_engine) as session:
            active = session.scalars(select(AdminUser).where(AdminUser.active.is_(True))).all()
            assert len(active) == 1 and active[0].id in (1, race_user)
            sessions = session.scalars(select(AdminSession).where(AdminSession.token_hash.in_([f'{1:064x}', f'{2:064x}']))).all()
            assert len(sessions) == 2 and all(item.revoked == (item.user_id != active[0].id) for item in sessions)
    print('PostgreSQL migrations, accounts, mocked OIDC and Jev, pricing, audit, limits, budgets, routing and retention passed')
finally:
    app.dependency_overrides.clear()
    test_engine.dispose()
    with admin_engine.connect() as connection:
        connection.execute(text(f'DROP DATABASE "{db_name}"'))
    admin_engine.dispose()
