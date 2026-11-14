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
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from decimal import Decimal
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from app.main import CapabilityVerificationIn, ModelIn, ProviderGroupIn, SecretIn, app, change_provider_key, create_model, db_session, lock_catalog, rotate_provider_key, set_capability_verification, set_provider_model_group, update_model
from app.models import AdminSession, AdminUser, AuditLog, BootstrapLock, BudgetReservation, ClientKey, KeyBudget, ModelRoute, OIDCIdentity, OIDCTransaction, RouteTarget, UsageRecord
from app.rate_limit import consume
from app.database import runtime_engine
from app.recover_admin import recover
from app.rotate_key import rotate
from app import observability, providers

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
        from app.maintenance import prune
        from app.security import hash_key
        legacy_token = 'mga_legacy_postgres'
        with Session(test_engine) as session:
            identity = OIDCIdentity(issuer='https://legacy.example', subject='legacy', user_id=1)
            session.add(identity); session.flush()
            session.add(AdminSession(user_id=1, oidc_identity_id=identity.id, token_hash=hash_key(legacy_token),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
            session.add(AdminSession(user_id=1, oidc_identity_id=identity.id, token_hash=hash_key('expired-legacy'),
                expires_at=datetime.now(timezone.utc) - timedelta(days=3)))
            session.commit(); identity_id = identity.id
        assert client.get('/admin/providers', headers={'Authorization':'Bearer '+legacy_token}).status_code == 401
        with Session(test_engine) as session:
            prune(session)
            assert session.get(OIDCIdentity, identity_id) is not None
            assert len(session.scalars(select(AdminSession).where(AdminSession.oidc_identity_id == identity_id)).all()) == 2
        # Hold the catalog lock in each possible winner, then start the other
        # operation. Verify both serialization orders without provider access.
        for group_first in (True, False):
            suffix = 'group-first' if group_first else 'model-first'
            group_provider = client.post('/admin/providers', headers=auth, json={
                'name':'purpose-race-' + suffix, 'provider_type':'openai', 'model_group':'general'}).json()['id']
            entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
            model_body = ModelIn(alias='purpose-' + suffix, provider_id=group_provider, upstream_model='mock', operations=['generation'])
            def operation(group, hold=False):
                with Session(test_engine) as session:
                    try:
                        if hold:
                            lock_catalog(session)
                            entered.set()
                            assert release.wait(10)
                        else:
                            second_started.set()
                        if group:
                            set_provider_model_group(group_provider, ProviderGroupIn(model_group='embedding'), session, 'admin:1')
                            return 200
                        create_model(model_body, session, 'admin:1')
                        return 201
                    except HTTPException as error:
                        session.rollback()
                        return error.status_code
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(operation, group_first, True)
                assert entered.wait(10)
                second = pool.submit(operation, not group_first)
                assert second_started.wait(10)
                try:
                    try:
                        second.result(timeout=0.2)
                        raise AssertionError('Catalog lock did not block the competing operation')
                    except FutureTimeout:
                        pass
                finally:
                    release.set()
                results = (first.result(timeout=10), second.result(timeout=10))
            assert results == ((200, 422) if group_first else (201, 409)), results
            providers_after = client.get('/admin/providers', headers=auth).json()
            group_after = next(p['model_group'] for p in providers_after if p['id'] == group_provider)
            models_after = [m for m in client.get('/admin/models', headers=auth).json() if m['provider_id'] == group_provider]
            assert (group_after, len(models_after)) == (('embedding', 0) if group_first else ('general', 1))
        # Reassignment of an existing model must obey the same lock ordering.
        for group_first in (True, False):
            suffix = 'move-group-first' if group_first else 'move-model-first'
            source = client.post('/admin/providers', headers=auth, json={
                'name':'source-' + suffix, 'provider_type':'openai', 'model_group':'general'}).json()['id']
            target = client.post('/admin/providers', headers=auth, json={
                'name':'target-' + suffix, 'provider_type':'openai', 'model_group':'general'}).json()['id']
            created = client.post('/admin/models', headers=auth, json={
                'alias':'purpose-' + suffix, 'provider_id':source, 'upstream_model':'mock', 'operations':['generation']}).json()['id']
            body = ModelIn(alias='purpose-' + suffix, provider_id=target, upstream_model='mock', operations=['generation'])
            entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
            def change_or_move(group, hold=False):
                with Session(test_engine) as session:
                    try:
                        if hold:
                            lock_catalog(session)
                            entered.set()
                            assert release.wait(10)
                        else:
                            second_started.set()
                        if group:
                            set_provider_model_group(target, ProviderGroupIn(model_group='embedding'), session, 'admin:1')
                        else:
                            update_model(created, body, session, 'admin:1')
                        return 200
                    except HTTPException as error:
                        session.rollback()
                        return error.status_code
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(change_or_move, group_first, True)
                assert entered.wait(10)
                second = pool.submit(change_or_move, not group_first)
                assert second_started.wait(10)
                try:
                    try:
                        second.result(timeout=0.2)
                        raise AssertionError('Catalog lock did not block model reassignment')
                    except FutureTimeout:
                        pass
                finally:
                    release.set()
                results = (first.result(timeout=10), second.result(timeout=10))
            assert results == ((200, 422) if group_first else (200, 409)), results
            group_after = next(p['model_group'] for p in client.get('/admin/providers', headers=auth).json() if p['id'] == target)
            model_after = next(m for m in client.get('/admin/models', headers=auth).json() if m['id'] == created)
            assert (group_after, model_after['provider_id']) == (('embedding', source) if group_first else ('general', target))
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
            assert health['unreadable_count'] == 1 and next(p['status'] for p in health['providers'] if p['provider_id'] == deferred_id) == 'unreadable'
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
        async def incomplete_stream(config, data):
            async def chunks():
                yield {'choices':[{'index':0,'delta':{'content':'partial'},'finish_reason':None}]}
            return chunks()
        providers.completion = incomplete_stream
        truncated = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+stream_key['key']}, json={'model':'chat-mock','messages':[{'role':'user','content':'test'}],'stream':True})
        assert truncated.status_code == 200 and 'Provider stream failed' in truncated.text and '[DONE]' not in truncated.text
        record = client.get('/admin/usage/requests', headers=auth, params={'root_request_id':truncated.headers['x-request-id']}).json()[0]
        assert record['status'] == 'error' and record['estimated_cost'] is None
        providers.completion = fake_chat
        assert client.put('/admin/models/'+str(exa_model), headers=auth, json={'alias':'chat-mock','provider_id':exa_provider,'upstream_model':'mock','operations':['generation'],'supports_tools':False}).status_code == 200
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
        response = client.post('/admin/models', headers=auth, json={'alias':'judge', 'provider_id':provider_id, 'upstream_model':'jev-latest', 'operations':['decision']}); assert response.status_code == 201
        model_id = response.json()['id']
        response = client.post('/admin/prices', headers=auth, json={'model_id':model_id, 'currency':'USD', 'basis':'question', 'per_question':'0.01'}); assert response.status_code == 201
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
        # Legacy routing configuration stays stored but no longer dispatches.
        with Session(test_engine) as session:
            old_route = ModelRoute(alias='legacy-judge-route', operation='decision', active=True, retry_on_failure=True)
            session.add(old_route); session.flush()
            session.add(RouteTarget(route_id=old_route.id, model_id=model_id, priority=0, weight=1))
            session.commit(); old_route_id = old_route.id
        assert client.get('/admin/routes', headers=auth).status_code == 404
        assert client.post('/v1/decisions', headers={'Authorization':'Bearer '+raw}, json={**payload, 'model':'legacy-judge-route'}).status_code == 403
        with Session(test_engine) as session:
            assert session.get(ModelRoute, old_route_id) is not None
            assert len(session.scalars(select(RouteTarget).where(RouteTarget.route_id == old_route_id)).all()) == 1
        lock_key = client.post('/admin/api-keys', headers=auth, json={'name':'lock-test','model_ids':[model_id]}).json()
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
                holder.execute(text('LOCK TABLE model_registrations IN ACCESS EXCLUSIVE MODE'))
                waiting = pool.submit(client.post, '/v1/decisions', headers={'Authorization':'Bearer '+lock_key['key']}, json=payload)
                try:
                    deadline = time.monotonic() + 1.5
                    while time.monotonic() < deadline:
                        with test_engine.connect() as connection:
                            blocked = connection.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%model_registrations%'"))
                        if blocked: break
                        time.sleep(0.02)
                    assert blocked, 'request did not reach the model lock'
                    before = time.monotonic()
                    assert client.get('/health/live').status_code == 200
                    assert time.monotonic() - before < 1, 'model selection blocked the event loop'
                finally:
                    holder.rollback()
                assert waiting.result(timeout=5).status_code == 200
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
        # Historical budget rows remain protected from retention; no new budget is created.
        with Session(test_engine) as session:
            old = datetime.now(timezone.utc) - timedelta(days=60)
            session.add(KeyBudget(client_key_id=key_id, currency='USD', limit_amount=Decimal('1'),
                                  reserve_per_request=Decimal('.1'), spent_amount=Decimal('0'), held_amount=Decimal('.1')))
            session.add(UsageRecord(request_id='legacy-budget-record', client_key_id=key_id, model_id=model_id,
                                    operation='decision', status='success', started_at=old, finished_at=old))
            session.flush()
            session.add(BudgetReservation(request_id='legacy-budget-record', client_key_id=key_id,
                                          reserved_amount=Decimal('.1'), status='pending'))
            session.add(UsageRecord(request_id='old-no-reservation', client_key_id=key_id, model_id=model_id,
                                    operation='decision', status='success', started_at=old, finished_at=old))
            session.commit()
        assert client.get('/v1/models', headers={'Authorization':'Bearer '+raw}).status_code == 403
        assert next(item for item in client.get('/admin/api-keys', headers=auth).json() if item['id'] == key_id)['legacy_budget'] is True
        preview = client.post('/admin/retention/preview', headers=auth, json={'usage_days':30, 'audit_days':30})
        assert preview.status_code == 200 and preview.json()['usage_records'] == 1, preview.text
        applied = client.post('/admin/retention/apply', headers=auth, json={'usage_days':30, 'audit_days':30})
        assert applied.status_code == 200 and applied.json()['usage_records_deleted'] == 1, applied.text
        with Session(test_engine) as session:
            assert session.get(UsageRecord, 'legacy-budget-record') is not None
            assert session.get(BudgetReservation, 'legacy-budget-record') is not None
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
                pending_sso = OIDCTransaction(state_hash='legacy-state', browser_hash='legacy-browser', nonce_hash='legacy-nonce',
                    encrypted_verifier=Fernet(saved_encryption.encode()).encrypt(b'legacy-verifier').decode(),
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), used=False)
                session.add(pending_sso); session.commit()
                assert rotate(session, saved_encryption, new_encryption_key) > 0
                assert Fernet(new_encryption_key.encode()).decrypt(pending_sso.encrypted_verifier.encode()) == b'legacy-verifier'
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
        # Admin model tests have no client key: exercise the nullable usage
        # record and audit entry against PostgreSQL for every supported task.
        current = client.post('/admin/sessions', json={'username':user['username'], 'password':'recovered test password'})
        assert current.status_code == 201
        test_admin = {'Authorization':'Bearer ' + current.json()['token']}
        test_calls = []
        async def test_generation(config, data):
            test_calls.append('generation')
            return {'choices':[{'index':0, 'message':{'role':'assistant','content':'OK'}, 'finish_reason':'stop'}],
                    'usage':{'prompt_tokens':2,'completion_tokens':1}}
        async def test_embedding(config, data):
            test_calls.append('embedding')
            return {'data':[{'index':0, 'embedding':[0.1,0.2]}], 'usage':{'prompt_tokens':2}}
        async def test_decision(config, data):
            test_calls.append('decision')
            return {'answers':[{'type':'predicate', 'name':'test', 'probability':0.9}],
                    'usage':{'input_tokens':2,'output_tokens':1}}
        test_models = {}
        for operation, provider_type, mock in [('generation','exaone',test_generation),
                                                ('embedding','exaone',test_embedding),
                                                ('decision','typesafe',test_decision)]:
            connection = client.post('/admin/providers', headers=test_admin, json={
                'name':'admin-test-' + operation, 'provider_type':provider_type, 'api_key':'fake',
                'model_group': {'generation':'general','embedding':'embedding','decision':'decision'}[operation]}).json()
            registered = client.post('/admin/models', headers=test_admin, json={
                'alias':'admin-test-' + operation, 'provider_id':connection['id'],
                'upstream_model':'mock-model', 'operations':[operation]}).json()
            test_models[operation] = registered['id']
            previous = getattr(providers, {'generation':'completion','embedding':'embedding','decision':'decision'}[operation])
            setattr(providers, {'generation':'completion','embedding':'embedding','decision':'decision'}[operation], mock)
            try:
                response = client.post(f"/admin/models/{registered['id']}/test", headers=test_admin, json={'operation':operation})
            finally:
                setattr(providers, {'generation':'completion','embedding':'embedding','decision':'decision'}[operation], previous)
            assert response.status_code == 200, response.text
            with Session(test_engine) as session:
                usage = session.get(UsageRecord, response.json()['request_id'])
                assert usage is not None and usage.client_key_id is None and usage.model_id == registered['id']
                assert usage.operation == operation and usage.status == 'success' and usage.input_tokens == 2
                assert session.scalar(select(AuditLog.id).where(AuditLog.action == 'model.test', AuditLog.target_id == str(registered['id'])))
        # The same three registered purposes must be enforced for client calls.
        issued = client.post('/admin/api-keys', headers=test_admin, json={
            'name':'purpose-client', 'model_ids':list(test_models.values())})
        assert issued.status_code == 201, issued.text
        client_auth = {'Authorization':'Bearer ' + issued.json()['key']}
        requests = {
            'generation':('/v1/chat/completions', {'messages':[{'role':'user','content':'test'}]}),
            'embedding':('/v1/embeddings', {'input':'test'}),
            'decision':('/v1/decisions', {'input':'test','questions':[{'type':'predicate','name':'test','instructions':'Is this a test?'}]}),
        }
        old_handlers = {name:getattr(providers, name) for name in ('completion','embedding','decision')}
        providers.completion, providers.embedding, providers.decision = test_generation, test_embedding, test_decision
        try:
            test_calls.clear()
            for allowed in test_models:
                for operation, (path, body) in requests.items():
                    if allowed != operation:
                        response = client.post(path, headers=client_auth, json={'model':'admin-test-' + allowed, **body})
                        assert response.status_code == 403, (allowed, operation, response.text)
            assert not test_calls
            for operation, (path, body) in requests.items():
                response = client.post(path, headers=client_auth, json={'model':'admin-test-' + operation, **body})
                assert response.status_code == 200, (operation, response.text)
            assert test_calls == ['generation','embedding','decision']
        finally:
            for name, handler in old_handlers.items(): setattr(providers, name, handler)
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
    print('PostgreSQL migrations, accounts, mocked Jev, pricing, audit, limits, legacy budget and route retention, and retention passed')
finally:
    app.dependency_overrides.clear()
    test_engine.dispose()
    with admin_engine.connect() as connection:
        connection.execute(text(f'DROP DATABASE "{db_name}"'))
    admin_engine.dispose()
