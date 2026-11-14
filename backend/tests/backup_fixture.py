"""Seed or verify an isolated backup test database; all credentials are test-only."""
import os
import socket
import sys
from decimal import Decimal
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.engine import make_url

from app import providers
from app.database import engine
from app.main import app
from app.models import BudgetAdjustment, BudgetReservation, ClientKey, KeyBudget, ProviderConnection, ModelRoute, RouteTarget
from app.security import decrypt_secret, hash_key

# Database connections use libpq; provider clients must never reach the network.
_connect, _connect_ex, _getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
_database_host = make_url(os.environ['DATABASE_URL']).host
def _guard_connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6): raise AssertionError('Unexpected test network connection')
    return _connect(sock, address)
def _guard_connect_ex(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6): raise AssertionError('Unexpected test network connection')
    return _connect_ex(sock, address)
def _guard_dns(host, *args, **kwargs):
    if host != _database_host: raise AssertionError('Unexpected test DNS lookup')
    return _getaddrinfo(host, *args, **kwargs)
socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = _guard_connect, _guard_connect_ex, _guard_dns

PASSWORD = 'backup test password'
TEST_KEY = 'mgp_backup_test_only_key'
PROVIDER_KEY = 'synthetic-legacy-provider-key'
# Synthetic fixture created with cryptography 47.0.0; validates old ciphertext
# survives both the package upgrade and database backup/restore.
LEGACY_CIPHERTEXT = 'gAAAAABq9_AQnoW72hNpjX9yfWxvybQYz7M-ky1X60-xmMg1jqm0JbVXSSCYK_5TJWPKijcKGwx9vvJRKM6EW7dnDfI-RJarYEnvRS5lBNQIjNbyMv6it68='


async def fake_embedding(config, data):
    assert config['api_key'] == PROVIDER_KEY
    if data['input'] == 'fail':
        raise TimeoutError('mock provider failure')
    if data['input'] == 'unknown':
        return {'data':[{'index':0,'embedding':[0.1,0.2]}]}
    return {'data':[{'index':0,'embedding':[0.1,0.2]}], 'usage':{'prompt_tokens':3}}


providers.embedding = fake_embedding
with TestClient(app) as client:
    if sys.argv[1] == 'seed':
        bootstrap = {'Authorization':'Bearer '+os.environ['MAGPIE_ADMIN_TOKEN']}
        assert client.post('/admin/users', headers=bootstrap, json={'username':'backup-admin','password':PASSWORD}).status_code == 201
        session = client.post('/admin/sessions', json={'username':'backup-admin','password':PASSWORD}).json()['token']
        admin = {'Authorization':'Bearer '+session}
        provider = client.post('/admin/providers', headers=admin, json={'name':'backup-provider','provider_type':'exaone','api_key':PROVIDER_KEY}).json()
        model = client.post('/admin/models', headers=admin, json={'alias':'backup-model','provider_id':provider['id'],'upstream_model':'mock','operations':['embedding'],'embedding_dimensions':2}).json()
        key = client.post('/admin/api-keys', headers=admin, json={'name':'backup-key','model_ids':[model['id']]}).json()
        with Session(engine()) as db:
            route = ModelRoute(alias='legacy-backup-route', operation='embedding', active=True, retry_on_failure=True)
            db.add(route)
            db.flush()
            db.add(RouteTarget(route_id=route.id, model_id=model['id'], priority=0, weight=1))
            db.get(ClientKey, key['id']).key_hash = hash_key(TEST_KEY)
            db.get(ProviderConnection, provider['id']).encrypted_api_key = LEGACY_CIPHERTEXT
            db.commit()
        assert client.post('/admin/prices', headers=admin, json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
        legacy = client.post('/admin/api-keys', headers=admin, json={'name':'backup-legacy-key','model_ids':[model['id']]}).json()
        assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+TEST_KEY}, json={'model':'backup-model','input':'sample'}).status_code == 200
        failed = client.post('/v1/embeddings', headers={'Authorization':'Bearer '+legacy['key']}, json={'model':'backup-model','input':'fail'})
        assert failed.status_code == 504
        request_id = failed.headers['x-request-id']
        with Session(engine()) as db:
            db.add(KeyBudget(client_key_id=legacy['id'], currency='USD', limit_amount=Decimal('1'), reserve_per_request=Decimal('.1'), spent_amount=Decimal('.025'), held_amount=Decimal('0')))
            db.flush()
            db.add(BudgetReservation(request_id=request_id, client_key_id=legacy['id'], reserved_amount=Decimal('.1'), settled_amount=Decimal('.025'), status='manual', reconciliation_note='backup-reconciliation', reconciliation_actor='admin:1', reconciled_at=datetime.now(timezone.utc), reconciliation_forced=False))
            db.flush()
            db.add(BudgetAdjustment(id='backup-adjustment', request_id=request_id, previous_amount=Decimal('.02'), revised_amount=Decimal('.025'), note='backup-invoice', actor='admin:1', created_at=datetime.now(timezone.utc)))
            db.commit()
        assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+TEST_KEY}, json={'model':'backup-model','input':'unknown'}).status_code == 200
    elif sys.argv[1] == 'verify':
        assert client.get('/health/ready').status_code == 200
        response = client.post('/admin/sessions', json={'username':'backup-admin','password':PASSWORD})
        assert response.status_code == 201
        admin = {'Authorization':'Bearer '+response.json()['token']}
        assert client.get('/admin/models', headers=admin).json()[0]['alias'] == 'backup-model'
        assert len(client.get('/admin/audit', headers=admin).json()) >= 4
        usage = client.get('/admin/usage/requests', headers=admin).json()
        assert len(usage) == 3
        assert sum(row['status'] == 'success' and row['input_tokens'] == 3 for row in usage) == 1
        assert sum(row['status'] == 'success' and row['input_tokens'] is None for row in usage) == 1
        failed = next(row for row in usage if row['status'] == 'error')
        with Session(engine()) as db:
            route = db.query(ModelRoute).filter_by(alias='legacy-backup-route').one()
            assert route.retry_on_failure and db.query(RouteTarget).filter_by(route_id=route.id).count() == 1
            legacy = db.query(ClientKey).filter_by(name='backup-legacy-key').one()
            budget = db.get(KeyBudget, legacy.id)
            reservation = db.get(BudgetReservation, failed['request_id'])
            adjustment = db.get(BudgetAdjustment, 'backup-adjustment')
            assert Decimal(budget.spent_amount) == Decimal('.025') and Decimal(budget.held_amount) == 0
            assert reservation.reconciliation_note == 'backup-reconciliation' and Decimal(reservation.settled_amount) == Decimal('.025')
            assert adjustment.note == 'backup-invoice'
            secret = db.query(ProviderConnection).one().encrypted_api_key
            assert secret == LEGACY_CIPHERTEXT and decrypt_secret(secret) == PROVIDER_KEY
        assert next(item for item in client.get('/admin/api-keys', headers=admin).json() if item['id'] == legacy.id)['legacy_budget'] is True
        assert client.get('/admin/routes', headers=admin).status_code == 404
        assert [m['id'] for m in client.get('/v1/models', headers={'Authorization':'Bearer '+TEST_KEY}).json()['data']] == ['backup-model']
        assert client.post('/v1/embeddings', headers={'Authorization':'Bearer '+TEST_KEY}, json={'model':'backup-model','input':'restored'}).status_code == 200
    else:
        raise ValueError('unknown mode')
