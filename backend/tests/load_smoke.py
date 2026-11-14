"""Bounded local concurrency test, using an isolated PostgreSQL DB and mock provider.

Run with PYTHONPATH=. python tests/load_smoke.py; the DB role needs CREATEDB.
These observations are not production capacity or latency guarantees.
"""
import asyncio
import os
import secrets
import socket
import subprocess
import time
from decimal import Decimal

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app import providers
from app.main import app, db_session
from app.models import UsageRecord

# Fail closed if an accidentally missing provider mock attempts a network call.
# psycopg resolves only the configured database host and libpq connects itself.
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

soak_seconds = int(os.environ.get('MAGPIE_SOAK_SECONDS', '0'))
if not 0 <= soak_seconds <= 3600:
    raise ValueError('MAGPIE_SOAK_SECONDS must be between 0 and 3600')

url = make_url(os.environ['DATABASE_URL'])
admin_engine = create_engine(url.set(database='postgres'), isolation_level='AUTOCOMMIT')
db_name = 'magpie_load_' + secrets.token_hex(6)
with admin_engine.connect() as connection:
    connection.execute(text(f'CREATE DATABASE "{db_name}"'))
test_url = url.set(database=db_name)
test_engine = create_engine(test_url, pool_size=24, max_overflow=8, pool_timeout=30)
original_embedding = providers.embedding
try:
    subprocess.run(['alembic', 'upgrade', 'head'], check=True,
                   env=dict(os.environ, DATABASE_URL=test_url.render_as_string(hide_password=False)))

    def get_test_db():
        with Session(test_engine) as session:
            yield session

    app.dependency_overrides[db_session] = get_test_db
    calls = []
    async def fake_embedding(config, data):
        calls.append(config['model'])
        await asyncio.sleep(0.01)
        return {'model': 'mock', 'data': [{'index': 0, 'embedding': [0.1, 0.2]}], 'usage': {'prompt_tokens': 2, 'total_tokens': 2}}
    providers.embedding = fake_embedding

    with TestClient(app) as client:
        admin = {'Authorization': 'Bearer ' + os.environ['MAGPIE_ADMIN_TOKEN']}
        provider = client.post('/admin/providers', headers=admin, json={'name':'load','provider_type':'exaone','api_key':'fake'}).json()
        model = client.post('/admin/models', headers=admin, json={'alias':'embed','provider_id':provider['id'],'upstream_model':'fake','operations':['embedding']}).json()
        key = client.post('/admin/api-keys', headers=admin, json={'name':'load','model_ids':[model['id']]}).json()
        assert client.post('/admin/prices', headers=admin, json={'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
        limited = client.post('/admin/api-keys', headers=admin, json={'name':'limited','model_ids':[model['id']],'requests_per_minute':10}).json()
        first_data = {'alias':'embed','provider_id':provider['id'],'upstream_model':'fake','operations':['embedding'], 'embedding_space':'load-space','embedding_dimensions':2}
        assert client.put('/admin/models/'+str(model['id']), headers=admin, json=first_data).status_code == 200
        backup = client.post('/admin/models', headers=admin, json={**first_data,'alias':'backup','upstream_model':'backup'}).json()
        assert client.post('/admin/prices', headers=admin, json={'model_id':backup['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'}).status_code == 201
        assert client.post('/admin/routes', headers=admin, json={'alias':'retry-load','operation':'embedding','retry_on_failure':True,'targets':[{'model_id':model['id'],'priority':0},{'model_id':backup['id'],'priority':1}]}).status_code == 201
        retry_key = client.post('/admin/api-keys', headers=admin, json={'name':'retry-load','model_ids':[model['id'],backup['id']]}).json()

    async def run_batch(token, size, concurrency, alias='embed'):
        semaphore = asyncio.Semaphore(concurrency)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url='http://magpie-test') as client:
            async def one():
                async with semaphore:
                    start = time.monotonic()
                    response = await client.post('/v1/embeddings', headers={'Authorization':'Bearer '+token}, json={'model':alias,'input':'test'})
                    return response.status_code, time.monotonic() - start, response.headers.get('x-request-id')
            start = time.monotonic()
            results = await asyncio.gather(*(one() for _ in range(size)))
            elapsed = time.monotonic() - start
        return results, elapsed

    total = 0
    for count, parallel in [(12, 1), (36, 6), (72, 16)]:
        results, elapsed = asyncio.run(run_batch(key['key'], count, parallel))
        statuses = [item[0] for item in results]
        assert statuses.count(200) == count, statuses
        assert len({item[2] for item in results}) == count
        total += count
        durations = sorted(item[1] for item in results)
        print(f'concurrency={parallel} requests={count} elapsed_s={elapsed:.3f} p95_s={durations[int((len(durations)-1)*0.95)]:.3f}')

    if soak_seconds:
        async def soak():
            deadline = time.monotonic() + soak_seconds
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url='http://magpie-test') as client:
                async def worker():
                    count = 0
                    while time.monotonic() < deadline:
                        response = await client.post('/v1/embeddings', headers={'Authorization':'Bearer '+key['key']}, json={'model':'embed','input':'test'})
                        assert response.status_code == 200, response.status_code
                        count += 1
                        await asyncio.sleep(0.05)
                    return count
                return sum(await asyncio.gather(*(worker() for _ in range(4))))
        started = time.monotonic()
        soak_count = asyncio.run(soak())
        assert soak_count > 0
        total += soak_count
        print(f'soak workers=4 requests={soak_count} elapsed_s={time.monotonic()-started:.3f}')

    with test_engine.connect() as connection:
        second = int(connection.execute(text('SELECT EXTRACT(SECOND FROM now())')).scalar_one())
    if second >= 40:
        time.sleep(61 - second)
    limited_results, _ = asyncio.run(run_batch(limited['key'], 30, 15))
    statuses = [item[0] for item in limited_results]
    assert statuses.count(200) == 10 and statuses.count(429) == 20, statuses

    with Session(test_engine) as session:
        assert session.scalar(select(func.count()).select_from(UsageRecord).where(UsageRecord.client_key_id == key['id'], UsageRecord.status == 'success')) == total
        assert session.scalar(select(func.sum(UsageRecord.estimated_cost)).where(UsageRecord.client_key_id == key['id'])) == Decimal('0.02') * total
        assert session.scalar(select(func.count()).select_from(UsageRecord).where(UsageRecord.client_key_id == limited['id'])) == 10
    assert len(calls) == total + 10
    async def flaky_embedding(config, data):
        await asyncio.sleep(0.01)
        if config['model'].endswith('/fake'):
            raise TimeoutError('mock timeout')
        return {'model':'mock','data':[{'index':0,'embedding':[0.1,0.2]}],'usage':{'prompt_tokens':2}}
    providers.embedding = flaky_embedding
    retry_results, elapsed = asyncio.run(run_batch(retry_key['key'], 24, 12, 'retry-load'))
    assert all(status == 200 for status, _, _ in retry_results), retry_results
    with Session(test_engine) as session:
        records = session.scalars(select(UsageRecord).where(UsageRecord.client_key_id == retry_key['id'])).all()
        roots = {record.root_request_id for record in records}
        failures = sum(record.status == 'error' for record in records)
        successes = sum(record.status == 'success' for record in records)
        assert len(roots) == 24 and successes == 24 and failures >= 1
        assert len(records) == successes + failures and max(record.attempt_number for record in records) == 2
        assert sum((record.estimated_cost or Decimal('0')) for record in records) == Decimal('0.02') * successes
    print(f'retry concurrency=12 requests=24 failures={failures} attempts={len(records)} elapsed_s={elapsed:.3f}')
    # PostgreSQL INTEGER is bounded even though Python integers are not.
    # Malformed provider usage must not roll back request finalization or be
    # treated as a reliable cost.
    with TestClient(app) as client:
        invalid_key = client.post('/admin/api-keys', headers=admin, json={'name':'invalid-usage','model_ids':[model['id']]}).json()
    async def malformed_usage(config, data):
        return {'model':'mock','data':[{'index':0,'embedding':[0.1,0.2]}], 'usage':{'prompt_tokens':2147483648}}
    providers.embedding = malformed_usage
    invalid_results, _ = asyncio.run(run_batch(invalid_key['key'], 1, 1))
    assert invalid_results[0][0] == 200
    with Session(test_engine) as session:
        record = session.get(UsageRecord, invalid_results[0][2])
        assert record.status == 'success' and record.input_tokens is None and record.estimated_cost is None
    print('PostgreSQL safely recorded unknown out-of-range provider usage')
    print(f'passed: {total} requests and 30 rate-limited attempts; no provider network calls')
finally:
    providers.embedding = original_embedding
    app.dependency_overrides.clear()
    test_engine.dispose()
    with admin_engine.connect() as connection:
        connection.execute(text(f'DROP DATABASE "{db_name}"'))
    admin_engine.dispose()
