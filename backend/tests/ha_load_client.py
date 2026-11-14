"""Exercise an isolated local HA stack; all provider responses are mocked."""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base = 'http://127.0.0.1:18082'
admin = 'test-token-012345678901234567890123456789'


def request(method, path, token, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {'Authorization':'Bearer '+token, 'Content-Type':'application/json'}
    try:
        with urlopen(Request(base + path, data=data, method=method, headers=headers), timeout=30) as response:
            content = response.read()
            return response.status, json.loads(content) if content else None
    except HTTPError as error:
        return error.code, None


status, provider = request('POST', '/admin/providers', admin, {'name':'mock','provider_type':'exaone','api_key':'fake'})
assert status == 201
status, model = request('POST', '/admin/models', admin, {'alias':'embed','provider_id':provider['id'],'upstream_model':'mock','operations':['embedding']})
assert status == 201
assert request('POST', '/admin/prices', admin, {'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'})[0] == 201
status, key = request('POST', '/admin/api-keys', admin, {'name':'ha','model_ids':[model['id']],'requests_per_minute':1000})
assert status == 201
assert request('PUT', f"/admin/api-keys/{key['id']}/budget", admin, {'currency':'USD','limit_amount':'100','reserve_per_request':'0.05'})[0] == 200


def send(_):
    return request('POST', '/v1/embeddings', key['key'], {'model':'embed','input':'sample'})[0]


with ThreadPoolExecutor(max_workers=16) as pool:
    statuses = list(pool.map(send, range(64)))
assert statuses == [200] * 64, statuses
status, budgets = request('GET', '/admin/budgets', admin)
assert status == 200 and Decimal(budgets[0]['spent_amount']) == Decimal('1.28') and Decimal(budgets[0]['held_amount']) == 0
status, records = request('GET', '/admin/usage/requests?limit=100', admin)
assert status == 200 and len(records) == 64 and all(r['status'] == 'success' for r in records)
assert len({r['request_id'] for r in records}) == 64
print('64 concurrent mocked requests passed through the HA proxy; PostgreSQL usage and budget totals agree')

# Hold accepted provider calls open so concurrent reservations compete for the
# same budget across both backend processes before any request can settle.
status, constrained = request('POST', '/admin/api-keys', admin, {'name':'budget-race','model_ids':[model['id']],'requests_per_minute':1000})
assert status == 201
assert request('PUT', f"/admin/api-keys/{constrained['id']}/budget", admin,
               {'currency':'USD','limit_amount':'0.10','reserve_per_request':'0.05'})[0] == 200
def budget_race(_):
    return request('POST', '/v1/embeddings', constrained['key'], {'model':'embed','input':'hold-for-db-test'})[0]

with ThreadPoolExecutor(max_workers=16) as pool:
    statuses = list(pool.map(budget_race, range(16)))
assert statuses.count(200) == 2 and statuses.count(429) == 14, statuses
status, budgets = request('GET', '/admin/budgets', admin)
budget = next(item for item in budgets if item['client_key_id'] == constrained['id'])
assert status == 200 and Decimal(budget['spent_amount']) == Decimal('0.04') and Decimal(budget['held_amount']) == 0
status, records = request('GET', '/admin/usage/requests?limit=100', admin)
budget_records = [row for row in records if row['client_key_id'] == constrained['id']]
assert status == 200 and len(budget_records) == 2 and all(row['status'] == 'success' for row in budget_records)
print('Concurrent budget reservations admitted exactly two of sixteen requests across the HA proxy')

# All requests arrive in one short burst; retry if the test is started just
# before a UTC minute boundary, rather than asserting a false global limit.
while time.time() % 60 > 50:
    time.sleep(0.2)
status, limited = request('POST', '/admin/api-keys', admin, {'name':'rate-race','model_ids':[model['id']],'requests_per_minute':3})
assert status == 201
def rate_race(_):
    return request('POST', '/v1/embeddings', limited['key'], {'model':'embed','input':'sample'})[0]

with ThreadPoolExecutor(max_workers=16) as pool:
    statuses = list(pool.map(rate_race, range(16)))
assert statuses.count(200) == 3 and statuses.count(429) == 13, statuses
status, records = request('GET', '/admin/usage/requests?limit=100', admin)
rate_records = [row for row in records if row['client_key_id'] == limited['id']]
assert status == 200 and len(rate_records) == 3 and all(row['status'] == 'success' for row in rate_records)
print('Concurrent requests respected the shared per-minute limit across the HA proxy')

# Exercise the other two operation types through the same proxy and shared
# PostgreSQL accounting, with independently registered keys and prices.
status, chat = request('POST', '/admin/models', admin, {'alias':'chat-ha','provider_id':provider['id'],
                        'upstream_model':'mock','operations':['generation']})
assert status == 201
status, jev = request('POST', '/admin/providers', admin, {'name':'mock-jev','provider_type':'typesafe','api_key':'fake'})
assert status == 201
status, judge = request('POST', '/admin/models', admin, {'alias':'judge-ha','provider_id':jev['id'],
                         'upstream_model':'jev-latest','operations':['decision']})
assert status == 201
for operation, registered in [('generation', chat), ('decision', judge)]:
    status, _ = request('POST', '/admin/prices', admin, {'model_id':registered['id'],'operation':operation,
        'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'})
    assert status == 201
    status, issued = request('POST', '/admin/api-keys', admin, {'name':operation+'-ha','model_ids':[registered['id']],
                              'requests_per_minute':1000})
    assert status == 201
    assert request('PUT', f"/admin/api-keys/{issued['id']}/budget", admin,
                   {'currency':'USD','limit_amount':'10','reserve_per_request':'0.05'})[0] == 200
    endpoint, body = (('/v1/chat/completions', {'model':'chat-ha','messages':[{'role':'user','content':'test'}]})
                      if operation == 'generation' else ('/v1/decisions', {'model':'judge-ha','input':'test',
                        'questions':[{'type':'predicate','name':'q','instructions':'yes?'}]}))
    def run_operation(_):
        return request('POST', endpoint, issued['key'], body)[0]
    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(run_operation, range(24)))
    assert statuses == [200] * 24, (operation, statuses)
    status, summaries = request('GET', f"/admin/usage?key_id={issued['id']}", admin)
    assert status == 200 and len(summaries) == 1
    summary = summaries[0]
    assert summary['operation'] == operation and summary['requests'] == 24
    assert summary['input_tokens'] == 48 and summary['output_tokens'] == 24
    assert Decimal(summary['estimated_cost']) == Decimal('0.72')
    status, budgets = request('GET', '/admin/budgets', admin)
    budget = next(item for item in budgets if item['client_key_id'] == issued['id'])
    assert status == 200 and Decimal(budget['spent_amount']) == Decimal('0.72') and Decimal(budget['held_amount']) == 0
    if operation == 'decision': assert summary['question_count'] == 24
    print(f'24 concurrent mocked {operation} requests passed; usage and budgets agree')

soak_seconds = int(os.environ.get('MAGPIE_HA_SOAK_SECONDS', '0'))
if not 0 <= soak_seconds <= 3600:
    raise ValueError('MAGPIE_HA_SOAK_SECONDS must be between 0 and 3600')
if soak_seconds:
    status, soak_key = request('POST', '/admin/api-keys', admin,
                               {'name':'ha-soak','model_ids':[model['id']],'requests_per_minute':100000})
    assert status == 201
    assert request('PUT', f"/admin/api-keys/{soak_key['id']}/budget", admin,
                   {'currency':'USD','limit_amount':'10000','reserve_per_request':'0.05'})[0] == 200
    deadline = time.monotonic() + soak_seconds
    def soak_worker(_):
        count = 0
        while time.monotonic() < deadline:
            status, _ = request('POST', '/v1/embeddings', soak_key['key'], {'model':'embed','input':'sample'})
            assert status == 200, status
            count += 1
            time.sleep(0.05)
        return count
    with ThreadPoolExecutor(max_workers=4) as pool:
        counts = list(pool.map(soak_worker, range(4)))
    total = sum(counts)
    assert min(counts) > 0
    status, budgets = request('GET', '/admin/budgets', admin)
    budget = next(item for item in budgets if item['client_key_id'] == soak_key['id'])
    assert status == 200 and Decimal(budget['spent_amount']) == Decimal('0.02') * total and Decimal(budget['held_amount']) == 0
    status, summaries = request('GET', f"/admin/usage?key_id={soak_key['id']}", admin)
    assert status == 200 and len(summaries) == 1
    summary = summaries[0]
    assert summary['status'] == 'success' and summary['requests'] == total
    assert summary['input_tokens'] == 2 * total and summary['cost_records'] == total
    assert Decimal(summary['estimated_cost']) == Decimal('0.02') * total
    print(f'HA soak workers=4 seconds={soak_seconds} requests={total}; usage and budgets agree')

# The bootstrap credential is retired when the first admin is created, so this
# test must run after the workload that uses it.
credentials = {'username':'ha-admin', 'password':'valid test password'}
status, user = request('POST', '/admin/users', admin, credentials)
assert status == 201
status, login = request('POST', '/admin/sessions', admin, credentials)
assert status == 201
session_token = login['token']
status, identity = request('POST', '/admin/oidc-identities', session_token,
                           {'user_id':user['id'], 'subject':'ha-subject'})
assert status == 201
status, start = request('POST', '/auth/oidc/start', session_token)
assert status == 200
callback = {'state':start['state'], 'browser_secret':start['browser_secret'], 'code':'mock'}
with ThreadPoolExecutor(max_workers=8) as pool:
    callbacks = list(pool.map(lambda _: request('POST', '/auth/oidc/callback', session_token, callback), range(8)))
statuses = [status for status, _ in callbacks]
assert statuses.count(200) == 1 and statuses.count(400) == 7, statuses
sso_token = next(body['token'] for status, body in callbacks if status == 200)
assert request('GET', '/admin/providers', sso_token)[0] == 200
assert request('DELETE', f"/admin/oidc-identities/{identity['id']}", session_token)[0] == 204
assert request('GET', '/admin/providers', sso_token)[0] == 401
print('Concurrent OIDC callback consumed once and linked session revoked after unlink')
