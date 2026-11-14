"""Exercise provider timeouts through an isolated local HA proxy and PostgreSQL."""
import json
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = 'http://127.0.0.1:18085'
ADMIN = 'test-token-012345678901234567890123456789'


def request(method, path, token=ADMIN, body=None, extra_headers=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {'Authorization':'Bearer '+token, 'Content-Type':'application/json'}
    headers.update(extra_headers or {})
    try:
        with urlopen(Request(BASE+path, data=data, method=method, headers=headers), timeout=10) as response:
            return response.status, response.read().decode()
    except HTTPError as error:
        return error.code, error.read().decode()


def request_json(method, path, token=ADMIN, body=None):
    status, content = request(method, path, token, body)
    return status, json.loads(content)


status, provider = request_json('POST', '/admin/providers', body={'name':'mock','provider_type':'exaone','api_key':'fake'})
assert status == 201
status, model = request_json('POST', '/admin/models', body={'alias':'mock','provider_id':provider['id'],'upstream_model':'mock','operations':['generation']})
assert status == 201
status, embed_model = request_json('POST', '/admin/models', body={'alias':'mock-embed','provider_id':provider['id'],'upstream_model':'mock','operations':['embedding']})
assert status == 201
request_headers = {'Idempotency-Key':'offline-proxy-test-0123456789'}
issuance_body = {'name':'one-request-across-workers','model_ids':[model['id']]}
def issue(_):
    # Deliberately discard the response body; a client might lose the secret.
    return request('POST','/admin/api-keys',body=issuance_body,extra_headers=request_headers)[0]
with ThreadPoolExecutor(max_workers=8) as pool:
    issuance_status = list(pool.map(issue, range(8)))
assert issuance_status.count(201) == 1 and issuance_status.count(409) == 7, issuance_status
status, keys = request_json('GET', '/admin/api-keys')
assert status == 200 and len([entry for entry in keys if entry['name'] == issuance_body['name']]) == 1
assert request('POST','/admin/api-keys',body=issuance_body,extra_headers=request_headers)[0] == 409
print('Concurrent and repeated key issuance through the HA proxy created exactly one test key.')
for operation in ('generation','embedding'):
    status, _ = request_json('POST','/admin/prices',body={'model_id':model['id'] if operation == 'generation' else embed_model['id'],'operation':operation,'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000' if operation == 'generation' else '0'})
    assert status == 201
status, key = request_json('POST','/admin/api-keys',body={'name':'stall-test','model_ids':[model['id'],embed_model['id']]})
assert status == 201

started = time.monotonic()
status, result = request_json('POST','/v1/embeddings',key['key'],{'model':'mock-embed','input':'hold-for-db-test'})
assert status == 504 and result['error']['code'] == 'provider_timeout'
assert 0.8 <= time.monotonic() - started < 8
status, body = request('POST','/v1/chat/completions',key['key'],{'model':'mock','messages':[{'role':'user','content':'mock'}],'stream':True})
assert status == 200 and 'mock partial' in body and 'Provider stream failed' in body and '[DONE]' not in body
status, response = request_json('POST','/v1/chat/completions',key['key'],{'model':'mock','messages':[{'role':'user','content':'mock'}]})
assert status == 200 and response['choices'][0]['message']['content'] == 'mock complete'
status, records = request_json('GET','/admin/usage/requests')
assert status == 200 and sorted(row['status'] for row in records) == ['error','error','success']
assert sum(Decimal(row['estimated_cost']) for row in records if row['estimated_cost'] is not None) == Decimal('0.03')
print('Mock provider stalls timed out through HA proxy; usage records retained and subsequent request succeeded.')
