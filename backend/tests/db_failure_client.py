"""HTTP checks for the isolated DB interruption test; credentials here are test-only."""
import json
import sys
from decimal import Decimal
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base = 'http://127.0.0.1:18084'
admin = 'test-token-012345678901234567890123456789'
mode, state_file = sys.argv[1], Path(sys.argv[2])


def request(method, path, token='', body=None, timeout=15):
    data = None if body is None else json.dumps(body).encode()
    headers = {'Authorization':'Bearer '+token, 'Content-Type':'application/json'}
    try:
        with urlopen(Request(base + path, data=data, method=method, headers=headers), timeout=timeout) as response:
            content = response.read()
            return response.status, json.loads(content) if content else None
    except HTTPError as error:
        return error.code, None


if mode == 'setup':
    status, provider = request('POST', '/admin/providers', admin, {'name':'mock','provider_type':'exaone','api_key':'fake'})
    assert status == 201
    status, model = request('POST', '/admin/models', admin, {'alias':'embed','provider_id':provider['id'],'upstream_model':'mock','operations':['embedding']})
    assert status == 201
    assert request('POST', '/admin/prices', admin, {'model_id':model['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0'})[0] == 201
    status, key = request('POST', '/admin/api-keys', admin, {'name':'db-test','model_ids':[model['id']],'requests_per_minute':100})
    assert status == 201
    state_file.write_text(key['key'])
    state_file.chmod(0o600)
    assert request('POST','/v1/embeddings',key['key'],{'model':'embed','input':'sample'})[0] == 200
elif mode == 'inflight':
    key = state_file.read_text()
    assert request('POST','/v1/embeddings',key,{'model':'embed','input':'hold-for-db-test'})[0] == 200
elif mode == 'crash_inflight':
    key = state_file.read_text()
    assert request('POST','/v1/embeddings',key,{'model':'embed','input':'hold-for-crash-test'})[0] == 502
elif mode == 'down':
    assert request('GET', '/health/ready')[0] == 503
    key = state_file.read_text()
    statuses = [request('POST', '/v1/embeddings', key, {'model':'embed','input':'sample'})[0] for _ in range(4)]
    assert statuses == [503] * 4, statuses
    print('DB unavailable: readiness failed and requests were rejected')
elif mode == 'recovered':
    assert request('GET', '/health/ready')[0] == 200
    key = state_file.read_text()
    assert request('POST','/v1/embeddings',key,{'model':'embed','input':'sample'})[0] == 200
    status, records = request('GET','/admin/usage/requests',admin)
    assert status == 200 and len(records) == 3 and sorted(r['status'] for r in records) == ['started','success','success']
    request_id = next(row['request_id'] for row in records if row['status'] == 'started')
    assert request('POST',f'/admin/usage/requests/{request_id}/resolve',admin,{'note':'mock worker completed during DB outage'})[0] == 200
    status, records = request('GET','/admin/usage/requests?status=unknown',admin)
    assert status == 200 and len(records) == 1 and records[0]['resolution_note'] == 'mock worker completed during DB outage'
    status, audit = request('GET','/admin/audit',admin)
    assert status == 200 and any(row['action'] == 'usage.resolve_unknown' for row in audit)
    print('DB recovered: requests resumed; interrupted usage remains available for review')
elif mode == 'crash_recovered':
    key = state_file.read_text()
    assert request('POST','/v1/embeddings',key,{'model':'embed','input':'sample'})[0] == 200
    status, records = request('GET','/admin/usage/requests',admin)
    assert status == 200 and len(records) == 5 and sorted(r['status'] for r in records) == ['started','success','success','success','unknown']
    print('Worker crash: request was not replayed; its unknown outcome was retained')
elif mode == 'slow_proxy':
    key = state_file.read_text()
    assert request('POST','/v1/embeddings',key,{'model':'embed','input':'hold-for-proxy-test'},timeout=90)[0] == 200
    print('Delayed mock response passed through the proxy')
else:
    raise ValueError('unknown test mode')
