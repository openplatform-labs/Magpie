"""Check bootstrap retirement using only a disposable local Compose database."""
import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base = 'http://127.0.0.1:8000'
token = 'test-bootstrap-token-012345678901234567890123456789'
credentials = {'username':'test-admin','password':'local test password'}


def request(method, path, body=None, bearer=None):
    headers = {'Content-Type':'application/json'}
    if bearer is not None:
        headers['Authorization'] = 'Bearer ' + bearer
    req = Request(base + path, method=method, headers=headers,
                  data=None if body is None else json.dumps(body).encode())
    try:
        with urlopen(req, timeout=5) as response:
            data = response.read()
            return response.status, json.loads(data) if data else None
    except HTTPError as error:
        return error.code, None


mode = sys.argv[1]
if mode == 'absent':
    assert request('GET', '/health/ready')[0] == 503
    assert request('POST', '/admin/users', credentials, token)[0] == 503
elif mode == 'placeholder':
    placeholder = 'replace-with-a-random-token-at-least-32-characters'
    assert request('GET', '/health/ready')[0] == 503
    assert request('POST', '/admin/users', credentials, placeholder)[0] == 503
elif mode == 'create':
    assert request('GET', '/health/ready')[0] == 200
    assert request('POST', '/admin/users', credentials, token)[0] == 201
elif mode == 'retired':
    assert request('GET', '/health/ready')[0] == 200
    assert request('GET', '/admin/providers', bearer=token)[0] == 401
    status, session = request('POST', '/admin/sessions', credentials)
    assert status == 201
    assert request('GET', '/admin/providers', bearer=session['token'])[0] == 200
    print('Admin login works with the bootstrap token removed.')
else:
    raise ValueError('Unknown test mode')
