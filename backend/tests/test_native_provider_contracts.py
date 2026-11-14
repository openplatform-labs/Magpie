"""Exercise LiteLLM's native adapters with mocked transport, never a provider API."""
import importlib
import json
import socket

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import providers
from app.database import Base
from app.main import app, db_session
from app.models import CatalogLock


@pytest.mark.parametrize(('provider','usage','unknown'), [
    ('anthropic', {'prompt_tokens':7,'completion_tokens':3,'total_tokens':10,'cache_read_input_tokens':7}, 'prompt_tokens'),
    ('gemini', {'prompt_tokens':7,'completion_tokens':3,'total_tokens':10,'prompt_tokens_details':{'tool_use_tokens':7}}, 'prompt_tokens'),
    ('gemini', {'prompt_tokens':7,'completion_tokens':3,'total_tokens':10,'completion_tokens_details':{'reasoning_tokens':3}}, 'completion_tokens'),
])
def test_native_usage_with_ambiguous_components_is_not_billable(provider, usage, unknown):
    result = {'usage':usage}
    providers.normalize_generation_usage(result, provider)
    assert unknown not in result['usage'] and 'total_tokens' not in result['usage']


@pytest.mark.parametrize(('metadata', 'expected'), [
    ({'promptTokenCount':0,'candidatesTokenCount':0,'totalTokenCount':0}, {'prompt_tokens':0,'completion_tokens':0,'total_tokens':0}),
    ({'promptTokenCount':7,'totalTokenCount':7}, {'prompt_tokens':7}),
    ({'promptTokenCount':7,'candidatesTokenCount':3,'thoughtsTokenCount':2,'totalTokenCount':12}, {'prompt_tokens':7}),
    ({'promptTokenCount':7,'candidatesTokenCount':3,'cachedContentTokenCount':4,'totalTokenCount':10}, {'completion_tokens':3}),
    ({'promptTokenCount':True,'candidatesTokenCount':3}, None),
    (None, None),
])
def test_gemini_native_stream_usage_provenance(metadata, expected):
    assert providers.gemini_reported_usage(metadata) == expected


def test_anthropic_native_stream_usage_provenance():
    import json
    stream = providers.AnthropicStreamProvenance(object())
    def event(value): stream._observe_line('data: ' + json.dumps(value))
    event({'type':'message_start','message':{'usage':{'input_tokens':7,'output_tokens':0}}})
    assert stream.magpie_reported_usage == {'prompt_tokens':7}
    event({'type':'message_delta','usage':{'output_tokens':0}})
    assert stream.magpie_reported_usage == {'prompt_tokens':7,'completion_tokens':0}
    event({'type':'message_delta','usage':{}})
    assert stream.magpie_reported_usage == {'prompt_tokens':7,'completion_tokens':0}
    event({'type':'message_delta','usage':{'input_tokens':9,'output_tokens':3}})
    assert stream.magpie_reported_usage == {'prompt_tokens':9,'completion_tokens':3}
    event({'type':'message_start','message':{'usage':{'input_tokens':7,'cache_read_input_tokens':3}}})
    event({'type':'message_delta','usage':{'input_tokens':7,'output_tokens':3}})
    assert stream.magpie_reported_usage == {'completion_tokens':3}
    event({'type':'message_delta','usage':{'output_tokens':True}})
    assert stream.magpie_reported_usage is None


@pytest.mark.parametrize('provider,model,operation,response_body', [
    ('anthropic', 'claude-sonnet-4-5', 'generation', {
        'id':'msg_mock', 'type':'message', 'role':'assistant', 'model':'claude-sonnet-4-5',
        'content':[{'type':'text','text':'mock answer'}], 'stop_reason':'end_turn',
        'usage':{'input_tokens':7,'output_tokens':3}}),
    ('anthropic', 'claude-sonnet-4-5', 'generation', {
        'id':'msg_tool', 'type':'message', 'role':'assistant', 'model':'claude-sonnet-4-5',
        'content':[{'type':'tool_use','id':'call_mock','name':'lookup','input':{'query':'sample'}}],
        'stop_reason':'tool_use', 'usage':{'input_tokens':7,'output_tokens':3}}),
    ('anthropic', 'claude-sonnet-4-5', 'generation', {
        'id':'msg_partial_usage', 'type':'message', 'role':'assistant', 'model':'claude-sonnet-4-5',
        'content':[{'type':'text','text':'mock answer'}], 'stop_reason':'end_turn', 'usage':{'input_tokens':7}}),
    ('anthropic', 'claude-sonnet-4-5', 'generation', {
        'id':'msg_cache_usage', 'type':'message', 'role':'assistant', 'model':'claude-sonnet-4-5',
        'content':[{'type':'text','text':'mock answer'}], 'stop_reason':'end_turn', 'usage':{'cache_read_input_tokens':7,'output_tokens':3}}),
    ('gemini', 'gemini-2.5-flash', 'generation', {
        'candidates':[{'content':{'role':'model','parts':[{'text':'mock answer'}]},'finishReason':'STOP','index':0}],
        'usageMetadata':{'promptTokenCount':7,'candidatesTokenCount':3,'totalTokenCount':10},
        'modelVersion':'gemini-2.5-flash'}),
    ('gemini', 'gemini-2.5-flash', 'generation', {
        'candidates':[{'content':{'role':'model','parts':[{'text':'mock answer'}]},'finishReason':'STOP','index':0}],
        'usageMetadata':{'promptTokenCount':7,'totalTokenCount':7}, 'modelVersion':'gemini-2.5-flash'}),
    ('gemini', 'gemini-2.5-flash', 'generation', {
        'candidates':[{'content':{'role':'model','parts':[{'text':'mock answer'}]},'finishReason':'STOP','index':0}],
        'usageMetadata':{'promptTokenCount':7,'thoughtsTokenCount':3,'totalTokenCount':10}, 'modelVersion':'gemini-2.5-flash'}),
    ('gemini', 'gemini-embedding-001', 'embedding', {'embeddings':[{'values':[0.1,0.2]}]}),
])
def test_native_provider_roundtrip(monkeypatch, provider, model, operation, response_body):
    # Fail closed if a path escapes the fake client.
    def no_socket(*args, **kwargs):
        raise AssertionError('unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_socket)
    monkeypatch.setattr(socket, 'getaddrinfo', no_socket)
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', 'a' * 40)
    monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(CatalogLock(id=1)); session.commit()
    def get_db():
        with Session(engine) as session:
            yield session
    app.dependency_overrides[db_session] = get_db
    captured = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            captured.append((url, kwargs))
            return httpx.Response(200, json=response_body, request=httpx.Request('POST', url))
    for module in ('litellm.llms.custom_httpx.llm_http_handler', 'litellm.llms.anthropic.chat.handler',
                   'litellm.llms.vertex_ai.gemini.vertex_and_google_ai_studio_gemini',
                   'litellm.llms.vertex_ai.gemini_embeddings.batch_embed_content_handler'):
        monkeypatch.setattr(importlib.import_module(module), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    try:
        with TestClient(app) as client:
            admin = {'Authorization':'Bearer ' + 'a'*40}
            conn = client.post('/admin/providers', headers=admin, json={'name':provider,'provider_type':provider,'api_key':'mock-secret'}).json()
            registered = client.post('/admin/models', headers=admin, json={'alias':'native','provider_id':conn['id'],'upstream_model':model,'operations':[operation]}).json()
            issued = client.post('/admin/api-keys', headers=admin, json={'name':'test','model_ids':[registered['id']]}).json()
            key = issued['key']
            assert client.post('/admin/prices', headers=admin, json={'model_id':registered['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'0' if operation == 'embedding' else '10000'}).status_code == 201
            assert client.put(f"/admin/api-keys/{issued['id']}/budget", headers=admin, json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
            path = '/v1/chat/completions' if operation == 'generation' else '/v1/embeddings'
            payload = {'model':'native','messages':[{'role':'user','content':'hello'}], 'max_tokens':32} if operation == 'generation' else {'model':'native','input':'hello'}
            tool_response = provider == 'anthropic' and response_body['content'][0]['type'] == 'tool_use'
            if tool_response:
                payload['tools'] = [{'type':'function','function':{'name':'lookup','parameters':{'type':'object','properties':{'query':{'type':'string'}}}}}]
            if operation == 'embedding':
                for input_value in ['files/private-file', 'https://generativelanguage.googleapis.com/v1beta/files/private-file',
                                    'gs://private-bucket/image.png', 'data:image/png;base64,YQ==',
                                    ['hello','files/private-file'], [1,2,3], [[1,2],[3,4]]]:
                    blocked = client.post(path, headers={'Authorization':'Bearer '+key}, json={'model':'native','input':input_value})
                    assert blocked.status_code == 400, blocked.text
                assert not captured
                assert client.get('/admin/usage/requests', headers=admin).json() == []
            result = client.post(path, headers={'Authorization':'Bearer '+key}, json=payload)
            assert result.status_code == 200, result.text
            assert result.json()['model'] == 'native'
            if operation == 'generation':
                if tool_response:
                    call = result.json()['choices'][0]['message']['tool_calls'][0]
                    assert call['id'] == 'call_mock' and call['function']['name'] == 'lookup'
                    assert json.loads(call['function']['arguments']) == {'query':'sample'}
                else:
                    assert result.json()['choices'][0]['message']['content'] == 'mock answer'
            else:
                assert result.json()['data'][0]['embedding'] == [0.1, 0.2]
                assert 'usage' not in result.json()
            assert len(captured) == 1
            url, call = captured[0]
            body = call.get('json') or json.loads(call['data'])
            if provider == 'anthropic':
                assert url == 'https://api.anthropic.com/v1/messages'
                assert body['model'] == model and body['messages'][0]['content'][0]['text'] == 'hello'
                assert body['max_tokens'] == 32
            elif operation == 'generation':
                assert 'generativelanguage.googleapis.com' in url and ':generateContent' in url and model in url
                assert body['contents'][0]['parts'][0]['text'] == 'hello'
            else:
                assert 'generativelanguage.googleapis.com' in url and ':batchEmbedContents' in url and model in url
                assert body['requests'][0]['content']['parts'][0]['text'] == 'hello'
            usage = client.get('/admin/usage/requests', headers=admin).json()[0]
            if operation == 'generation':
                expected_output = response_body['usage'].get('output_tokens') if provider == 'anthropic' else response_body['usageMetadata'].get('candidatesTokenCount')
                expected_input = None if provider == 'anthropic' and response_body['usage'].get('cache_read_input_tokens') else 7
                assert usage['input_tokens'] == expected_input and usage['output_tokens'] == expected_output
                if expected_output is None or expected_input is None:
                    assert usage['estimated_cost'] is None
                    assert len(client.get('/admin/budget-reservations', headers=admin).json()) == 1
            else:
                assert usage['input_tokens'] is None and usage['total_tokens'] is None
                assert usage['estimated_cost'] is None
                assert len(client.get('/admin/budget-reservations', headers=admin).json()) == 1
            assert 'mock-secret' not in str(usage)
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


@pytest.mark.parametrize('include_usage', [True, False])
@pytest.mark.parametrize('complete', [True, False, 'missing_message_stop', 'error_after_delta', 'error_after_finish', 'success_multiple_deltas'])
@pytest.mark.parametrize(('provider', 'model', 'wire'), [
    ('anthropic', 'claude-sonnet-4-5',
     'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":7,"output_tokens":0}}}\n\n'
     'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
     'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"mock answer"}}\n\n'
     'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
     'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}\n\n'
     'event: message_stop\ndata: {"type":"message_stop"}\n\n'),
    ('anthropic', 'claude-sonnet-4-5',
     'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":7,"output_tokens":0}}}\n\n'
     'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_mock","name":"lookup","input":{}}}\n\n'
     'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"q\\":1}"}}\n\n'
     'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
     'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":3}}\n\n'
     'event: message_stop\ndata: {"type":"message_stop"}\n\n'),
    ('anthropic', 'claude-sonnet-4-5',
     'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":7,"output_tokens":0}}}\n\n'
     'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
     'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"mock answer"}}\n\n'
     'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
     'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{}}\n\n'
     'event: message_stop\ndata: {"type":"message_stop"}\n\n'),
    ('anthropic', 'claude-sonnet-4-5',
     'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[]}}\n\n'
     'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
     'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"mock answer"}}\n\n'
     'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
     'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null}}\n\n'
     'event: message_stop\ndata: {"type":"message_stop"}\n\n'),
    ('gemini', 'gemini-2.5-flash',
     'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"mock answer"}]},"index":0}],"modelVersion":"gemini-2.5-flash"}\n\n'
     'data: {"candidates":[{"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3,"totalTokenCount":10},"modelVersion":"gemini-2.5-flash"}\n\n'),
    ('gemini', 'gemini-2.5-flash',
     'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"mock answer"}]},"index":0}],"modelVersion":"gemini-2.5-flash"}\n\n'
     'data: {"candidates":[{"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":7,"totalTokenCount":7},"modelVersion":"gemini-2.5-flash"}\n\n'),
    ('gemini', 'gemini-2.5-flash',
     'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"mock answer"}]},"index":0}],"modelVersion":"gemini-2.5-flash"}\n\n'
     'data: {"candidates":[{"finishReason":"STOP","index":0}],"modelVersion":"gemini-2.5-flash"}\n\n'),
    ('gemini', 'gemini-2.5-flash',
     'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"mock answer"}]},"index":0}],"modelVersion":"gemini-2.5-flash"}\n\n'
     'data: {"candidates":[{"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":0,"candidatesTokenCount":0,"totalTokenCount":0},"modelVersion":"gemini-2.5-flash"}\n\n'),
])
def test_native_provider_stream_roundtrip_without_network(monkeypatch, provider, model, wire, complete, include_usage):
    if complete in ('missing_message_stop', 'error_after_delta', 'success_multiple_deltas') and provider != 'anthropic':
        pytest.skip('Anthropic-specific terminal event')
    if complete == 'error_after_finish' and provider != 'gemini':
        pytest.skip('Gemini-specific stream error')
    tool_response = 'toolu_mock' in wire
    missing_output = '"output_tokens":3' not in wire if provider == 'anthropic' else '"candidatesTokenCount"' not in wire
    if complete is False:
        wire = wire.split('event: message_delta', 1)[0] if provider == 'anthropic' else wire.split('\n\n', 1)[0] + '\n\n'
    elif complete in ('missing_message_stop', 'error_after_delta'):
        wire = wire.split('event: message_stop', 1)[0]
        if complete == 'error_after_delta':
            wire += 'event: error\ndata: {"type":"error","error":{"type":"api_error","message":"mock error"}}\n\n'
    elif complete == 'error_after_finish':
        wire += 'data: {"error":{"code":500,"message":"mock error","status":"INTERNAL"}}\n\n'
    elif complete == 'success_multiple_deltas':
        wire = wire.replace('event: message_stop', 'event: message_delta\ndata: {"type":"message_delta","delta":{},"usage":{}}\n\nevent: message_stop')
    should_succeed = complete is True or complete == 'success_multiple_deltas'
    def no_socket(*args, **kwargs): raise AssertionError('unexpected network access')
    monkeypatch.setattr(socket.socket, 'connect', no_socket)
    monkeypatch.setattr(socket, 'getaddrinfo', no_socket)
    monkeypatch.setenv('MAGPIE_ADMIN_TOKEN', 'a' * 40)
    monkeypatch.setenv('MAGPIE_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(CatalogLock(id=1)); session.commit()
    def get_db():
        with Session(engine) as session: yield session
    app.dependency_overrides[db_session] = get_db
    captured = []
    class FakeHTTP:
        async def post(self, url, **kwargs):
            captured.append((url, kwargs))
            return httpx.Response(200, content=wire.encode(), headers={'content-type':'text/event-stream'}, request=httpx.Request('POST',url))
    monkeypatch.setattr(providers.litellm, 'module_level_aclient', FakeHTTP())
    for module in ('litellm.llms.custom_httpx.llm_http_handler', 'litellm.llms.anthropic.chat.handler',
                   'litellm.llms.vertex_ai.gemini.vertex_and_google_ai_studio_gemini'):
        monkeypatch.setattr(importlib.import_module(module), 'get_async_httpx_client', lambda **kwargs: FakeHTTP())
    try:
        with TestClient(app) as client:
            admin = {'Authorization':'Bearer ' + 'a'*40}
            conn = client.post('/admin/providers', headers=admin, json={'name':provider,'provider_type':provider,'api_key':'mock-secret'}).json()
            registered = client.post('/admin/models', headers=admin, json={'alias':'native-stream','provider_id':conn['id'],'upstream_model':model,'operations':['generation']}).json()
            issued = client.post('/admin/api-keys', headers=admin, json={'name':'test','model_ids':[registered['id']]}).json()
            key = issued['key']
            assert client.post('/admin/prices', headers=admin, json={'model_id':registered['id'],'currency':'USD','basis':'tokens','input_per_million':'10000','output_per_million':'10000'}).status_code == 201
            assert client.put(f"/admin/api-keys/{issued['id']}/budget", headers=admin, json={'currency':'USD','limit_amount':'1','reserve_per_request':'0.1'}).status_code == 200
            payload = {'model':'native-stream','messages':[{'role':'user','content':'hello'}], 'max_tokens':32, 'stream':True}
            if include_usage:
                payload['stream_options'] = {'include_usage':True}
            if tool_response:
                payload['tools'] = [{'type':'function','function':{'name':'lookup','parameters':{'type':'object','properties':{'q':{'type':'integer'}}}}}]
            response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+key}, json=payload)
            assert response.status_code == 200 and ('toolu_mock' if tool_response else 'mock answer') in response.text, response.text
            assert ('[DONE]' in response.text) is should_succeed and ('Provider stream failed' in response.text) is not should_succeed, response.text
            if complete is False:
                assert '"finish_reason": "stop"' not in response.text
            assert len(captured) == 1
            assert ('api.anthropic.com' if provider == 'anthropic' else 'generativelanguage.googleapis.com') in captured[0][0]
            usage = client.get('/admin/usage/requests', headers=admin).json()[0]
            assert usage['status'] == ('success' if should_succeed else 'error') and 'mock-secret' not in str(usage)
            if not should_succeed:
                assert usage['estimated_cost'] is None
                assert len(client.get('/admin/budget-reservations', headers=admin).json()) == 1
            elif missing_output:
                assert usage['output_tokens'] is None and usage['estimated_cost'] is None
                assert len(client.get('/admin/budget-reservations', headers=admin).json()) == 1
            elif provider == 'gemini' and '"candidatesTokenCount":0' in wire:
                assert usage['input_tokens'] == 0 and usage['output_tokens'] == 0
                assert float(usage['estimated_cost']) == 0
                assert not client.get('/admin/budget-reservations', headers=admin).json()
            else:
                assert usage['input_tokens'] == 7 and usage['output_tokens'] == 3
                assert float(usage['estimated_cost']) == 0.1
                assert not client.get('/admin/budget-reservations', headers=admin).json()
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_gemini_stream_fails_closed_if_litellm_interface_changes(monkeypatch):
    import asyncio
    closed = []
    class UnsupportedStream:
        async def aclose(self): closed.append(True)
    async def fake(**kwargs): return UnsupportedStream()
    monkeypatch.setattr(providers.litellm, 'acompletion', fake)
    async def run():
        with pytest.raises(ValueError):
            await providers.completion({'model':'gemini/mock','api_key':'fake'}, {'messages':[], 'stream':True})
    asyncio.run(run())
    assert closed == [True]


def test_litellm_uses_offline_tokenizer_without_download(monkeypatch):
    import litellm.utils as utils
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('unexpected tokenizer download')
    monkeypatch.setattr(utils.tokenizer_dispatch, 'from_pretrained', forbidden)
    assert utils.is_offline_mode()
    for model in ('together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo', 'cohere/command-r-plus'):
        assert utils.select_tokenizer(model)['type'] == 'openai_tokenizer'
    assert calls == []
