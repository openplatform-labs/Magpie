"""Local-only mock used by the isolated multi-instance test deployment."""
import asyncio
import os
import socket
from app.main import app
from app import main, providers

# Provider mocks must never fall through to a Python network client. PostgreSQL
# connects through libpq; the server itself only accepts incoming sockets.
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex
def _guard_connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        raise AssertionError('Unexpected outbound Python network connection')
    return _connect(sock, address)
def _guard_connect_ex(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        raise AssertionError('Unexpected outbound Python network connection')
    return _connect_ex(sock, address)
socket.socket.connect = _guard_connect
socket.socket.connect_ex = _guard_connect_ex


async def mock_embedding(config, data):
    print('MOCK_EMBEDDING_EXECUTED', flush=True)
    if data.get('input') == 'fail-for-test':
        raise TimeoutError('mock provider timeout')
    if data.get('input') == 'hold-for-db-test':
        print('MOCK_EMBEDDING_WAITING', flush=True)
        await asyncio.sleep(5)
    elif data.get('input') == 'hold-for-crash-test':
        print('MOCK_CRASH_WAITING', flush=True)
        await asyncio.sleep(15)
    elif data.get('input') == 'hold-for-proxy-test':
        await asyncio.sleep(float(os.environ.get('MAGPIE_TEST_DELAY_SECONDS', '1')))
    else:
        await asyncio.sleep(0.01)
    return {'model':'mock', 'data':[{'index':0, 'embedding':[0.1, 0.2]}], 'usage':{'prompt_tokens':2}}


providers.embedding = mock_embedding


# Keep provider data out of the logs while identifying a response validation
# failure if the isolated concurrent test unexpectedly returns 502.
_validate_embedding_response = main.validate_embedding_response
def mock_validate_embedding_response(data, request, dimensions):
    try:
        return _validate_embedding_response(data, request, dimensions)
    except Exception as error:
        print('MOCK_EMBEDDING_VALIDATION_FAILED', type(error).__name__, flush=True)
        raise
main.validate_embedding_response = mock_validate_embedding_response


async def mock_completion(config, data):
    if data.get('stream'):
        async def chunks():
            try:
                yield {'choices':[{'index':0, 'delta':{'content':'mock partial'}, 'finish_reason':None}]}
                await asyncio.sleep(5)
                yield {'choices':[{'index':0, 'delta':{}, 'finish_reason':'stop'}]}
            finally:
                print('MOCK_STREAM_CLOSED', flush=True)
        return chunks()
    return {'choices':[{'index':0,'message':{'role':'assistant','content':'mock complete'},'finish_reason':'stop'}],
            'usage':{'prompt_tokens':2,'completion_tokens':1}}


providers.completion = mock_completion


async def mock_decision(config, data):
    await asyncio.sleep(0.01)
    return {'answers':[{'type':'predicate','name':q['name'],'probability':0.75} for q in data['questions']],
            'usage':{'input_tokens':2,'output_tokens':1}}


providers.decision = mock_decision
