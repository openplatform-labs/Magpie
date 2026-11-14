"""Bound request bodies before JSON parsing, including chunked requests."""
import asyncio
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes=2 * 1024 * 1024, max_read_seconds=60):
        self.app = app
        self.max_bytes = max_bytes
        self.max_read_seconds = max_read_seconds

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        chunks = []
        size = 0
        oversized = False
        try:
            async with asyncio.timeout(self.max_read_seconds):
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect':
                        return
                    if message['type'] != 'http.request':
                        continue
                    chunk = message.get('body', b'')
                    size += len(chunk)
                    if size > self.max_bytes:
                        oversized = True
                        break
                    chunks.append(chunk)
                    if not message.get('more_body', False):
                        break
        except TimeoutError:
            payload = {'error': {'message': 'Request body timed out', 'type': 'invalid_request_error', 'code': 'request_timeout'}} if scope.get('path', '').startswith('/v1/') else {'detail': 'Request body timed out'}
            await JSONResponse(payload, status_code=408)(scope, receive, send)
            return
        if oversized:
            payload = {'error': {'message': 'Request body too large', 'type': 'invalid_request_error', 'code': 'request_too_large'}} if scope.get('path', '').startswith('/v1/') else {'detail': 'Request body too large'}
            await JSONResponse(payload, status_code=413)(scope, receive, send)
            return
        body = b''.join(chunks)
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return await receive()
        await self.app(scope, replay, send)
