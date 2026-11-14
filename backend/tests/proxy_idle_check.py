"""Check proxy client timeouts using only local, deliberately incomplete requests."""
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

use_tls = sys.argv[1] != '--http'
context = ssl.create_default_context(cafile=sys.argv[1]) if use_tls else None
port = 18443 if use_tls else 18082


def stalled(part):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with (context.wrap_socket(raw, server_hostname='localhost') if context else raw) as connection:
            connection.settimeout(25)
            if part == 'header':
                request = b'POST /v1/embeddings HTTP/1.1\r\nHost: localhost\r\n'
            else:
                request = b'POST /v1/embeddings HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{'
            start = time.monotonic()
            connection.sendall(request)
            response = connection.recv(1024)
            elapsed = time.monotonic() - start
            assert not response or response.startswith(b'HTTP/1.1 408'), (part, response[:80])
            assert 10 <= elapsed <= 24, (part, elapsed)
            return part, round(elapsed, 2)


with ThreadPoolExecutor(max_workers=2) as pool:
    results = list(pool.map(stalled, ['header', 'body']))
print(('TLS' if use_tls else 'HTTP') + ' proxy idle deadlines:', results)
