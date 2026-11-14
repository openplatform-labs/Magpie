"""Keep unit and integration tests from contacting external services."""
import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def deny_dns(*args, **kwargs):
        attempts.append('DNS lookup')
        raise AssertionError('Unexpected network access in test')

    def guard_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            attempts.append('IP connection')
            raise AssertionError('Unexpected network access in test')
        return original_connect(sock, address)

    def guard_connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            attempts.append('IP connection')
            raise AssertionError('Unexpected network access in test')
        return original_connect_ex(sock, address)

    monkeypatch.setattr(socket, 'getaddrinfo', deny_dns)
    monkeypatch.setattr(socket.socket, 'connect', guard_connect)
    monkeypatch.setattr(socket.socket, 'connect_ex', guard_connect_ex)
    yield
    assert not attempts, f"Unexpected network access during test: {', '.join(attempts)}"
