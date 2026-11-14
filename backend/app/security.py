import hashlib
import hmac
import os
import secrets
from cryptography.fernet import Fernet
from fastapi import HTTPException


def valid_bootstrap_token(value: str) -> bool:
    """Reject the public example credential as well as missing/short values."""
    return len(value) >= 32 and value != 'replace-with-a-random-token-at-least-32-characters'


def cipher() -> Fernet:
    try:
        return Fernet(os.environ["MAGPIE_ENCRYPTION_KEY"].encode())
    except (KeyError, ValueError):
        raise HTTPException(503, "Secret encryption is not configured") from None


def encrypt_secret(value: str) -> str:
    return cipher().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return cipher().decrypt(value.encode()).decode()


def new_client_key() -> str:
    return "mgp_" + secrets.token_urlsafe(32)


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    """Scrypt is memory-hard; the random salt and parameters are stored with the hash."""
    import base64
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt$16384$8$1$' + base64.urlsafe_b64encode(salt).decode() + '$' + base64.urlsafe_b64encode(derived).decode()


def password_verify(password: str, stored: str) -> bool:
    import base64
    try:
        algorithm, n, r, p, salt, expected = stored.split('$')
        if (algorithm, n, r, p) != ('scrypt', '16384', '8', '1'):
            return False
        derived = hashlib.scrypt(password.encode(), salt=base64.urlsafe_b64decode(salt), n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(derived, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False
