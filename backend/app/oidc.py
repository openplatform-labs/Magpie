"""OIDC authorization code + PKCE. Only pre-linked admin identities are accepted."""
import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .models import OIDCTransaction
from .security import decrypt_secret, encrypt_secret, hash_key


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    authorization_url: str
    token_url: str
    jwks_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None


def config() -> OIDCConfig:
    names = ['ISSUER', 'AUTHORIZATION_URL', 'TOKEN_URL', 'JWKS_URL', 'CLIENT_ID', 'REDIRECT_URI']
    values = {name: os.environ.get('MAGPIE_OIDC_' + name, '') for name in names}
    if not all(values.values()):
        raise HTTPException(503, 'OIDC is not configured')
    for name in ('ISSUER', 'AUTHORIZATION_URL', 'TOKEN_URL', 'JWKS_URL', 'REDIRECT_URI'):
        parsed = urlsplit(values[name])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise HTTPException(503, 'OIDC requires configured HTTPS URLs without userinfo, query, or fragment')
    if len(values['ISSUER']) > 500 or len(values['CLIENT_ID']) > 255:
        raise HTTPException(503, 'OIDC configuration is invalid')
    return OIDCConfig(values['ISSUER'], values['AUTHORIZATION_URL'], values['TOKEN_URL'], values['JWKS_URL'],
                      values['CLIENT_ID'], values['REDIRECT_URI'], os.environ.get('MAGPIE_OIDC_CLIENT_SECRET') or None)


def start(db: Session, settings: OIDCConfig):
    state, browser_secret, nonce, verifier = [secrets.token_urlsafe(32) for _ in range(4)]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    now = db.scalar(select(func.now()))
    db.add(OIDCTransaction(state_hash=hash_key(state), browser_hash=hash_key(browser_secret), nonce_hash=hash_key(nonce),
                           encrypted_verifier=encrypt_secret(verifier), expires_at=now + timedelta(minutes=10), used=False))
    db.commit()
    params = {'response_type': 'code', 'client_id': settings.client_id, 'redirect_uri': settings.redirect_uri,
              'scope': 'openid', 'state': state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
    return {'authorization_url': settings.authorization_url + '?' + urlencode(params), 'state': state, 'browser_secret': browser_secret}


def consume(db: Session, state: str, browser_secret: str):
    row = db.scalar(select(OIDCTransaction).where(OIDCTransaction.state_hash == hash_key(state),
        OIDCTransaction.used.is_(False), OIDCTransaction.expires_at > func.now()).with_for_update())
    if not row or not hmac.compare_digest(row.browser_hash, hash_key(browser_secret)):
        raise HTTPException(400, 'Invalid or expired SSO transaction')
    try:
        verifier = decrypt_secret(row.encrypted_verifier)
    except Exception:
        raise HTTPException(503, 'SSO transaction cannot be decrypted') from None
    nonce_hash = row.nonce_hash
    row.used = True
    db.commit()  # Reject replay even if token exchange later fails.
    return verifier, nonce_hash


async def read_json_bounded(response: httpx.Response, maximum: int):
    response.raise_for_status()
    chunks = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > maximum:
            raise ValueError('OIDC response too large')
        chunks.append(chunk)
    result = json.loads(b''.join(chunks))
    if not isinstance(result, dict):
        raise ValueError('Invalid OIDC response')
    return result


async def exchange(settings: OIDCConfig, code: str, verifier: str):
    data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': settings.redirect_uri,
            'client_id': settings.client_id, 'code_verifier': verifier}
    # OAuth client_secret_basic form-encodes each component before Basic auth.
    # Raw Basic credentials cannot represent a colon in the client identifier.
    auth = (quote_plus(settings.client_id, safe=''), quote_plus(settings.client_secret, safe='')) if settings.client_secret else None
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
        async with client.stream('POST', settings.token_url, data=data, auth=auth) as response:
            result = await read_json_bounded(response, 65536)
        token = result.get('id_token')
        if not isinstance(token, str) or len(token) > 32768:
            raise ValueError('Missing identity token')
        async with client.stream('GET', settings.jwks_url) as response:
            jwks = await read_json_bounded(response, 1048576)
        return token, jwks


def verify(settings: OIDCConfig, token: str, jwks: dict, expected_nonce_hash: str) -> str:
    header = jwt.get_unverified_header(token)
    if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
        raise ValueError('Unsupported identity token signature')
    keys = jwks.get('keys', []) if isinstance(jwks, dict) else []
    matches = [key for key in keys if isinstance(key, dict) and key.get('kid') == header['kid'] and key.get('kty') == 'RSA' and key.get('use', 'sig') == 'sig']
    if len(matches) != 1:
        raise ValueError('Identity signing key unavailable')
    key = jwt.PyJWK.from_dict(matches[0], algorithm='RS256')
    claims = jwt.decode(token, key, algorithms=['RS256'], issuer=settings.issuer, audience=settings.client_id,
                        options={'require': ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']}, leeway=30)
    if not isinstance(claims['nonce'], str) or not hmac.compare_digest(hash_key(claims['nonce']), expected_nonce_hash):
        raise ValueError('Identity nonce mismatch')
    audience = claims['aud']
    if (isinstance(audience, list) and len(audience) > 1 and claims.get('azp') != settings.client_id) or ('azp' in claims and claims['azp'] != settings.client_id):
        raise ValueError('Identity authorized party mismatch')
    subject = claims['sub']
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise ValueError('Identity subject invalid')
    return subject
