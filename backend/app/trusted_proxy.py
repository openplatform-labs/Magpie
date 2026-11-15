"""Opt-in, request-bound management delegation from a separately authenticated BFF.

Not SSO, not inference authentication, and never an identity supplied by a browser
header. Existing local administrator authentication remains available by default.
"""
import hashlib
import hmac
import os
import uuid
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import TrustedProxyRequest


@lru_cache
def configuration():
    names = ['MAGPIE_PROXY_PUBLIC_KEY_FILE', 'MAGPIE_PROXY_ISSUER', 'MAGPIE_PROXY_AUDIENCE']
    values = [os.environ.get(name, '') for name in names]
    if not any(values):
        return None
    if not all(values):
        raise HTTPException(503, 'Trusted management proxy is not configured')
    try:
        path = Path(values[0])
        if path.stat().st_size > 16384:
            raise ValueError()
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError()
    except (OSError, ValueError, TypeError):
        raise HTTPException(503, 'Trusted management proxy is not configured') from None
    if any(len(value) > 256 for value in values[1:]):
        raise HTTPException(503, 'Trusted management proxy is not configured')
    return key, values[1], values[2]


def verified_claims(raw, method, target, body):
    config = configuration()
    if config is None:
        raise HTTPException(401, 'Invalid credentials')
    key, issuer, audience = config
    try:
        header = jwt.get_unverified_header(raw)
        if set(header) != {'alg', 'typ'} or header['alg'] != 'ES256' or header['typ'] != 'JWT':
            raise ValueError()
        claims = jwt.decode(raw, key, algorithms=['ES256'], issuer=issuer, audience=audience,
                            leeway=0, options={'require': ['iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti',
                                                          'scope', 'method', 'target', 'body_sha256', 'actor_kind']})
        if claims['aud'] != audience:
            raise ValueError()
        if any(type(claims[k]) is not int for k in ['iat', 'nbf', 'exp']):
            raise ValueError()
        if claims['nbf'] != claims['iat'] or not 0 < claims['exp'] - claims['iat'] <= 60:
            raise ValueError()
        if str(uuid.UUID(claims['sub'])) != claims['sub'] or str(uuid.UUID(claims['jti'])) != claims['jti']:
            raise ValueError()
        kind = claims['actor_kind']
        if kind not in ['human', 'agent']:
            raise ValueError()
        if kind == 'agent':
            if method != 'GET' or str(uuid.UUID(claims.get('agent_id', ''))) != claims['agent_id']:
                raise ValueError()
        elif 'agent_id' in claims:
            raise ValueError()
        scope = 'magpie:admin:read' if method == 'GET' else 'magpie:admin:write'
        if claims['scope'] != scope or claims['method'] != method or claims['target'] != target:
            raise ValueError()
        if method not in ['GET', 'POST', 'PUT', 'DELETE'] or not target.startswith('/admin/'):
            raise ValueError()
        # The proxy does not acquire authority to create local identities/sessions.
        path = target.split('?', 1)[0]
        if path.startswith(('/admin/users', '/admin/sessions')):
            raise ValueError()
        expected = hashlib.sha256(body).hexdigest()
        if not isinstance(claims['body_sha256'], str) or not hmac.compare_digest(claims['body_sha256'], expected):
            raise ValueError()
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(401, 'Invalid credentials') from None


async def authenticate(request, db, raw):
    target = request.scope.get('raw_path', request.url.path.encode()).decode('ascii')
    query = request.scope.get('query_string', b'')
    if query:
        target += '?' + query.decode('ascii')
    claims = verified_claims(raw, request.method, target, await request.body())
    actor = 'px:' + hashlib.sha256(('\0'.join([claims['iss'], claims['sub'], claims['actor_kind'], claims.get('agent_id', '')])).encode()).hexdigest()[:24]
    request.state.proxy_claims = claims
    if request.method != 'GET':
        # Reserve in a separate transaction BEFORE any external or local effect.
        # Handler rollback must not make a captured write token reusable. A lost
        # response is not permission to retry under a new request identity.
        try:
            with Session(db.get_bind()) as nonce_db:
                nonce_db.add(TrustedProxyRequest(id=claims['jti'], issuer=claims['iss'],
                    subject=claims['sub'], actor=actor, method=request.method,
                    target=target.split('?', 1)[0][:250], body_sha256=claims['body_sha256'],
                    expires_at=claims['exp']))
                nonce_db.commit()
        except IntegrityError:
            raise HTTPException(409, 'Delegated request already consumed; reconcile its outcome') from None
        db.info['proxy_request_id'] = claims['jti']
    db.info['admin_actor'] = actor
    request.state.admin_actor, request.state.admin_db = actor, db
    return actor
