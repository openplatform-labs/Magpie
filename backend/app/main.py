import asyncio
import base64
import binascii
import hmac
import logging
import math
import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal
from pathlib import Path
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from cryptography.fernet import InvalidToken
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.datastructures import MutableHeaders
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import case, delete, exists, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, selectinload
from .database import engine
from .request_limit import BodyLimitMiddleware
from .models import AdminSession, AdminUser, BootstrapLock, CatalogLock, AuditLog, BudgetReservation, CapabilityVerificationEvent, KeyBudget, OperationalPolicy, ClientKey, ClientKeyGrant, ModelCapability, ModelPrice, ModelRegistration, ProviderConnection, UsageRecord
from . import observability, providers, rate_limit
from .security import cipher, decrypt_secret, encrypt_secret, hash_key, new_client_key, password_hash, password_verify, valid_bootstrap_token

app = FastAPI(title="Magpie", version="0.2.0")
app.add_middleware(BodyLimitMiddleware)
DUMMY_PASSWORD_HASH = password_hash("unused-dummy-password")
logger = logging.getLogger(__name__)


def audit_admin_failure(request: Request, status: int):
    """Audit authenticated management failures without persisting request data.

    Unauthenticated attempts are deliberately excluded here to avoid allowing
    anonymous callers to generate unbounded audit writes. Login failures have
    a separate rate-limited audit path.
    """
    actor = getattr(request.state, "admin_actor", None)
    db = getattr(request.state, "admin_db", None)
    route = request.scope.get("route")
    if not actor or db is None or not request.url.path.startswith('/admin/') or route is None:
        return
    # Route templates are server-defined; never store a raw path or request input.
    target = f"{request.method} {route.path} {status}"[:100]
    try:
        db.rollback()
        observability.audit(db, "admin.request.failed", "admin_endpoint", target, actor=actor)
        db.commit()
    except Exception:
        db.rollback()
        logger.warning("Failed to persist admin failure audit")


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Validation errors can contain plaintext secrets in their input fields.
    audit_admin_failure(request, 422)
    if request.url.path.startswith("/v1/"):
        return JSONResponse(status_code=400, content={"error": {"message": "Invalid request", "type": "invalid_request_error", "code": "invalid_request"}})
    return JSONResponse(status_code=422, content={"detail": [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]})


@app.exception_handler(StarletteHTTPException)
async def http_error(request, exc):
    audit_admin_failure(request, exc.status_code)
    if request.url.path.startswith("/v1/"):
        categories = {400: ("invalid_request_error", "invalid_request"), 401: ("authentication_error", "invalid_api_key"),
                      403: ("permission_error", "model_access_denied"), 404: ("invalid_request_error", "not_found"),
                      429: ("rate_limit_error", "rate_limit_exceeded"), 502: ("provider_error", "provider_error"),
                      503: ("provider_error", "service_unavailable"), 504: ("provider_error", "provider_timeout")}
        kind, code = categories.get(exc.status_code, ("api_error", "api_error"))
        return JSONResponse(status_code=exc.status_code, content={"error": {"message": str(exc.detail), "type": kind, "code": code}}, headers=exc.headers)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)


@app.exception_handler(Exception)
async def unexpected_error(request, exc):
    audit_admin_failure(request, 500)
    if request.url.path.startswith('/v1/'):
        return JSONResponse(status_code=500, content={"error": {"message": "Internal server error", "type": "api_error", "code": "internal_error"}})
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    # Database exceptions can contain SQL parameters or connection details.
    audit_admin_failure(request, 503)
    if request.url.path.startswith('/v1/'):
        return JSONResponse(status_code=503, content={"error": {"message": "Database unavailable", "type": "api_error", "code": "database_unavailable"}})
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})


class SanitizedUnhandledErrors:
    """Prevent server error tracebacks from logging request or credential data."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        started = False
        async def tracked_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
            await send(message)
        try:
            await self.app(scope, receive, tracked_send)
        except Exception:
            logger.error('Unhandled request failure')
            if not started:
                response = await unexpected_error(Request(scope), None)
                await response(scope, receive, send)


app.add_middleware(SanitizedUnhandledErrors)


class SensitiveResponseNoStore:
    """Prevent caches from storing admin credentials and model responses."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith(('/admin/', '/auth/', '/v1/')):
            await self.app(scope, receive, send)
            return
        async def no_store_send(message):
            if message['type'] == 'http.response.start':
                headers = MutableHeaders(scope=message)
                current = headers.get('cache-control', '')
                directives = {part.strip().lower() for part in current.split(',')}
                if 'no-store' not in directives:
                    headers['cache-control'] = f'{current}, no-store' if current else 'no-store'
            await send(message)
        await self.app(scope, receive, no_store_send)


app.add_middleware(SensitiveResponseNoStore)


def db_session():
    with Session(engine()) as session:
        yield session


DB = Annotated[Session, Depends(db_session)]
async def admin_auth(request: Request, db: DB, authorization: str | None = Header(default=None)) -> str:
    raw = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
    if raw.startswith('mgd_'):
        if len(raw) > 4096:
            raise HTTPException(401, "Invalid credentials")
        from .trusted_proxy import authenticate
        return await authenticate(request, db, raw[4:])
    if len(raw) > 512:
        raise HTTPException(401, "Invalid credentials")
    session = db.scalar(select(AdminSession).join(AdminUser, AdminSession.user_id == AdminUser.id).where(
        AdminSession.token_hash == hash_key(raw), AdminSession.revoked.is_(False), AdminSession.oidc_identity_id.is_(None),
        AdminSession.expires_at > func.now(), AdminUser.active.is_(True)))
    if session:
        actor = f"admin:{session.user_id}"
        request.state.admin_actor, request.state.admin_db = actor, db
        return actor
    # The bootstrap token ceases to work once the first account exists.
    configured = os.environ.get("MAGPIE_ADMIN_TOKEN", "")
    if not db.scalar(select(AdminUser.id).limit(1)):
        if not valid_bootstrap_token(configured):
            raise HTTPException(503, "Admin authentication is not configured")
        if hmac.compare_digest(raw.encode(), configured.encode()):
            request.state.admin_actor, request.state.admin_db = "bootstrap", db
            return "bootstrap"
    raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"})


Admin = Annotated[str, Depends(admin_auth)]


@app.get('/admin/proxy-requests/{request_id}')
def delegated_request(request_id: str, request: Request, db: DB, _: Admin):
    from .models import TrustedProxyRequest
    claims = getattr(request.state, 'proxy_claims', None)
    row = db.get(TrustedProxyRequest, request_id)
    if not claims or not row or row.subject != claims['sub'] or row.issuer != claims['iss']:
        raise HTTPException(404, 'Delegated request not found')
    audits = db.scalars(select(AuditLog).where(AuditLog.proxy_request_id == request_id).order_by(AuditLog.id)).all()
    return {'request_id': row.id, 'state': 'consumed', 'method': row.method, 'target': row.target,
            'body_sha256': row.body_sha256,
            'audits': [{'id': entry.id, 'action': entry.action, 'target_type': entry.target_type,
                        'target_id': entry.target_id} for entry in audits],
            'outcome': 'audit_evidence' if audits else 'unknown'}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AdminCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256, repr=False)


class NewPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=12, max_length=256, repr=False)


def valid_provider_group(provider_type: str, model_group: str) -> bool:
    return not ((provider_type == 'typesafe' and model_group != 'decision') or
                (model_group == 'decision' and provider_type not in ('typesafe', 'openai')) or
                (provider_type in providers.CODING_PROVIDERS and model_group != 'general'))


class ProviderIn(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    provider_type: str = Field(min_length=1, max_length=50)
    model_group: Literal['general', 'decision', 'embedding'] | None = None

    @model_validator(mode="after")
    def known_provider(self):
        if self.provider_type not in providers.PROVIDERS:
            raise ValueError("Unsupported provider")
        if self.model_group is None:
            self.model_group = 'decision' if self.provider_type == 'typesafe' else 'general'
        if not valid_provider_group(self.provider_type, self.model_group):
            raise ValueError('The provider does not support this group')
        return self
    api_key: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)
    base_url: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def safe_base(self):
        if self.provider_type == "openai_compatible":
            self.base_url = providers.validate_custom_base(self.base_url)
        elif self.base_url is not None:
            raise ValueError("base_url is allowed only for custom providers")
        return self


class SecretIn(StrictModel):
    api_key: str = Field(min_length=1, max_length=4096, repr=False)


class ProviderGroupIn(StrictModel):
    model_group: Literal['general', 'decision', 'embedding']


class ProviderNameIn(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class ModelIn(StrictModel):
    alias: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    upstream_model: str = Field(min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_.:-]+(?:/[a-zA-Z0-9_.:-]+)*$")
    provider_id: int = Field(gt=0)
    operations: list[Literal["generation", "embedding", "decision"]] = Field(min_length=1, max_length=3)
    description: str | None = Field(default=None, max_length=1000)
    embedding_dimensions: int | None = Field(default=None, gt=0, le=1000000)
    embedding_space: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    supports_embedding_batch: bool | None = None
    embedding_max_batch_size: int | None = Field(default=None, gt=0, le=100000)
    max_input_tokens: int | None = Field(default=None, gt=0, le=10000000)
    supports_streaming: bool | None = None
    supports_tools: bool | None = None
    supports_reasoning: bool | None = None


class CapabilityVerificationIn(StrictModel):
    status: Literal['unverified', 'mock_verified', 'provider_verified', 'failed']
    note: str = Field(min_length=1, max_length=500)
    expected_version: int = Field(ge=1)


class KeyIn(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    model_ids: list[int] = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None
    requests_per_minute: int | None = Field(default=None, ge=1, le=100000)

    @model_validator(mode="after")
    def validate_expiry(self):
        if self.expires_at is not None and (self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None):
            raise ValueError("expires_at must include a timezone")
        return self


class KeyUpdate(KeyIn):
    pass


class RetentionIn(StrictModel):
    usage_days: int = Field(ge=1, le=36500)
    audit_days: int = Field(ge=1, le=36500)


class ResolveUsageIn(StrictModel):
    note: str = Field(min_length=1, max_length=500)


class OperationalPolicyIn(StrictModel):
    size_warning_bytes: int | None = Field(default=None, ge=1, le=9000000000000000)
    stale_after_minutes: int = Field(default=60, ge=1, le=525600)
    stale_count_warning: int = Field(default=1, ge=1, le=1000000000)


class PriceIn(StrictModel):
    model_id: int = Field(gt=0)
    operation: Literal['generation', 'embedding', 'decision'] | None = None
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    basis: Literal["tokens", "question"]
    input_per_million: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=8)
    output_per_million: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=8)
    per_question: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=8)

    @model_validator(mode="after")
    def validate_rates(self):
        if self.basis == "tokens" and (self.input_per_million is None or self.output_per_million is None or self.per_question is not None):
            raise ValueError("token pricing requires both token rates")
        if self.basis == "question" and (self.per_question is None or self.input_per_million is not None or self.output_per_million is not None):
            raise ValueError("question pricing requires only a per-question rate")
        return self


class ActiveIn(StrictModel):
    active: bool


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=100)
    messages: list[dict[str, Any]] = Field(min_length=1)
    stream: bool = False
    temperature: float | None = Field(default=None, strict=True, allow_inf_nan=False)
    top_p: float | None = Field(default=None, strict=True, allow_inf_nan=False)
    max_tokens: int | None = Field(default=None, gt=0)
    max_completion_tokens: int | None = Field(default=None, gt=0)
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    reasoning_effort: str | None = None
    stream_options: dict[str, Any] | None = None

    @model_validator(mode='after')
    def validate_messages(self):
        # Python's JSON decoder accepts NaN and Infinity even though JSON
        # does not. Flexible function schemas and stream options must not
        # carry those values through to a provider.
        pending = [self.messages, self.tools, self.tool_choice, self.stream_options]
        while pending:
            value = pending.pop()
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError('non-finite JSON number')
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        # Some LiteLLM provider adapters download remote media themselves.
        # Do not let untrusted clients turn the gateway into an HTTP proxy.
        allowed_message_keys = {'role', 'content', 'name', 'tool_call_id', 'tool_calls', 'function_call', 'refusal', 'reasoning_content'}
        if self.max_tokens is not None and self.max_completion_tokens is not None:
            raise ValueError('use either max_tokens or max_completion_tokens')
        # Function definitions are descriptions passed to the model. Provider
        # built-in tools (including remote MCP) can perform actions directly.
        for tool in self.tools or []:
            function = tool.get('function')
            if (set(tool) != {'type', 'function'} or tool.get('type') != 'function'
                    or not isinstance(function, dict) or set(function) - {'name', 'description', 'parameters', 'strict'}
                    or not isinstance(function.get('name'), str) or not function['name']):
                raise ValueError('only function tool definitions are supported')
        if isinstance(self.tool_choice, str) and self.tool_choice not in ('auto', 'none', 'required'):
            raise ValueError('unsupported tool choice')
        if isinstance(self.tool_choice, dict):
            function = self.tool_choice.get('function')
            if (set(self.tool_choice) != {'type', 'function'} or self.tool_choice.get('type') != 'function'
                    or not isinstance(function, dict) or set(function) != {'name'}
                    or not isinstance(function.get('name'), str) or not function['name']):
                raise ValueError('only function tool choices are supported')
        for message in self.messages:
            role = message.get('role')
            if set(message) - allowed_message_keys or not isinstance(role, str) or role not in {'system', 'developer', 'user', 'assistant', 'tool', 'function'}:
                raise ValueError('unsupported chat message')
            if 'reasoning_content' in message and not isinstance(message['reasoning_content'], (str, type(None))):
                raise ValueError('reasoning_content must be text')
            history_calls = message.get('tool_calls')
            if history_calls is not None:
                if not isinstance(history_calls, list):
                    raise ValueError('invalid tool call history')
                for call in history_calls:
                    if not isinstance(call, dict) or call.get('type') != 'function' or set(call) - {'id', 'type', 'function', 'index'}:
                        raise ValueError('only function tool call history is supported')
                    function = call.get('function')
                    if (not isinstance(call.get('id'), str) or not call['id']
                            or ('index' in call and (type(call['index']) is not int or call['index'] < 0))
                            or not isinstance(function, dict) or set(function) != {'name', 'arguments'}
                            or not isinstance(function.get('name'), str) or not function['name']
                            or not isinstance(function.get('arguments'), str)):
                        raise ValueError('only function tool call history is supported')
            function_call = message.get('function_call')
            if function_call is not None and (not isinstance(function_call, dict)
                    or set(function_call) != {'name', 'arguments'}
                    or not isinstance(function_call.get('name'), str) or not function_call['name']
                    or not isinstance(function_call.get('arguments'), str)):
                raise ValueError('invalid function call history')
            content = message.get('content')
            if content is None or isinstance(content, str):
                continue
            if not isinstance(content, list) or not content:
                raise ValueError('unsupported chat content')
            for part in content:
                if not isinstance(part, dict):
                    raise ValueError('unsupported chat content part')
                if part.get('type') == 'text' and set(part) == {'type', 'text'} and isinstance(part['text'], str):
                    continue
                if part.get('type') != 'image_url' or set(part) != {'type', 'image_url'}:
                    raise ValueError('only text and inline images are supported')
                image = part['image_url']
                if isinstance(image, dict):
                    if set(image) - {'url', 'detail'} or image.get('detail', 'auto') not in ('auto', 'low', 'high'):
                        raise ValueError('invalid image options')
                    image = image.get('url')
                if not isinstance(image, str):
                    raise ValueError('image must be an inline data URL')
                prefix, separator, encoded = image.partition(',')
                if not separator or prefix not in ('data:image/png;base64', 'data:image/jpeg;base64', 'data:image/webp;base64', 'data:image/gif;base64'):
                    raise ValueError('image must be an inline data URL')
                try:
                    if not base64.b64decode(encoded, validate=True):
                        raise ValueError('image must not be empty')
                except (ValueError, binascii.Error):
                    raise ValueError('invalid image encoding') from None
        return self


class EmbeddingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=100)
    input: str | list[str] | list[Annotated[int, Field(strict=True, ge=0)]] | list[list[Annotated[int, Field(strict=True, ge=0)]]]
    dimensions: int | None = Field(default=None, gt=0, le=1000000)
    encoding_format: Literal["float", "base64"] | None = None

    @model_validator(mode="after")
    def validate_input(self):
        if self.input == '' or (isinstance(self.input, list) and any(isinstance(item, str) and not item for item in self.input)):
            raise ValueError("embedding text must not be empty")
        if isinstance(self.input, list) and (not self.input or any(isinstance(item, list) and not item for item in self.input)):
            raise ValueError("embedding input must not be empty")
        return self

    def batch_size(self):
        if isinstance(self.input, str) or (self.input and isinstance(self.input[0], int)):
            return 1
        return len(self.input)

    def token_lengths(self):
        if not isinstance(self.input, list) or not self.input:
            return ()
        if isinstance(self.input[0], int):
            return (len(self.input),)
        if isinstance(self.input[0], list):
            return tuple(len(item) for item in self.input)
        return ()


class DecisionOption(StrictModel):
    value: str | bool
    description: str | None = None


class DecisionLevel(StrictModel):
    label: str = Field(min_length=1)
    description: str | None = None


class DecisionQuestion(StrictModel):
    type: Literal["predicate", "choice", "score", "box"]
    name: str = Field(min_length=1, max_length=100)
    instructions: str = Field(min_length=1, max_length=10000)
    choices: list[DecisionOption] | None = None
    levels: list[DecisionLevel] | None = None

    @model_validator(mode="after")
    def validate_shape(self):
        if self.type in ("predicate", "box") and (self.choices is not None or self.levels is not None):
            raise ValueError("predicate and box do not accept choices or levels")
        if self.type == "choice":
            if self.levels is not None or self.choices is None or not 2 <= len(self.choices) <= 255:
                raise ValueError("choice requires 2 to 255 choices")
            values = [str(c.value).lower() if isinstance(c.value, bool) else c.value for c in self.choices]
            if len(set(values)) != len(values):
                raise ValueError("choice values must be unique")
        if self.type == "score" and (self.choices is not None or self.levels is None or not 2 <= len(self.levels) <= 10):
            raise ValueError("score requires 2 to 10 levels")
        return self


class DecisionText(StrictModel):
    type: Literal["input_text"]
    text: str = Field(min_length=1, max_length=200000)


class DecisionImage(StrictModel):
    type: Literal["input_image"]
    image_url: str = Field(max_length=2 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_inline_image(self):
        prefix, separator, encoded = self.image_url.partition(',')
        if not separator or prefix not in ('data:image/png;base64', 'data:image/jpeg;base64'):
            raise ValueError("image must be an inline PNG or JPEG data URL")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("invalid base64 image") from None
        if not data or (prefix == 'data:image/png;base64' and not data.startswith(b'\x89PNG\r\n\x1a\n')) or (prefix == 'data:image/jpeg;base64' and not data.startswith(b'\xff\xd8\xff')):
            raise ValueError("image data does not match its media type")
        return self


class DecisionMessage(StrictModel):
    type: Literal["message"] = "message"
    role: Literal["user"] = "user"
    content: str | list[DecisionText | DecisionImage] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_content(self):
        if isinstance(self.content, str) and len(self.content) > 200000:
            raise ValueError("input text too long")
        if isinstance(self.content, list) and len(self.content) > 128:
            raise ValueError("too many content parts")
        return self


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=100)
    input: str | list[DecisionMessage] = Field(min_length=1)
    questions: list[DecisionQuestion] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def unique_names(self):
        if len({q.name for q in self.questions}) != len(self.questions):
            raise ValueError("question names must be unique")
        if isinstance(self.input, str) and len(self.input) > 200000:
            raise ValueError("input text too long")
        if isinstance(self.input, list) and len(self.input) > 128:
            raise ValueError("too many messages")
        return self

    def requires_images_opt_in(self):
        return any(q.type == 'box' for q in self.questions) or self.has_images()

    def has_images(self):
        return isinstance(self.input, list) and any(
            isinstance(part, DecisionImage) for message in self.input if isinstance(message.content, list) for part in message.content)


def commit(session: Session):
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "Name or alias already exists") from None


def flush(db: Session):
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Name or alias already exists") from None


def client_auth(db: DB, authorization: str | None = Header(default=None)) -> ClientKey:
    raw = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
    if not raw.startswith("mgp_") or len(raw) > 200:
        raise HTTPException(401, "Invalid API key", headers={"WWW-Authenticate": "Bearer"})
    key = db.scalar(select(ClientKey).where(ClientKey.key_hash == hash_key(raw), ClientKey.active.is_(True), or_(ClientKey.expires_at.is_(None), ClientKey.expires_at > func.now())))
    if not key:
        raise HTTPException(401, "Invalid API key", headers={"WWW-Authenticate": "Bearer"})
    # Never silently remove an existing spending limit. The operator must
    # replace legacy budget-bound keys after reviewing their retained ledger.
    if db.get(KeyBudget, key.id) is not None:
        raise HTTPException(403, "Legacy budget-bound key must be replaced")
    return key


Client = Annotated[ClientKey, Depends(client_auth)]


def model_info(row: ModelRegistration):
    return {"id": row.id, "alias": row.alias, "provider": row.provider.name,
            "provider_id": row.provider_id, "upstream_model": row.upstream_model,
            "active": row.active, "operations": [cap.operation for cap in row.capabilities],
            "verification_version": row.verification_version,
            "capabilities": [{"operation": cap.operation, "api_mode": cap.api_mode, "verification_status": cap.verification_status} for cap in row.capabilities],
            "description": row.description, "embedding_dimensions": row.embedding_dimensions, "embedding_space": row.embedding_space,
            "supports_embedding_batch": row.supports_embedding_batch, "embedding_max_batch_size": row.embedding_max_batch_size,
            "max_input_tokens": row.max_input_tokens, "supports_streaming": row.supports_streaming,
            "supports_tools": row.supports_tools, "supports_reasoning": row.supports_reasoning}


def embedding_limit_error(row: ModelRegistration, body: EmbeddingIn) -> str | None:
    if body.dimensions is not None and row.embedding_dimensions is not None and body.dimensions != row.embedding_dimensions:
        return 'Requested dimensions do not match the registered model dimensions'
    if row.provider.provider_type == 'gemini':
        inputs = [body.input] if isinstance(body.input, str) else body.input
        if any(not isinstance(item, str) for item in inputs):
            return 'Gemini embedding requires text input, not token arrays'
        if any(item.startswith(('files/', 'gs://', 'https://generativelanguage.googleapis.com/v1beta/files/'))
               or (item.startswith('data:') and ';base64,' in item) for item in inputs):
            return 'Gemini embedding file and media references are not supported'
    count = body.batch_size()
    if count > 1 and row.supports_embedding_batch is False:
        return "Model does not support embedding batches"
    if row.embedding_max_batch_size is not None and count > row.embedding_max_batch_size:
        return "Embedding batch exceeds the configured limit"
    if row.max_input_tokens is not None and any(length > row.max_input_tokens for length in body.token_lengths()):
        return "Embedding input exceeds the configured token limit"
    return None


def validate_generation_response(data: dict) -> None:
    choices = data.get('choices')
    if data.get('error') is not None or not isinstance(choices, list) or not choices:
        raise ValueError('Invalid generation response choices')
    indices = set()
    for choice in choices:
        if not isinstance(choice, dict):
            raise ValueError('Invalid generation response choice')
        index, message = choice.get('index'), choice.get('message')
        if type(index) is not int or index < 0 or index in indices:
            raise ValueError('Invalid generation response index')
        if not isinstance(message, dict) or message.get('role') != 'assistant':
            raise ValueError('Invalid generation response message')
        for field in ('content', 'refusal', 'reasoning_content'):
            if message.get(field) is not None and not isinstance(message[field], str):
                raise ValueError('Invalid generation response content')
        calls = message.get('tool_calls')
        if calls is not None:
            if not isinstance(calls, list) or any(
                not isinstance(call, dict) or call.get('type') != 'function'
                or not isinstance(call.get('id'), str) or not call['id']
                or not isinstance(call.get('function'), dict)
                or not isinstance(call['function'].get('name'), str) or not call['function']['name']
                or not isinstance(call['function'].get('arguments'), str)
                for call in calls
            ):
                raise ValueError('Invalid generation response tool calls')
        function = message.get('function_call')
        if function is not None and (not isinstance(function, dict) or not isinstance(function.get('name'), str)
                or not function['name'] or not isinstance(function.get('arguments'), str)):
            raise ValueError('Invalid generation response function call')
        reason = choice.get('finish_reason')
        if reason is not None and (not isinstance(reason, str) or not reason):
            raise ValueError('Invalid generation finish reason')
        if not (any(isinstance(message.get(field), str) for field in ('content', 'refusal', 'reasoning_content'))
                or calls or function or reason == 'content_filter'):
            raise ValueError('Empty generation response message')
        indices.add(index)


def validate_embedding_response(data: dict, body: EmbeddingIn, registered_dimensions: int | None) -> None:
    import math
    import struct
    items = data.get('data')
    expected_dimensions = body.dimensions or registered_dimensions
    if data.get('error') is not None or not isinstance(items, list) or len(items) != body.batch_size():
        raise ValueError('Invalid embedding response count')
    indices = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Invalid embedding item')
        index = item.get('index')
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= len(items) or index in indices:
            raise ValueError('Invalid embedding index')
        indices.add(index)
        vector = item.get('embedding')
        if isinstance(vector, str):
            try:
                raw = base64.b64decode(vector, validate=True)
            except (ValueError, binascii.Error):
                raise ValueError('Invalid embedding encoding') from None
            if not raw or len(raw) % 4:
                raise ValueError('Invalid embedding encoding')
            size = len(raw) // 4
            values = (v[0] for v in struct.iter_unpack('<f', raw))
        elif isinstance(vector, list) and vector:
            size = len(vector)
            values = iter(vector)
        else:
            raise ValueError('Invalid embedding vector')
        if expected_dimensions is None:
            expected_dimensions = size
        if size != expected_dimensions:
            raise ValueError('Embedding dimension mismatch')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values):
            raise ValueError('Invalid embedding value')
        # Some adapters ignore encoding_format. Preserve a consistent gateway
        # contract by converting the validated vector to the requested format.
        if body.encoding_format == 'base64' and isinstance(vector, list):
            try:
                raw = struct.pack(f'<{size}f', *vector)
            except (OverflowError, struct.error):
                raise ValueError('Embedding cannot be encoded as float32') from None
            item['embedding'] = base64.b64encode(raw).decode('ascii')
        elif body.encoding_format != 'base64' and isinstance(vector, str):
            item['embedding'] = [value[0] for value in struct.iter_unpack('<f', raw)]


def validate_decision_response(data: dict, body: DecisionIn) -> None:
    import math
    def number(value, low=None, high=None):
        return (not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
                and (low is None or value >= low) and (high is None or value <= high))
    def probability(value):
        return number(value, 0, 1)
    answers = data.get('answers')
    if data.get('error') is not None or not isinstance(answers, (list, tuple)) or len(answers) != len(body.questions):
        raise ValueError('Invalid decision answer count')
    for answer, question in zip(answers, body.questions, strict=True):
        if not isinstance(answer, dict) or answer.get('name') != question.name:
            raise ValueError('Decision answer does not match question')
        kind = answer.get('type')
        if kind == 'refusal':
            continue
        if kind != question.type:
            raise ValueError('Invalid decision answer type')
        if kind == 'predicate':
            if not probability(answer.get('probability')):
                raise ValueError('Invalid predicate probability')
        elif kind in ('choice', 'score'):
            options = question.choices if kind == 'choice' else question.levels
            entries = answer.get('probabilities')
            if not probability(answer.get('confidence')) or not isinstance(entries, (list, tuple)) or len(entries) != len(options):
                raise ValueError('Invalid decision probabilities')
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or not probability(entry.get('probability')):
                    raise ValueError('Invalid decision probability')
                value = entry.get('value')
                if kind == 'choice':
                    valid = any(type(value) is type(option.value) and value == option.value for option in options)
                    marker = (type(value), value) if isinstance(value, (bool, str)) else None
                else:
                    valid = type(value) is int and 0 <= value < len(options) and entry.get('label') == options[value].label
                    marker = value if type(value) is int else None
                if not valid or marker in seen:
                    raise ValueError('Invalid decision probability option')
                seen.add(marker)
            if kind == 'choice':
                choice = answer.get('choice')
                if not any(type(choice) is type(option.value) and choice == option.value for option in options):
                    raise ValueError('Invalid decision choice')
            elif not number(answer.get('score'), 0, len(options) - 1):
                raise ValueError('Invalid decision score')
        else:
            box = answer.get('box')
            if not isinstance(box, dict) or not all(number(box.get(key)) for key in ('top', 'bottom', 'left', 'right')):
                raise ValueError('Invalid decision box')
            if box['left'] > box['right'] or box['top'] > box['bottom']:
                raise ValueError('Invalid decision box coordinates')
            if answer.get('confidence') is not None and not probability(answer['confidence']):
                raise ValueError('Invalid decision confidence')


def generation_capability_error(row: ModelRegistration, body: ChatIn) -> str | None:
    if body.stream and row.supports_streaming is False:
        return "Model does not support streaming"
    tool_history = any(message.get('role') in ('tool', 'function') or message.get('tool_calls')
                       or message.get('function_call') is not None or message.get('tool_call_id') is not None
                       for message in body.messages)
    if (body.tools or tool_history or (body.tool_choice is not None and body.tool_choice != 'none')) and row.supports_tools is False:
        return "Model does not support tool calls"
    if body.reasoning_effort and row.supports_reasoning is False:
        return "Model does not support reasoning controls"
    return None


def decision_capability_error(row: ModelRegistration, body: DecisionIn, images_opt_in: bool) -> str | None:
    provider_type = row.provider.provider_type
    if any(question.type == 'box' for question in body.questions) and provider_type != 'typesafe':
        return 'Box decisions currently require a TypeSafe model'
    if provider_type == 'typesafe' and body.requires_images_opt_in() and not images_opt_in:
        return 'TypeSafe image and box decisions require explicit image opt-in'
    return None


def permitted_model(db: Session, key: ClientKey, alias: str, operation: str) -> ModelRegistration:
    row = db.scalar(select(ModelRegistration).join(ClientKeyGrant, ClientKeyGrant.model_id == ModelRegistration.id)
        .join(ProviderConnection).where(ClientKeyGrant.client_key_id == key.id, ModelRegistration.alias == alias,
            ModelRegistration.active.is_(True), ProviderConnection.active.is_(True))
        .options(selectinload(ModelRegistration.provider), selectinload(ModelRegistration.capabilities)))
    if not row or operation not in [cap.operation for cap in row.capabilities]:
        raise HTTPException(403, "Model or operation is not available for this API key")
    if not row.provider.encrypted_api_key:
        raise HTTPException(503, "Provider credentials are not configured")
    return row


def upstream_config(row: ModelRegistration):
    try:
        return providers.provider_arguments(row.provider.provider_type, row.upstream_model, decrypt_secret(row.provider.encrypted_api_key), row.provider.base_url)
    except Exception:
        raise HTTPException(503, "Provider credentials are unavailable") from None


@app.get("/health/live")
def live():
    return {"status": "ok"}


@app.get("/health/ready")
def ready():
    # This checks the encryption key's format, not whether it matches every
    # previously encrypted credential. Do not expose secret values in errors.
    cipher()
    try:
        with engine().connect() as connection:
            version = int(connection.execute(text("SHOW server_version_num")).scalar_one())
            current_revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            if version // 10000 != 19:
                raise HTTPException(503, "PostgreSQL 19 is required")
            config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
            config.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "migrations"))
            if current_revision != ScriptDirectory.from_config(config).get_current_head():
                raise HTTPException(503, "Database migration is required")
            admin_exists = connection.execute(text("SELECT EXISTS (SELECT 1 FROM admin_users LIMIT 1)")).scalar_one()
        from .trusted_proxy import configuration as proxy_configuration
        if not admin_exists and proxy_configuration() is None and not valid_bootstrap_token(os.environ.get('MAGPIE_ADMIN_TOKEN', '')):
            raise HTTPException(503, 'Admin authentication is not configured')
        return {"status": "ready", "postgres_major": 19}
    except (SQLAlchemyError, RuntimeError):
        raise HTTPException(503, "Database unavailable") from None


@app.get("/api/catalog")
def catalog():
    return {"providers": [{"id": k, "name": v["name"], "adapter": "openai-compatible" if v["prefix"] == "openai" and (v["base"] or k == "openai_compatible") else "decision" if k == "typesafe" else "native", "base_url": v['base']} for k, v in providers.PROVIDERS.items()],
            "operations": ["generation", "decision", "embedding"], "status": "development"}


@app.post("/admin/users", status_code=201)
def create_admin(body: AdminCredentials, db: DB, actor: Admin):
    # Serialize bootstrap creation and re-check after acquiring the lock.
    db.execute(select(BootstrapLock).where(BootstrapLock.id == 1).with_for_update()).first()
    if actor == "bootstrap" and db.scalar(select(AdminUser.id).limit(1)):
        raise HTTPException(403, "Bootstrap already completed")
    user = AdminUser(username=body.username, password_hash=password_hash(body.password), active=True)
    db.add(user)
    flush(db)
    observability.audit(db, "admin.create", "admin_user", user.id, actor=actor)
    commit(db)
    return {"id": user.id, "username": user.username}


@app.get("/admin/users")
def list_admins(db: DB, _: Admin):
    return [{"id": u.id, "username": u.username, "active": u.active}
            for u in db.scalars(select(AdminUser).order_by(AdminUser.id))]


@app.put("/admin/users/{user_id}/active")
def set_admin_active(user_id: int, body: ActiveIn, db: DB, actor: Admin):
    db.execute(select(BootstrapLock).where(BootstrapLock.id == 1).with_for_update()).first()
    user = db.scalar(select(AdminUser).where(AdminUser.id == user_id).with_for_update())
    if not user:
        raise HTTPException(404, "Administrator not found")
    if user.active and not body.active and db.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.active.is_(True))) <= 1:
        raise HTTPException(409, "At least one administrator must remain active")
    user.active = body.active
    if not body.active:
        db.execute(update(AdminSession).where(AdminSession.user_id == user_id).values(revoked=True))
    observability.audit(db, "admin.activate" if body.active else "admin.deactivate", "admin_user", user.id, actor=actor)
    commit(db)
    return {"id": user.id, "active": user.active}


@app.put("/admin/users/{user_id}/password")
def reset_admin_password(user_id: int, body: NewPassword, db: DB, actor: Admin):
    user = db.scalar(select(AdminUser).where(AdminUser.id == user_id).with_for_update())
    if not user:
        raise HTTPException(404, "Administrator not found")
    user.password_hash = password_hash(body.password)
    db.execute(update(AdminSession).where(AdminSession.user_id == user_id).values(revoked=True))
    observability.audit(db, "admin.password.reset", "admin_user", user.id, actor=actor)
    commit(db)
    return {"id": user.id, "sessions_revoked": True}


@app.post("/admin/sessions", status_code=201)
def login(body: AdminCredentials, request: Request, db: DB):
    rate_limit.login_attempt(db, body.username, request.client.host if request.client else "unknown")
    user = db.scalar(select(AdminUser).where(AdminUser.username == body.username))
    observed_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    password_valid = password_verify(body.password, observed_hash)
    if user and password_valid:
        # Scrypt runs outside the row lock. Re-read after taking it so a
        # concurrent password reset or deactivation cannot issue a stale session.
        user = db.scalar(select(AdminUser).where(AdminUser.id == user.id).with_for_update().execution_options(populate_existing=True))
    if not user or not user.active or not password_valid or user.password_hash != observed_hash:
        observability.audit(db, "admin.login.failed", "admin_user", user.id if user else "unknown", actor="anonymous")
        commit(db)
        raise HTTPException(401, "Invalid credentials")
    raw = "mga_" + secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=12)
    session = AdminSession(token_hash=hash_key(raw), user_id=user.id, expires_at=expires_at, revoked=False)
    db.add(session)
    observability.audit(db, "admin.login", "admin_user", user.id, actor=f"admin:{user.id}")
    commit(db)
    return JSONResponse({"token": raw, "expires_at": expires_at.isoformat()}, status_code=201, headers={"Cache-Control": "no-store"})


@app.delete("/admin/sessions/current", status_code=204)
def logout(db: DB, actor: Admin, authorization: str | None = Header(default=None)):
    if actor == "bootstrap":
        raise HTTPException(400, "Bootstrap token cannot be revoked here")
    raw = authorization.removeprefix("Bearer ") if authorization else ""
    session = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_key(raw)))
    if session:
        session.revoked = True
        observability.audit(db, "admin.logout", "admin_user", session.user_id, actor=actor)
        commit(db)


@app.get("/admin/providers")
def list_providers(db: DB, _: Admin):
    return [{"id": p.id, "name": p.name, "provider_type": p.provider_type, "model_group": p.model_group, "active": p.active, "configured": bool(p.encrypted_api_key), "base_url": p.base_url} for p in db.scalars(select(ProviderConnection).order_by(ProviderConnection.id))]


@app.get('/admin/provider-credential-health')
def provider_credential_health(db: DB, _: Admin):
    current_cipher = cipher()
    results = []
    for provider in db.scalars(select(ProviderConnection).order_by(ProviderConnection.id)):
        if not provider.encrypted_api_key:
            status = 'not_configured'
        else:
            try:
                decoded = current_cipher.decrypt(provider.encrypted_api_key.encode()).decode('utf-8')
                status = 'decryptable' if decoded else 'unreadable'
            except (InvalidToken, UnicodeDecodeError, ValueError, TypeError):
                status = 'unreadable'
        results.append({'provider_id':provider.id, 'name':provider.name, 'status':status})
    return {'providers':results, 'unreadable_count':sum(row['status'] == 'unreadable' for row in results)}


@app.post('/admin/providers/{provider_id}/discover')
async def discover_provider_models(provider_id: int, db: DB, actor: Admin):
    provider = db.get(ProviderConnection, provider_id)
    if not provider or not provider.active:
        raise HTTPException(404, 'Provider is not active')
    public_catalog = provider.provider_type in providers.PUBLIC_DISCOVERY_PROVIDERS
    if not provider.encrypted_api_key and not public_catalog:
        raise HTTPException(400, 'provider_key_missing')
    secret = None
    if not public_catalog:
        try:
            secret = decrypt_secret(provider.encrypted_api_key)
        except Exception:
            raise HTTPException(503, 'provider_key_unavailable') from None
    provider_type, base = provider.provider_type, provider.base_url
    db.rollback()  # Do not hold a DB transaction open during the external request.
    try:
        result = await providers.discover_models(provider_type, secret, base)
    except providers.DiscoveryError as exc:
        raise HTTPException(502, 'provider_' + exc.code) from None
    observability.audit(db, 'provider.discover', 'provider', provider_id, actor=actor)
    commit(db)
    return result


@app.post("/admin/providers", status_code=201)
def create_provider(body: ProviderIn, db: DB, _: Admin):
    p = ProviderConnection(name=body.name, provider_type=body.provider_type, model_group=body.model_group, base_url=body.base_url if body.provider_type == "openai_compatible" else providers.PROVIDERS[body.provider_type]["base"], encrypted_api_key=encrypt_secret(body.api_key) if body.api_key is not None else None, active=True)
    db.add(p)
    flush(db)
    observability.audit(db, "provider.create", "provider", p.id, actor=_)
    commit(db)
    return {"id": p.id, "name": p.name, "provider_type": p.provider_type, "model_group": p.model_group, "configured": bool(p.encrypted_api_key)}


@app.put('/admin/providers/{provider_id}/model-group')
def set_provider_model_group(provider_id: int, body: ProviderGroupIn, db: DB, actor: Admin):
    # Serialize with model creation and updates so a concurrent write cannot
    # leave a dedicated connection with an incompatible model.
    lock_catalog(db)
    p = db.get(ProviderConnection, provider_id)
    if not p:
        raise HTTPException(404, 'Provider not found')
    if not valid_provider_group(p.provider_type, body.model_group):
        raise HTTPException(422, 'The provider does not support this group')
    if p.model_group == body.model_group:
        return {'id': p.id, 'model_group': p.model_group}
    if body.model_group != 'general':
        incompatible = db.scalar(select(ModelCapability.id).join(ModelRegistration).where(
            ModelRegistration.provider_id == provider_id, ModelCapability.operation != body.model_group).limit(1))
        if incompatible:
            raise HTTPException(409, 'Move incompatible models to another connection first')
    p.model_group = body.model_group
    observability.audit(db, 'provider.group.change', 'provider', p.id, actor=actor)
    commit(db)
    return {'id': p.id, 'model_group': p.model_group}


@app.put('/admin/providers/{provider_id}/name')
def set_provider_name(provider_id: int, body: ProviderNameIn, db: DB, actor: Admin):
    provider = db.scalar(select(ProviderConnection).where(ProviderConnection.id == provider_id).with_for_update())
    if not provider:
        raise HTTPException(404, 'Provider not found')
    if provider.name == body.name:
        return {'id': provider.id, 'name': provider.name}
    provider.name = body.name
    observability.audit(db, 'provider.name.change', 'provider', provider.id, actor=actor)
    commit(db)
    return {'id': provider.id, 'name': provider.name}


def change_provider_key(provider_id: int, secret: str | None, db: Session, actor: str):
    # Serialize with catalog edits and lock models in a stable order before
    # invalidating evidence; an old verification must not survive a new key.
    lock_catalog(db)
    p = db.get(ProviderConnection, provider_id)
    if not p:
        raise HTTPException(404, "Provider not found")
    if secret is None and not p.encrypted_api_key:
        return False
    p.encrypted_api_key = encrypt_secret(secret) if secret is not None else None
    models = db.scalars(select(ModelRegistration).where(ModelRegistration.provider_id == provider_id)
        .order_by(ModelRegistration.id).with_for_update().options(selectinload(ModelRegistration.capabilities))).all()
    for model in models:
        model.verification_version += 1
        for cap in model.capabilities:
            if cap.verification_status != 'unverified':
                db.add(CapabilityVerificationEvent(model_id=model.id, operation=cap.operation,
                    previous_status=cap.verification_status, status='unverified',
                    note='Provider credential changed' if secret is not None else 'Provider credential removed', actor=actor, created_at=datetime.now(timezone.utc)))
                cap.verification_status = 'unverified'
    observability.audit(db, "provider.key.rotate" if secret is not None else "provider.key.remove", "provider", p.id, actor=actor)
    commit(db)
    return True


@app.put("/admin/providers/{provider_id}/key")
def rotate_provider_key(provider_id: int, body: SecretIn, db: DB, _: Admin):
    change_provider_key(provider_id, body.api_key, db, _)
    return {"id": provider_id, "configured": True}


@app.delete("/admin/providers/{provider_id}/key", status_code=204)
def remove_provider_key(provider_id: int, db: DB, actor: Admin):
    change_provider_key(provider_id, None, db, actor)


@app.get("/admin/models")
def list_models(db: DB, _: Admin):
    rows = db.scalars(select(ModelRegistration).options(selectinload(ModelRegistration.capabilities), selectinload(ModelRegistration.provider)).order_by(ModelRegistration.alias)).all()
    return [model_info(row) for row in rows]


def lock_catalog(db: Session):
    if not db.scalar(select(CatalogLock).where(CatalogLock.id == 1).with_for_update()):
        raise HTTPException(503, "Catalog lock is missing; run migrations")


def validate_model(db: Session, body: ModelIn) -> ProviderConnection:
    if any(part in (".", "..") for part in body.upstream_model.split("/")):
        raise HTTPException(422, "Invalid upstream model identifier")
    if any(value is not None for value in (body.embedding_dimensions, body.embedding_space, body.supports_embedding_batch, body.embedding_max_batch_size)) and "embedding" not in body.operations:
        raise HTTPException(422, "Embedding metadata requires embedding capability")
    if body.supports_embedding_batch is False and body.embedding_max_batch_size not in (None, 1):
        raise HTTPException(422, "A model without batching cannot have a batch limit greater than one")
    if len(set(body.operations)) != len(body.operations):
        raise HTTPException(422, "Operations must be unique")
    p = db.get(ProviderConnection, body.provider_id)
    if not p or not p.active:
        raise HTTPException(404, "Provider not found")
    if p.model_group in ('decision', 'embedding') and body.operations != [p.model_group]:
        raise HTTPException(422, 'Model operation must match the dedicated provider group')
    if p.provider_type == "typesafe" and body.operations != ["decision"]:
        raise HTTPException(422, "TypeSafe supports decision operations only")
    if p.provider_type in providers.CODING_PROVIDERS and body.operations != ["generation"]:
        raise HTTPException(422, "Coding plan connections support generation operations only")
    if "decision" in body.operations and p.provider_type not in ("typesafe", "openai"):
        raise HTTPException(422, "Decision operations require a supported decision provider")
    return p


@app.post("/admin/models", status_code=201)
def create_model(body: ModelIn, db: DB, _: Admin):
    lock_catalog(db)
    if len(body.operations) != 1:
        raise HTTPException(422, 'Choose one model operation')
    p = validate_model(db, body)
    row = ModelRegistration(alias=body.alias, upstream_model=body.upstream_model, provider=p, active=True,
        description=body.description, embedding_dimensions=body.embedding_dimensions, embedding_space=body.embedding_space, max_input_tokens=body.max_input_tokens,
        supports_embedding_batch=body.supports_embedding_batch, embedding_max_batch_size=body.embedding_max_batch_size,
        supports_streaming=body.supports_streaming, supports_tools=body.supports_tools, supports_reasoning=body.supports_reasoning,
        capabilities=[ModelCapability(operation=x, api_mode={"generation": "chat_completions", "embedding": "embeddings", "decision": "decisions"}[x]) for x in body.operations])
    db.add(row)
    flush(db)
    observability.audit(db, "model.create", "model", row.id, actor=_)
    commit(db)
    return model_info(row)


@app.put("/admin/models/{model_id}")
def update_model(model_id: int, body: ModelIn, db: DB, actor: Admin):
    lock_catalog(db)
    row = db.scalar(select(ModelRegistration).where(ModelRegistration.id == model_id).with_for_update())
    if not row:
        raise HTTPException(404, "Model not found")
    if len(body.operations) != 1 and (row.provider_id != body.provider_id or row.upstream_model != body.upstream_model or
                                      set(body.operations) != {cap.operation for cap in row.capabilities}):
        raise HTTPException(422, 'Choose one model operation')
    provider = validate_model(db, body)
    identity_changed = row.provider_id != body.provider_id or row.upstream_model != body.upstream_model
    if identity_changed:
        row.pricing_version += 1
    changed_common = row.max_input_tokens != body.max_input_tokens
    changed_embedding = any((row.embedding_dimensions != body.embedding_dimensions, row.embedding_space != body.embedding_space,
        row.supports_embedding_batch != body.supports_embedding_batch, row.embedding_max_batch_size != body.embedding_max_batch_size))
    changed_generation = any((row.supports_streaming != body.supports_streaming, row.supports_tools != body.supports_tools,
        row.supports_reasoning != body.supports_reasoning))
    if identity_changed or changed_common or changed_embedding or changed_generation or {cap.operation for cap in row.capabilities} != set(body.operations):
        row.verification_version += 1
    for cap in row.capabilities:
        reset = identity_changed or cap.operation not in body.operations or changed_common or (cap.operation == 'embedding' and changed_embedding) or (cap.operation == 'generation' and changed_generation)
        if reset and cap.verification_status != 'unverified':
            db.add(CapabilityVerificationEvent(model_id=row.id, operation=cap.operation, previous_status=cap.verification_status,
                status='unverified', note='Model configuration or capability changed', actor=actor, created_at=datetime.now(timezone.utc)))
            cap.verification_status = 'unverified'
    row.alias, row.upstream_model, row.provider = body.alias, body.upstream_model, provider
    row.description, row.embedding_dimensions, row.embedding_space, row.max_input_tokens = body.description, body.embedding_dimensions, body.embedding_space, body.max_input_tokens
    row.supports_embedding_batch, row.embedding_max_batch_size = body.supports_embedding_batch, body.embedding_max_batch_size
    row.supports_streaming, row.supports_tools, row.supports_reasoning = body.supports_streaming, body.supports_tools, body.supports_reasoning
    desired = set(body.operations)
    for cap in list(row.capabilities):
        if cap.operation not in desired:
            row.capabilities.remove(cap)
    current = {cap.operation for cap in row.capabilities}
    for operation in desired - current:
        row.capabilities.append(ModelCapability(operation=operation, api_mode={"generation": "chat_completions", "embedding": "embeddings", "decision": "decisions"}[operation]))
    observability.audit(db, "model.update", "model", row.id, actor=actor)
    commit(db)
    return model_info(row)


@app.put('/admin/models/{model_id}/capabilities/{operation}/verification')
def set_capability_verification(model_id: int, operation: Literal['generation', 'embedding', 'decision'], body: CapabilityVerificationIn, db: DB, actor: Admin):
    # Serialize with model edits so old evidence cannot be attached to a new deployment.
    model = db.scalar(select(ModelRegistration).where(ModelRegistration.id == model_id).with_for_update())
    if model is None:
        raise HTTPException(404, 'Model not found')
    if model.verification_version != body.expected_version:
        raise HTTPException(409, 'Model configuration changed; refresh before recording verification')
    capability = next((cap for cap in model.capabilities if cap.operation == operation), None)
    if capability is None:
        raise HTTPException(404, 'Capability not found')
    db.add(CapabilityVerificationEvent(model_id=model_id, operation=operation, previous_status=capability.verification_status,
        status=body.status, note=body.note, actor=actor, created_at=datetime.now(timezone.utc)))
    capability.verification_status = body.status
    observability.audit(db, 'capability.verification', 'model', model_id, actor=actor)
    commit(db)
    return {'model_id': model_id, 'operation': operation, 'status': body.status}


@app.get('/admin/models/{model_id}/verification-history')
def capability_verification_history(model_id: int, db: DB, _: Admin, limit: int = Query(default=100, ge=1, le=500)):
    if db.get(ModelRegistration, model_id) is None:
        raise HTTPException(404, 'Model not found')
    events = db.scalars(select(CapabilityVerificationEvent).where(CapabilityVerificationEvent.model_id == model_id)
        .order_by(CapabilityVerificationEvent.id.desc()).limit(limit))
    return [{'id': event.id, 'operation': event.operation, 'previous_status': event.previous_status,
             'status': event.status, 'note': event.note, 'actor': event.actor, 'created_at': event.created_at} for event in events]


@app.post("/admin/api-keys", status_code=201)
def create_key(body: KeyIn, db: DB, _: Admin,
               idempotency_key: Annotated[str | None, Header(alias='Idempotency-Key', min_length=16, max_length=128, pattern=r'^[a-zA-Z0-9_-]+$')] = None):
    request_hash = hash_key(idempotency_key) if idempotency_key is not None else None
    if request_hash and db.scalar(select(ClientKey.id).where(ClientKey.creation_request_hash == request_hash)):
        raise HTTPException(409, 'Key issuance was already processed; inspect the key list')
    ids = set(body.model_ids)
    available = set(db.scalars(select(ModelRegistration.id).where(ModelRegistration.id.in_(ids), ModelRegistration.active.is_(True))).all())
    if ids != available:
        raise HTTPException(400, "One or more models do not exist or are inactive")
    raw = new_client_key()
    key = ClientKey(name=body.name, key_hash=hash_key(raw), creation_request_hash=request_hash, key_prefix=raw[:12], active=True, expires_at=body.expires_at, requests_per_minute=body.requests_per_minute,
                    grants=[ClientKeyGrant(model_id=i) for i in ids])
    db.add(key)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        if request_hash and db.scalar(select(ClientKey.id).where(ClientKey.creation_request_hash == request_hash)):
            raise HTTPException(409, 'Key issuance was already processed; inspect the key list') from None
        raise HTTPException(409, 'Key issuance conflict') from None
    observability.audit(db, "api_key.create", "api_key", key.id, actor=_)
    commit(db)
    return {"id": key.id, "name": key.name, "key": raw, "prefix": key.key_prefix}


@app.get("/admin/api-keys")
def list_keys(db: DB, _: Admin):
    rows = db.execute(select(ClientKey, (ClientKey.expires_at <= func.now()).label('expired')).options(selectinload(ClientKey.grants)).order_by(ClientKey.id)).all()
    legacy_budget_ids = set(db.scalars(select(KeyBudget.client_key_id)).all())
    return [{"id": k.id, "name": k.name, "prefix": k.key_prefix, "active": k.active, "expired": bool(expired), "expires_at": k.expires_at, "requests_per_minute": k.requests_per_minute, "model_ids": [g.model_id for g in k.grants], "legacy_budget": k.id in legacy_budget_ids} for k, expired in rows]


@app.delete("/admin/api-keys/{key_id}", status_code=204)
def revoke_key(key_id: int, db: DB, _: Admin):
    key = db.get(ClientKey, key_id)
    if not key:
        raise HTTPException(404, "API key not found")
    key.active = False
    observability.audit(db, "api_key.revoke", "api_key", key.id, actor=_)
    commit(db)


@app.put("/admin/api-keys/{key_id}")
def update_key(key_id: int, body: KeyUpdate, db: DB, _: Admin):
    key = db.get(ClientKey, key_id)
    if not key:
        raise HTTPException(404, "API key not found")
    if not key.active:
        raise HTTPException(409, "Revoked API keys cannot be updated")
    ids = set(body.model_ids)
    available = set(db.scalars(select(ModelRegistration.id).where(ModelRegistration.id.in_(ids), ModelRegistration.active.is_(True))).all())
    if ids != available:
        raise HTTPException(400, "One or more models do not exist or are inactive")
    key.name = body.name
    key.expires_at = body.expires_at
    key.requests_per_minute = body.requests_per_minute
    current = {grant.model_id: grant for grant in key.grants}
    for model_id, grant in current.items():
        if model_id not in ids:
            db.delete(grant)
    for model_id in ids - set(current):
        db.add(ClientKeyGrant(client_key_id=key.id, model_id=model_id))
    observability.audit(db, "api_key.update", "api_key", key.id, actor=_)
    commit(db)
    return {"id": key.id, "name": key.name, "active": key.active, "model_ids": sorted(ids),
            "expires_at": key.expires_at, "requests_per_minute": key.requests_per_minute}


@app.put("/admin/models/{model_id}/active")
def set_model_active(model_id: int, body: ActiveIn, db: DB, _: Admin):
    row = db.get(ModelRegistration, model_id)
    if not row:
        raise HTTPException(404, "Model not found")
    row.active = body.active
    observability.audit(db, "model.activate" if body.active else "model.deactivate", "model", row.id, actor=_)
    commit(db)
    return {"id": row.id, "active": row.active}


@app.put("/admin/providers/{provider_id}/active")
def set_provider_active(provider_id: int, body: ActiveIn, db: DB, _: Admin):
    row = db.get(ProviderConnection, provider_id)
    if not row:
        raise HTTPException(404, "Provider not found")
    row.active = body.active
    observability.audit(db, "provider.activate" if body.active else "provider.deactivate", "provider", row.id, actor=_)
    commit(db)
    return {"id": row.id, "active": row.active}


@app.get("/v1/models")
def available_models(db: DB, key: Client):
    rows = db.scalars(select(ModelRegistration).join(ClientKeyGrant, ClientKeyGrant.model_id == ModelRegistration.id)
        .join(ProviderConnection).where(ClientKeyGrant.client_key_id == key.id, ModelRegistration.active.is_(True), ProviderConnection.active.is_(True),
                                        ProviderConnection.encrypted_api_key.is_not(None), ProviderConnection.encrypted_api_key != '')
        .options(selectinload(ModelRegistration.capabilities))).all()
    data = [{"id": row.alias, "object": "model", "owned_by": "magpie", "operations": [c.operation for c in row.capabilities]} for row in rows]
    return {"object": "list", "data": data}


@app.post("/admin/prices", status_code=201)
def create_price(body: PriceIn, db: DB, actor: Admin):
    model = db.scalar(select(ModelRegistration).where(ModelRegistration.id == body.model_id).with_for_update())
    if model is None:
        raise HTTPException(404, "Model not found")
    operations = {c.operation for c in model.capabilities}
    operation = body.operation
    if operation is None:
        if len(operations) == 1:
            operation = next(iter(operations))
        else:
            raise HTTPException(422, 'Select an operation for this model price')
    if operation not in operations:
        raise HTTPException(422, 'The model does not support this operation')
    if body.basis == 'question' and operation != 'decision':
        raise HTTPException(422, 'Per-question pricing requires a decision operation')
    price = ModelPrice(**body.model_dump(exclude={'operation'}), operation=operation, pricing_version=model.pricing_version, effective_from=db.scalar(select(func.now())))
    db.add(price)
    flush(db)
    observability.audit(db, "price.create", "model_price", price.id, actor=actor)
    commit(db)
    return {"id": price.id, "model_id": price.model_id, "operation": price.operation, "effective_from": price.effective_from,
            "basis": price.basis, "currency": price.currency, "pricing_version": price.pricing_version}


@app.get("/admin/prices")
def list_prices(db: DB, _: Admin, model_id: int | None = None):
    query = select(ModelPrice)
    if model_id is not None:
        query = query.where(ModelPrice.model_id == model_id)
    rows = db.scalars(query.order_by(ModelPrice.effective_from.desc(), ModelPrice.id.desc()).limit(500)).all()
    return [{"id": p.id, "model_id": p.model_id, "operation": p.operation, "effective_from": p.effective_from,
             "currency": p.currency, "basis": p.basis, "pricing_version": p.pricing_version, "input_per_million": str(p.input_per_million) if p.input_per_million is not None else None,
             "output_per_million": str(p.output_per_million) if p.output_per_million is not None else None, "per_question": str(p.per_question) if p.per_question is not None else None} for p in rows]


def usage_query_filters(query, start: datetime | None, end: datetime | None,
                        model_id: int | None, key_id: int | None, operation: str | None, status: str | None):
    for value in (start, end):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(422, "Timestamps must include a timezone")
    if start and end and start >= end:
        raise HTTPException(422, "start must precede end")
    if start: query = query.where(UsageRecord.started_at >= start)
    if end: query = query.where(UsageRecord.started_at < end)
    if model_id is not None: query = query.where(UsageRecord.model_id == model_id)
    if key_id is not None: query = query.where(UsageRecord.client_key_id == key_id)
    if operation: query = query.where(UsageRecord.operation == operation)
    if status: query = query.where(UsageRecord.status == status)
    return query


def before_usage_cursor(query, started_at: datetime | None, request_id: str | None):
    if (started_at is None) != (request_id is None):
        raise HTTPException(422, 'Both cursor fields are required')
    if started_at is not None:
        if started_at.tzinfo is None or started_at.utcoffset() is None:
            raise HTTPException(422, 'Cursor timestamp must include a timezone')
        query = query.where(or_(UsageRecord.started_at < started_at,
                               (UsageRecord.started_at == started_at) & (UsageRecord.request_id < request_id)))
    return query


@app.get("/admin/metrics")
def usage_metrics(db: DB, _: Admin, start: datetime | None = None, end: datetime | None = None,
                  model_id: int | None = None, key_id: int | None = None,
                  operation: Literal["generation", "embedding", "decision"] | None = None,
                  status: Literal["started", "success", "error", "interrupted", "unknown"] | None = None):
    query = select(func.count(UsageRecord.request_id), func.count(func.distinct(func.coalesce(UsageRecord.root_request_id, UsageRecord.request_id))),
        func.sum(case((UsageRecord.attempt_number > 1, 1), else_=0)),
        func.sum(case((UsageRecord.status == "success", 1), else_=0)),
        func.sum(case((UsageRecord.status == "error", 1), else_=0)),
        func.sum(case((UsageRecord.status == "interrupted", 1), else_=0)),
        func.sum(case((UsageRecord.status == "started", 1), else_=0)),
        func.sum(case((UsageRecord.status == "unknown", 1), else_=0)),
        func.avg(UsageRecord.duration_ms), func.max(UsageRecord.duration_ms))
    count, unique_requests, retry_attempts, success, errors, interrupted, started, unknown, avg_ms, max_ms = db.execute(
        usage_query_filters(query, start, end, model_id, key_id, operation, status)).one()
    return {"requests": count, "attempts": count, "unique_requests": unique_requests, "retry_attempts": retry_attempts or 0, "success": success or 0, "errors": errors or 0,
            "interrupted": interrupted or 0, "started": started or 0, "unknown": unknown or 0,
            "average_duration_ms": float(avg_ms) if avg_ms is not None else None,
            "max_duration_ms": max_ms}


@app.get("/admin/usage")
def usage_summary(db: DB, _: Admin, start: datetime | None = None, end: datetime | None = None,
                  model_id: int | None = None, key_id: int | None = None,
                  operation: Literal["generation", "embedding", "decision"] | None = None,
                  status: Literal["started", "success", "error", "interrupted", "unknown"] | None = None):
    query = select(UsageRecord.operation, UsageRecord.status, UsageRecord.model_id, UsageRecord.client_key_id, UsageRecord.currency, func.count(),
        func.sum(UsageRecord.input_tokens), func.sum(UsageRecord.output_tokens),
        func.count(UsageRecord.input_tokens), func.count(UsageRecord.output_tokens),
        func.sum(UsageRecord.question_count), func.sum(UsageRecord.estimated_cost), func.count(UsageRecord.estimated_cost))
    query = usage_query_filters(query, start, end, model_id, key_id, operation, status)
    rows = db.execute(query.group_by(UsageRecord.operation, UsageRecord.status, UsageRecord.model_id, UsageRecord.client_key_id, UsageRecord.currency)).all()
    return [{"operation": op, "status": row_status, "model_id": row_model_id, "client_key_id": client_key_id, "requests": count, "input_tokens": inp,
             "output_tokens": out, "input_token_records": inp_count, "output_token_records": out_count,
             "question_count": questions, "currency": currency, "estimated_cost": str(cost) if cost is not None else None, "cost_records": cost_count}
            for op, row_status, row_model_id, client_key_id, currency, count, inp, out, inp_count, out_count, questions, cost, cost_count in rows]


@app.get("/admin/usage/requests")
def usage_requests(db: DB, _: Admin, limit: int = Query(default=100, ge=1, le=500),
                   start: datetime | None = None, end: datetime | None = None,
                   model_id: int | None = None, key_id: int | None = None,
                   operation: Literal["generation", "embedding", "decision"] | None = None,
                   status: Literal["started", "success", "error", "interrupted", "unknown"] | None = None,
                   before_started_at: datetime | None = None,
                   before_request_id: str | None = Query(default=None, min_length=1, max_length=36),
                   root_request_id: str | None = Query(default=None, pattern=r"^[0-9a-fA-F-]{36}$")):
    query = usage_query_filters(select(UsageRecord), start, end, model_id, key_id, operation, status)
    query = before_usage_cursor(query, before_started_at, before_request_id)
    if root_request_id is not None:
        query = query.where(or_(UsageRecord.root_request_id == root_request_id,
                               (UsageRecord.root_request_id.is_(None)) & (UsageRecord.request_id == root_request_id)))
    rows = db.scalars(query.order_by(UsageRecord.started_at.desc(), UsageRecord.request_id.desc()).limit(limit)).all()
    return [{"request_id": r.request_id, "root_request_id": r.root_request_id or r.request_id, "attempt_number": r.attempt_number, "client_key_id": r.client_key_id, "model_id": r.model_id,
             "operation": r.operation, "requested_alias": r.requested_alias, "status": r.status, "started_at": r.started_at,
             "provider_id_snapshot": r.provider_id_snapshot, "provider_type_snapshot": r.provider_type_snapshot,
             "provider_name_snapshot": r.provider_name_snapshot, "upstream_model_snapshot": r.upstream_model_snapshot,
             "duration_ms": r.duration_ms, "input_tokens": r.input_tokens, "output_tokens": r.output_tokens,
             "total_tokens": r.total_tokens, "question_count": r.question_count, "price_id": r.price_id, "estimated_cost": str(r.estimated_cost) if r.estimated_cost is not None else None, "currency": r.currency,
             "resolved_at": r.resolved_at, "resolution_actor": r.resolution_actor, "resolution_note": r.resolution_note} for r in rows]


@app.post('/admin/usage/requests/{request_id}/resolve')
def resolve_usage(request_id: str, body: ResolveUsageIn, db: DB, actor: Admin):
    row = db.scalar(select(UsageRecord).where(UsageRecord.request_id == request_id).with_for_update())
    if row is None:
        raise HTTPException(404, 'Request not found')
    if row.status != 'started':
        raise HTTPException(409, 'Only started requests can be resolved')
    row.status = 'unknown'
    row.resolved_at = datetime.now(timezone.utc)
    row.resolution_actor = actor
    row.resolution_note = body.note
    observability.audit(db, 'usage.resolve_unknown', 'request', request_id, actor=actor)
    commit(db)
    return {'request_id': request_id, 'status': 'unknown'}


def retention_cutoffs(db: Session, body: RetentionIn):
    now = db.scalar(select(func.now()))
    return now - timedelta(days=body.usage_days), now - timedelta(days=body.audit_days)


def retention_conditions(usage_cutoff, audit_cutoff):
    # Preserve running/uncertain requests and every request tied to a financial ledger.
    has_reservation = exists(select(BudgetReservation.request_id).where(BudgetReservation.request_id == UsageRecord.request_id))
    return (UsageRecord.finished_at.is_not(None), UsageRecord.finished_at < usage_cutoff, ~has_reservation), (AuditLog.created_at < audit_cutoff,)


@app.post("/admin/retention/preview")
def retention_preview(body: RetentionIn, db: DB, _: Admin):
    usage_cutoff, audit_cutoff = retention_cutoffs(db, body)
    usage_where, audit_where = retention_conditions(usage_cutoff, audit_cutoff)
    return {"usage_records": db.scalar(select(func.count()).select_from(UsageRecord).where(*usage_where)),
            "audit_records": db.scalar(select(func.count()).select_from(AuditLog).where(*audit_where)),
            "usage_cutoff": usage_cutoff, "audit_cutoff": audit_cutoff}


@app.post("/admin/retention/apply")
def retention_apply(body: RetentionIn, db: DB, actor: Admin):
    usage_cutoff, audit_cutoff = retention_cutoffs(db, body)
    usage_where, audit_where = retention_conditions(usage_cutoff, audit_cutoff)
    usage_count = db.execute(delete(UsageRecord).where(*usage_where)).rowcount
    audit_count = db.execute(delete(AuditLog).where(*audit_where)).rowcount
    observability.audit(db, "retention.apply", "retention", f"usage:{usage_count};audit:{audit_count}", actor=actor)
    commit(db)
    return {"usage_records_deleted": usage_count, "audit_records_deleted": audit_count}


@app.get("/admin/audit")
def audit_logs(db: DB, _: Admin, limit: int = 100, before_id: int | None = Query(default=None, gt=0)):
    if not 1 <= limit <= 500:
        raise HTTPException(422, "limit must be between 1 and 500")
    query = select(AuditLog)
    if before_id is not None:
        query = query.where(AuditLog.id < before_id)
    rows = db.scalars(query.order_by(AuditLog.id.desc()).limit(limit)).all()
    return [{"id": r.id, "created_at": r.created_at, "actor": r.actor, "action": r.action,
             "target_type": r.target_type, "target_id": r.target_id} for r in rows]


@app.put('/admin/operational-policy')
def set_operational_policy(body: OperationalPolicyIn, db: DB, actor: Admin):
    policy = db.scalar(select(OperationalPolicy).where(OperationalPolicy.id == 1).with_for_update())
    if policy is None:
        # Migrations create the singleton. SQLite-only tests create metadata directly.
        if db.get_bind().dialect.name != 'sqlite':
            raise HTTPException(503, 'Operational policy is missing; run migrations')
        policy = OperationalPolicy(id=1)
        db.add(policy)
    policy.size_warning_bytes = body.size_warning_bytes
    policy.stale_after_minutes = body.stale_after_minutes
    policy.stale_count_warning = body.stale_count_warning
    observability.audit(db, 'operational.policy.update', 'operational_policy', 1, actor=actor)
    commit(db)
    return body.model_dump()


@app.get('/admin/operational-status')
def operational_status(db: DB, _: Admin):
    policy = db.get(OperationalPolicy, 1)
    if policy is None and db.get_bind().dialect.name != 'sqlite':
        raise HTTPException(503, 'Operational policy is missing; run migrations')
    age_minutes = policy.stale_after_minutes if policy else 60
    warning_count = policy.stale_count_warning if policy else 1
    threshold = policy.size_warning_bytes if policy else None
    now = db.scalar(select(func.now()))
    cutoff = now - timedelta(minutes=age_minutes)
    stale = db.scalar(select(func.count()).select_from(UsageRecord).where(UsageRecord.status == 'started', UsageRecord.started_at < cutoff))
    size = db.scalar(select(func.pg_database_size(func.current_database()))) if db.get_bind().dialect.name == 'postgresql' else None
    return {'database_size_bytes': size, 'size_warning_bytes': threshold,
            'size_warning': None if size is None or threshold is None else size >= threshold,
            'stale_after_minutes': age_minutes, 'stale_count_warning': warning_count,
            'stale_started_requests': stale,
            'stale_warning': stale >= warning_count, 'checked_at': now}


async def db_work(work):
    """Keep a session alive until its worker finishes, including on cancellation."""
    pending = asyncio.create_task(asyncio.to_thread(work))
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        try:
            await pending
        except Exception:
            pass
        raise


async def invoke(body, operation, db, key, fn, decision_images_enabled=False):
    key_id = key.id
    def select_model():
        row = permitted_model(db, key, body.model, operation)
        if operation == "generation":
            error = generation_capability_error(row, body)
        elif operation == "embedding":
            error = embedding_limit_error(row, body)
        else:
            error = decision_capability_error(row, body, decision_images_enabled)
        if error:
            raise HTTPException(400, error)
        config = upstream_config(row)
        uncertain_embedding_usage = operation == 'embedding' and row.provider.provider_type == 'gemini'
        embedding_dimensions = row.embedding_dimensions if operation == 'embedding' else None
        if operation == "decision" and row.provider.provider_type == "typesafe" and body.requires_images_opt_in():
            config['extra_headers'] = {'TypeSafe-Danger-Zone-Images': 'true'}
        snapshot = {'provider_id_snapshot': row.provider.id, 'provider_type_snapshot': row.provider.provider_type,
                    'provider_name_snapshot': row.provider.name, 'upstream_model_snapshot': row.upstream_model}
        return row.id, row.pricing_version, config, snapshot, uncertain_embedding_usage, embedding_dimensions
    model_id, pricing_version, config, model_snapshot, uncertain_embedding_usage, embedding_dimensions = await db_work(select_model)
    bind = db.get_bind()
    def record_attempt():
        rate_limit.consume(db, key)
        return observability.begin(db, key_id, model_id, operation,
            len(body.questions) if operation == "decision" else None, pricing_version, body.model,
            model_snapshot=model_snapshot)
    pending_record = asyncio.create_task(asyncio.to_thread(record_attempt))
    try:
        request_id, started = await asyncio.shield(pending_record)
    except asyncio.CancelledError:
        try:
            cancelled_id, cancelled_started = await pending_record
        except Exception:
            db.rollback()
        else:
            await observability.finish(bind, cancelled_id, cancelled_started, 'interrupted')
        raise
    except HTTPException:
        db.rollback()
        raise
    headers = {"X-Request-ID": request_id, "X-Attempt-ID": request_id}
    try:
        async with asyncio.timeout(providers.UPSTREAM_TIMEOUT_SECONDS):
            result = await fn(config, body.model_dump(exclude={"model"}, exclude_none=True))
    except asyncio.CancelledError:
        await observability.finish(bind, request_id, started, "interrupted")
        raise
    except Exception as exc:
        upstream_status = getattr(exc, "status_code", None)
        await observability.finish(bind, request_id, started, "error")
        if isinstance(exc, (TimeoutError, providers.litellm.Timeout)) or upstream_status in (408, 504):
            status, message = 504, "Provider request timed out"
        elif upstream_status in (400, 429, 503):
            status, message = upstream_status, "Provider rejected the request" if upstream_status == 400 else "Provider is unavailable"
        else:
            status, message = 502, "Provider request failed"
        raise HTTPException(status, message, headers=headers) from None
    if operation == "generation" and body.stream:
        return StreamingResponse(observability.tracked_stream(result, body.model, bind, request_id, started, model_snapshot['provider_type_snapshot']),
                                 media_type="text/event-stream", headers={"Cache-Control": "no-cache", **headers})
    try:
        data = providers.as_dict(result)
        if not isinstance(data, dict):
            raise ValueError("Invalid provider response")
        if operation == 'generation':
            validate_generation_response(data)
            providers.apply_generation_usage(data, result, model_snapshot['provider_type_snapshot'])
        if operation == 'embedding':
            validate_embedding_response(data, body, embedding_dimensions)
            providers.apply_embedding_usage(data, result)
        if operation == 'decision':
            validate_decision_response(data, body)
            providers.apply_decision_usage(data, result)
        if uncertain_embedding_usage and not isinstance(result, providers.EmbeddingProvenance):
            data.pop('usage', None)
        data["model"] = body.model
        response = JSONResponse(jsonable_encoder(data), headers=headers)
        await observability.finish(bind, request_id, started, "success", data.get("usage"))
        return response
    except Exception:
        await observability.finish(bind, request_id, started, "error")
        raise HTTPException(502, "Provider response failed", headers=headers) from None


class ModelTestIn(StrictModel):
    operation: Literal['generation', 'embedding', 'decision']


@app.post('/admin/models/{model_id}/test')
async def test_registered_model(model_id: int, body: ModelTestIn, db: DB, actor: Admin):
    """Execute one small, explicitly requested provider call without a client key."""
    operation = body.operation
    def prepare():
        row = db.scalar(select(ModelRegistration).where(ModelRegistration.id == model_id)
                        .options(selectinload(ModelRegistration.capabilities), selectinload(ModelRegistration.provider)))
        if not row or not row.active or not row.provider.active:
            raise HTTPException(404, 'Active model not found')
        if operation not in {cap.operation for cap in row.capabilities}:
            raise HTTPException(422, 'Model does not support this operation')
        if not row.provider.encrypted_api_key:
            raise HTTPException(400, 'provider_key_missing')
        try:
            config = upstream_config(row)
        except HTTPException:
            raise HTTPException(503, 'provider_config_unavailable') from None
        if operation == 'generation':
            request = ChatIn(model=row.alias, messages=[{'role':'user', 'content':'Reply with OK.'}], max_tokens=16)
        elif operation == 'embedding':
            request = EmbeddingIn(model=row.alias, input='Magpie connection test')
            if error := embedding_limit_error(row, request):
                raise HTTPException(400, error)
        else:
            request = DecisionIn(model=row.alias, input='The sky is blue.', questions=[{'type':'predicate','name':'test','instructions':'Is the statement about the sky?'}])
        snapshot = {'provider_id_snapshot':row.provider.id, 'provider_type_snapshot':row.provider.provider_type,
                    'provider_name_snapshot':row.provider.name, 'upstream_model_snapshot':row.upstream_model}
        dimensions = row.embedding_dimensions
        observability.audit(db, 'model.test', 'model', row.id, actor=actor)
        request_id, started = observability.begin(db, None, row.id, operation,
            1 if operation == 'decision' else None, row.pricing_version, row.alias, model_snapshot=snapshot)
        return request, config, dimensions, snapshot, request_id, started
    # A cancellation cannot abandon a DB worker that might already commit.
    pending = asyncio.create_task(asyncio.to_thread(prepare))
    try:
        request, config, dimensions, snapshot, request_id, started = await asyncio.shield(pending)
    except asyncio.CancelledError:
        try:
            _, _, _, _, request_id, started = await pending
        except Exception:
            pass
        else:
            await observability.finish(db.get_bind(), request_id, started, 'interrupted')
        raise
    bind = db.get_bind()
    try:
        fn = {'generation':providers.completion, 'embedding':providers.embedding, 'decision':providers.decision}[operation]
        async with asyncio.timeout(providers.UPSTREAM_TIMEOUT_SECONDS):
            result = await fn(config, request.model_dump(exclude={'model'}, exclude_none=True))
        data = providers.as_dict(result)
        if not isinstance(data, dict):
            raise ValueError('Invalid provider response')
        if operation == 'generation':
            validate_generation_response(data)
            providers.apply_generation_usage(data, result, snapshot['provider_type_snapshot'])
        elif operation == 'embedding':
            validate_embedding_response(data, request, dimensions)
            providers.apply_embedding_usage(data, result)
            if snapshot['provider_type_snapshot'] == 'gemini' and not isinstance(result, providers.EmbeddingProvenance):
                data.pop('usage', None)
        else:
            validate_decision_response(data, request)
            providers.apply_decision_usage(data, result)
    except asyncio.CancelledError:
        await observability.finish(bind, request_id, started, 'interrupted')
        raise
    except Exception as exc:
        await observability.finish(bind, request_id, started, 'error')
        upstream_status = getattr(exc, 'status_code', None)
        if isinstance(exc, (TimeoutError, providers.litellm.Timeout)) or upstream_status in (408, 504):
            raise HTTPException(504, 'provider_test_timeout', headers={'X-Request-ID':request_id}) from None
        code = ('provider_test_authentication' if upstream_status in (401, 403) else
                'provider_test_model_not_found' if upstream_status == 404 else
                'provider_test_rate_limited' if upstream_status == 429 else
                'provider_test_rejected' if upstream_status in (400, 422) else 'provider_test_failed')
        raise HTTPException(502, code, headers={'X-Request-ID':request_id}) from None
    # Once the provider response has been validated, cancellation during the
    # shielded success finalization must not overwrite the success as interrupted.
    await observability.finish(bind, request_id, started, 'success', data.get('usage'))
    return {'request_id':request_id, 'operation':operation, 'status':'success'}


@app.post("/v1/chat/completions")
async def chat(body: ChatIn, db: DB, key: Client):
    return await invoke(body, "generation", db, key, providers.completion)


@app.post("/v1/embeddings")
async def embeddings(body: EmbeddingIn, db: DB, key: Client):
    return await invoke(body, "embedding", db, key, providers.embedding)


@app.post("/v1/decisions")
async def decisions(body: DecisionIn, db: DB, key: Client, typesafe_images: Annotated[str | None, Header(alias="TypeSafe-Danger-Zone-Images")] = None):
    return await invoke(body, "decision", db, key, providers.decision, decision_images_enabled=typesafe_images is not None and typesafe_images.strip().lower() == 'true')
