from datetime import datetime
from decimal import Decimal
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Numeric, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class ProviderConnection(Base):
    __tablename__ = "provider_connections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    provider_type: Mapped[str] = mapped_column(String(50))
    encrypted_api_key: Mapped[str | None] = mapped_column(String)
    base_url: Mapped[str | None] = mapped_column(String(500))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    models: Mapped[list["ModelRegistration"]] = relationship(back_populates="provider")


class ModelRegistration(Base):
    __tablename__ = "model_registrations"
    id: Mapped[int] = mapped_column(primary_key=True)
    alias: Mapped[str] = mapped_column(String(100), unique=True)
    upstream_model: Mapped[str] = mapped_column(String(200))
    pricing_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    verification_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    description: Mapped[str | None] = mapped_column(String(1000))
    embedding_dimensions: Mapped[int | None] = mapped_column(Integer)
    embedding_space: Mapped[str | None] = mapped_column(String(100))
    supports_embedding_batch: Mapped[bool | None] = mapped_column(Boolean)
    embedding_max_batch_size: Mapped[int | None] = mapped_column(Integer)
    max_input_tokens: Mapped[int | None] = mapped_column(Integer)
    supports_streaming: Mapped[bool | None] = mapped_column(Boolean)
    supports_tools: Mapped[bool | None] = mapped_column(Boolean)
    supports_reasoning: Mapped[bool | None] = mapped_column(Boolean)
    provider_id: Mapped[int] = mapped_column(ForeignKey("provider_connections.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    provider: Mapped[ProviderConnection] = relationship(back_populates="models")
    capabilities: Mapped[list["ModelCapability"]] = relationship(back_populates="model", cascade="all, delete-orphan")


class ModelCapability(Base):
    __tablename__ = "model_capabilities"
    __table_args__ = (UniqueConstraint("model_id", "operation", name="uq_model_operation"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey("model_registrations.id", ondelete="CASCADE"))
    operation: Mapped[str] = mapped_column(String(30))
    api_mode: Mapped[str] = mapped_column(String(50))
    verification_status: Mapped[str] = mapped_column(String(30), default='unverified', server_default='unverified')
    model: Mapped[ModelRegistration] = relationship(back_populates="capabilities")


class CapabilityVerificationEvent(Base):
    __tablename__ = 'capability_verification_events'
    id: Mapped[int] = mapped_column(primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey('model_registrations.id'))
    operation: Mapped[str] = mapped_column(String(30))
    previous_status: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))
    note: Mapped[str] = mapped_column(String(500))
    actor: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ModelCircuit(Base):
    __tablename__ = 'model_circuits'
    model_id: Mapped[int] = mapped_column(ForeignKey('model_registrations.id'), primary_key=True)
    operation: Mapped[str] = mapped_column(String(30), primary_key=True)
    config_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    open_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ClientKey(Base):
    __tablename__ = "client_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    creation_request_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    key_prefix: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requests_per_minute: Mapped[int | None] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    grants: Mapped[list["ClientKeyGrant"]] = relationship(cascade="all, delete-orphan")


class ClientKeyGrant(Base):
    __tablename__ = "client_key_grants"
    __table_args__ = (UniqueConstraint("client_key_id", "model_id", name="uq_client_key_model"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    client_key_id: Mapped[int] = mapped_column(ForeignKey("client_keys.id", ondelete="CASCADE"))
    model_id: Mapped[int] = mapped_column(ForeignKey("model_registrations.id", ondelete="CASCADE"))


class UsageRecord(Base):
    __tablename__ = "usage_records"
    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    root_request_id: Mapped[str | None] = mapped_column(String(36))
    attempt_number: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    client_key_id: Mapped[int] = mapped_column(ForeignKey("client_keys.id"))
    model_id: Mapped[int] = mapped_column(ForeignKey("model_registrations.id"))
    operation: Mapped[str] = mapped_column(String(30))
    requested_alias: Mapped[str | None] = mapped_column(String(100))
    provider_id_snapshot: Mapped[int | None] = mapped_column(Integer)
    provider_type_snapshot: Mapped[str | None] = mapped_column(String(50))
    provider_name_snapshot: Mapped[str | None] = mapped_column(String(100))
    upstream_model_snapshot: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20))
    started_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped["datetime | None"] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped["datetime | None"] = mapped_column(DateTime(timezone=True))
    resolution_actor: Mapped[str | None] = mapped_column(String(30))
    resolution_note: Mapped[str | None] = mapped_column(String(500))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    question_count: Mapped[int | None] = mapped_column(Integer)
    price_id: Mapped[int | None] = mapped_column(ForeignKey("model_prices.id"))
    estimated_cost: Mapped[Decimal | None] = mapped_column(Numeric(24, 10))
    currency: Mapped[str | None] = mapped_column(String(3))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped["datetime"] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(30))
    action: Mapped[str] = mapped_column(String(50))
    target_type: Mapped[str] = mapped_column(String(30))
    target_id: Mapped[str] = mapped_column(String(100))


class RateLimitCounter(Base):
    __tablename__ = "rate_limit_counters"
    client_key_id: Mapped[int] = mapped_column(ForeignKey("client_keys.id", ondelete="CASCADE"), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)


class AdminUser(Base):
    __tablename__ = 'admin_users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class AdminSession(Base):
    __tablename__ = 'admin_sessions'
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('admin_users.id', ondelete='CASCADE'))
    oidc_identity_id: Mapped[int | None] = mapped_column(ForeignKey('oidc_identities.id', ondelete='SET NULL'))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class BootstrapLock(Base):
    __tablename__ = 'bootstrap_lock'
    id: Mapped[int] = mapped_column(primary_key=True)


class OperationalPolicy(Base):
    __tablename__ = 'operational_policy'
    id: Mapped[int] = mapped_column(primary_key=True)
    size_warning_bytes: Mapped[int | None] = mapped_column(BigInteger)
    stale_after_minutes: Mapped[int] = mapped_column(Integer, default=60, server_default='60')
    stale_count_warning: Mapped[int] = mapped_column(Integer, default=1, server_default='1')


class LoginRateCounter(Base):
    __tablename__ = 'login_rate_counters'
    scope_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)


class ModelPrice(Base):
    __tablename__ = 'model_prices'
    pricing_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    id: Mapped[int] = mapped_column(primary_key=True)
    model_id: Mapped[int] = mapped_column(ForeignKey('model_registrations.id'))
    operation: Mapped[str | None] = mapped_column(String(30))
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    currency: Mapped[str] = mapped_column(String(3))
    basis: Mapped[str] = mapped_column(String(20))
    input_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    output_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    per_question: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))


class KeyBudget(Base):
    __tablename__ = 'key_budgets'
    client_key_id: Mapped[int] = mapped_column(ForeignKey('client_keys.id'), primary_key=True)
    currency: Mapped[str] = mapped_column(String(3))
    limit_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10))
    reserve_per_request: Mapped[Decimal] = mapped_column(Numeric(24, 10))
    spent_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10), default=Decimal('0'))
    held_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10), default=Decimal('0'))


class BudgetReservation(Base):
    __tablename__ = 'budget_reservations'
    request_id: Mapped[str] = mapped_column(ForeignKey('usage_records.request_id'), primary_key=True)
    client_key_id: Mapped[int] = mapped_column(ForeignKey('key_budgets.client_key_id'))
    reserved_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10))
    settled_amount: Mapped[Decimal | None] = mapped_column(Numeric(24, 10))
    status: Mapped[str] = mapped_column(String(20))
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reconciliation_note: Mapped[str | None] = mapped_column(String(500))
    reconciliation_actor: Mapped[str | None] = mapped_column(String(30))
    reconciliation_forced: Mapped[bool | None] = mapped_column(Boolean)


class BudgetAdjustment(Base):
    __tablename__ = 'budget_adjustments'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey('budget_reservations.request_id'))
    previous_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10))
    revised_amount: Mapped[Decimal] = mapped_column(Numeric(24, 10))
    note: Mapped[str] = mapped_column(String(500))
    actor: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OIDCIdentity(Base):
    __tablename__ = 'oidc_identities'
    __table_args__ = (UniqueConstraint('issuer', 'subject', name='uq_oidc_issuer_subject'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    issuer: Mapped[str] = mapped_column(String(500))
    subject: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[int] = mapped_column(ForeignKey('admin_users.id'))


class OIDCTransaction(Base):
    __tablename__ = 'oidc_transactions'
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_hash: Mapped[str] = mapped_column(String(64))
    nonce_hash: Mapped[str] = mapped_column(String(64))
    encrypted_verifier: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class CatalogLock(Base):
    __tablename__ = 'catalog_lock'
    id: Mapped[int] = mapped_column(primary_key=True)


class ModelRoute(Base):
    __tablename__ = 'model_routes'
    id: Mapped[int] = mapped_column(primary_key=True)
    alias: Mapped[str] = mapped_column(String(100), unique=True)
    operation: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    retry_on_failure: Mapped[bool] = mapped_column(Boolean, default=False, server_default='false')
    targets: Mapped[list['RouteTarget']] = relationship(cascade='all, delete-orphan')


class RouteTarget(Base):
    __tablename__ = 'route_targets'
    __table_args__ = (UniqueConstraint('route_id', 'model_id', name='uq_route_model'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    route_id: Mapped[int] = mapped_column(ForeignKey('model_routes.id', ondelete='CASCADE'))
    model_id: Mapped[int] = mapped_column(ForeignKey('model_registrations.id'))
    priority: Mapped[int] = mapped_column(Integer)
    weight: Mapped[int] = mapped_column(Integer)
