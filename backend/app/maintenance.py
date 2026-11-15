"""Remove expired transient counters and sessions. Run under operator control."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from .database import engine
from .models import AdminSession, AuditLog, LoginRateCounter, RateLimitCounter, TrustedProxyRequest


def prune(db: Session) -> dict[str, int]:
    now = db.scalar(select(func.now()))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = now - timedelta(days=2)
    counts = {}
    for name, model, column in [
        ('rate_limits', RateLimitCounter, RateLimitCounter.window_start),
        ('login_limits', LoginRateCounter, LoginRateCounter.window_start),
        ('expired_sessions', AdminSession, AdminSession.expires_at),
    ]:
        statement = delete(model).where(column < cutoff)
        if model is AdminSession:
            # Preserve historical SSO rows even though they no longer authenticate.
            statement = statement.where(AdminSession.oidc_identity_id.is_(None))
        result = db.execute(statement)
        counts[name] = result.rowcount
    # Keep consumed write identities for at least two days and for as long as
    # any audit entry refers to them; never prune a live/replayable delegation.
    statement = delete(TrustedProxyRequest).where(
        TrustedProxyRequest.expires_at < int(cutoff.timestamp()),
        ~select(AuditLog.id).where(AuditLog.proxy_request_id == TrustedProxyRequest.id).exists())
    counts['expired_proxy_requests'] = db.execute(statement).rowcount
    db.commit()
    return counts


def main():
    with Session(engine()) as db:
        print(prune(db))


if __name__ == '__main__':
    main()
