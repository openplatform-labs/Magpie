"""Remove expired transient counters and sessions. Run under operator control."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from .database import engine
from .models import AdminSession, LoginRateCounter, OIDCTransaction, RateLimitCounter


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
        ('expired_oidc', OIDCTransaction, OIDCTransaction.expires_at),
    ]:
        result = db.execute(delete(model).where(column < cutoff))
        counts[name] = result.rowcount
    db.commit()
    return counts


def main():
    with Session(engine()) as db:
        print(prune(db))


if __name__ == '__main__':
    main()
