"""PostgreSQL atomic fixed-window limits shared across gateway instances."""
from datetime import timezone
from fastapi import HTTPException
from sqlalchemy import func, select
from .models import RateLimitCounter


def consume(db, key):
    limit = key.requests_per_minute
    if limit is None:
        return
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == 'sqlite':  # Test support; production requires PostgreSQL.
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RuntimeError('Unsupported database for rate limiting')
    # Use the database clock, so application instance clock skew does not bypass limits.
    now = db.scalar(select(func.current_timestamp()))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    window = now.replace(second=0, microsecond=0)
    counter = RateLimitCounter.__table__
    statement = insert(counter).values(client_key_id=key.id, window_start=window, count=1)
    statement = statement.on_conflict_do_update(
        index_elements=[counter.c.client_key_id, counter.c.window_start],
        set_={'count': counter.c.count + 1}, where=counter.c.count < limit,
    ).returning(counter.c.count)
    if db.scalar(statement) is None:
        db.rollback()
        raise HTTPException(429, 'Request rate limit exceeded', headers={'Retry-After': str(60 - now.second)})


def login_attempt(db, username, peer):
    from .models import LoginRateCounter
    from .security import hash_key
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == 'sqlite':
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RuntimeError('Unsupported database for login limiting')
    now = db.scalar(select(func.current_timestamp()))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    window = now.replace(second=0, microsecond=0)
    counter = LoginRateCounter.__table__
    # Connection peer is authoritative; forwarded headers are intentionally not trusted.
    for scope, maximum in [('user:' + username.casefold(), 10), ('peer:' + peer, 50)]:
        statement = insert(counter).values(scope_hash=hash_key(scope), window_start=window, count=1)
        statement = statement.on_conflict_do_update(
            index_elements=[counter.c.scope_hash, counter.c.window_start],
            set_={'count': counter.c.count + 1}, where=counter.c.count < maximum,
        ).returning(counter.c.count)
        if db.scalar(statement) is None:
            db.rollback()
            raise HTTPException(429, 'Too many login attempts', headers={'Retry-After': str(60 - now.second)})
    # Count the attempt even if the password is incorrect or the process crashes later.
    db.commit()
