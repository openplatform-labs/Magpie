import os
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def runtime_engine(url, *, lock_timeout_ms=5000, statement_timeout_ms=30000):
    # Bound database work and connection-pool contention for request handlers.
    # Alembic has its own engine so DDL is not subject to these runtime limits.
    return create_engine(url, pool_pre_ping=True, pool_timeout=5,
                         connect_args={'connect_timeout': 3, 'options':
                             f'-c lock_timeout={lock_timeout_ms} -c statement_timeout={statement_timeout_ms}'})


@lru_cache
def engine():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is required")
    return runtime_engine(url)
