import os
from alembic import context
from sqlalchemy import create_engine, pool
from app.database import Base
from app import models  # noqa: F401

config = context.config
target_metadata = Base.metadata
url = os.environ.get("DATABASE_URL")
if not url:
    raise RuntimeError("DATABASE_URL is required")

if context.is_offline_mode():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
