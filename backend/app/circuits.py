"""Cross-instance cooldowns; never retry an already dispatched request."""
import logging
from datetime import timedelta
from sqlalchemy import case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session
from .models import ModelCircuit

logger = logging.getLogger(__name__)
FAILURE_THRESHOLD = 3
COOLDOWN_SECONDS = 30


def available_ids(db, candidates, operation):
    now = db.scalar(select(func.now()))
    ids = [model.id for model, *_ in candidates]
    rows = db.scalars(select(ModelCircuit).where(ModelCircuit.model_id.in_(ids), ModelCircuit.operation == operation)).all()
    blocked = {(r.model_id, r.config_version) for r in rows if r.open_until is not None and r.open_until > now}
    return {model.id for model, *_ in candidates if (model.id, model.verification_version) not in blocked}


def record(bind, model_id, operation, version, failed):
    """Record completion order; a DB error must not change the provider response."""
    try:
        with Session(bind) as db:
            now = db.scalar(select(func.now()))
            if failed:
                insert = pg_insert if db.bind.dialect.name == 'postgresql' else sqlite_insert
                statement = insert(ModelCircuit).values(model_id=model_id, operation=operation, config_version=version, failure_count=1)
                expired = (ModelCircuit.open_until.is_not(None)) & (ModelCircuit.open_until <= now)
                opened = (ModelCircuit.open_until.is_not(None)) & (ModelCircuit.open_until > now)
                next_count = case((expired, 1), (opened, ModelCircuit.failure_count), else_=ModelCircuit.failure_count + 1)
                statement = statement.on_conflict_do_update(index_elements=['model_id', 'operation', 'config_version'], set_={
                    'failure_count': next_count,
                    'open_until': case((expired, None), (opened, ModelCircuit.open_until),
                        (next_count >= FAILURE_THRESHOLD, now + timedelta(seconds=COOLDOWN_SECONDS)), else_=None)})
                db.execute(statement)
            else:
                db.execute(update(ModelCircuit).where(ModelCircuit.model_id == model_id, ModelCircuit.operation == operation,
                    ModelCircuit.config_version == version, or_(ModelCircuit.open_until.is_(None), ModelCircuit.open_until <= now))
                    .values(failure_count=0, open_until=None))
            db.commit()
    except Exception:
        logger.warning('Could not update model cooldown state')
