"""Persistent request metadata: never store prompts, responses, or credentials."""
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .models import AuditLog, BudgetReservation, ModelPrice, UsageRecord
from . import budgets
from .providers import as_dict, apply_generation_usage, UPSTREAM_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)
STREAM_CLOSE_TIMEOUT_SECONDS = 2.0


def audit(db, action, target_type, target_id, actor="admin_token"):
    db.add(AuditLog(created_at=datetime.now(timezone.utc), actor=actor, action=action,
                    target_type=target_type, target_id=str(target_id)))


def begin(db, key_id, model_id, operation, question_count=None, pricing_version=1, requested_alias=None, root_request_id=None, attempt_number=1, model_snapshot=None):
    request_id = str(uuid.uuid4())
    started_at = db.scalar(select(func.now()))
    price = db.scalar(select(ModelPrice).where(ModelPrice.model_id == model_id, ModelPrice.pricing_version == pricing_version, ModelPrice.operation == operation, ModelPrice.effective_from <= started_at)
        .order_by(ModelPrice.effective_from.desc(), ModelPrice.id.desc()).limit(1))
    db.add(UsageRecord(price_id=price.id if price else None, request_id=request_id, root_request_id=root_request_id or request_id, attempt_number=attempt_number, client_key_id=key_id, model_id=model_id,
        operation=operation, requested_alias=requested_alias, status='started', started_at=started_at, question_count=question_count,
        **(model_snapshot or {})))
    db.flush()
    if key_id is not None:
        budgets.reserve(db, key_id, request_id, price)
    db.commit()  # Reservation and request record commit before the provider call.
    return request_id, time.monotonic()


def end(bind, request_id, started, status, usage=None):
    try:
        usage = as_dict(usage) if usage else {}
        usage = usage if isinstance(usage, dict) else {}
        invalid_usage = False
        def count(*names):
            nonlocal invalid_usage
            values = [usage[name] for name in names if name in usage and usage[name] is not None]
            if any(type(value) is not int or not 0 <= value <= 2147483647 for value in values) or len(set(values)) > 1:
                invalid_usage = True
                return None
            return values[0] if values else None
        with Session(bind) as db:
            # Serialize with manual resolution so a late completion cannot be lost.
            row = db.scalar(select(UsageRecord).where(UsageRecord.request_id == request_id).with_for_update())
            if row is None:
                logger.error('Usage record missing for request %s', request_id)
                return
            row.status = status
            row.finished_at = datetime.now(timezone.utc)
            row.duration_ms = max(0, int((time.monotonic() - started) * 1000))
            row.input_tokens = count('prompt_tokens', 'input_tokens')
            row.output_tokens = count('completion_tokens', 'output_tokens')
            row.total_tokens = count('total_tokens')
            if row.total_tokens is not None and row.total_tokens < (row.input_tokens or 0) + (row.output_tokens or 0):
                invalid_usage = True
            if invalid_usage:
                row.input_tokens = row.output_tokens = row.total_tokens = None
            price = db.get(ModelPrice, row.price_id) if row.price_id else None
            if status == 'success' and price:
                cost = None
                if price.basis == 'question' and row.question_count is not None:
                    cost = price.per_question * row.question_count
                elif price.basis == 'tokens' and not invalid_usage:
                    # A zero rate needs no reported usage for that dimension.
                    inp = row.input_tokens if row.input_tokens is not None else (0 if price.input_per_million == 0 else None)
                    out = row.output_tokens if row.output_tokens is not None else (0 if price.output_per_million == 0 else None)
                    if inp is not None and out is not None:
                        cost = (price.input_per_million * inp + price.output_per_million * out) / Decimal(1000000)
                if cost is not None:
                    cost = cost.quantize(Decimal("0.0000000001"), rounding=ROUND_CEILING)
                    row.estimated_cost, row.currency = cost, price.currency
                    reservation = db.get(BudgetReservation, request_id)
                    if reservation is not None:
                        budgets.settle(db, reservation, cost, 'settled')
            db.commit()
    except Exception:
        # The provider call may already have been billed; do not retry it.
        logger.warning('Could not finalize usage record %s', request_id)


async def finish(bind, request_id, started, status, usage=None, circuit=None, circuit_failed=None):
    def write():
        end(bind, request_id, started, status, usage)
        if circuit is not None and circuit_failed is not None:
            from . import circuits
            circuits.record(bind, *circuit, circuit_failed)

    task = asyncio.create_task(asyncio.to_thread(write))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        # Don't abandon a DB thread that is already finalizing the attempt.
        await task
        raise


async def tracked_stream(stream, alias, bind, request_id, started, circuit, usage_provider=None):
    status, usage = 'interrupted', None
    seen_choices, finished_choices = set(), set()
    try:
        iterator = aiter(stream)
        while True:
            try:
                # The adapter's HTTP timeout may not cover every implementation
                # of an async iterator. Bound time spent waiting for each chunk.
                async with asyncio.timeout(UPSTREAM_TIMEOUT_SECONDS):
                    chunk = await anext(iterator)
            except StopAsyncIteration:
                break
            data = as_dict(chunk)
            if not isinstance(data, dict) or data.get('error') is not None:
                raise ValueError('Invalid provider stream chunk')
            choices = data.get('choices')
            if not isinstance(choices, list):
                raise ValueError('Invalid provider stream choices')
            chunk_indices = set()
            for choice in choices:
                if not isinstance(choice, dict):
                    raise ValueError('Invalid provider stream choice')
                index = choice.get('index')
                if type(index) is not int or index < 0 or index in chunk_indices or index in finished_choices:
                    raise ValueError('Invalid provider stream choice index')
                chunk_indices.add(index)
                delta = choice.get('delta')
                if not isinstance(delta, dict):
                    raise ValueError('Invalid provider stream delta')
                if delta.get('role') not in (None, 'assistant'):
                    raise ValueError('Invalid provider stream role')
                if any(delta.get(field) is not None and not isinstance(delta[field], str)
                       for field in ('content', 'refusal', 'reasoning_content')):
                    raise ValueError('Invalid provider stream content')
                calls = delta.get('tool_calls')
                if calls is not None:
                    if not isinstance(calls, list):
                        raise ValueError('Invalid provider stream tool calls')
                    for call in calls:
                        if not isinstance(call, dict) or type(call.get('index')) is not int or call['index'] < 0:
                            raise ValueError('Invalid provider stream tool call')
                        if call.get('type') not in (None, 'function') or (call.get('id') is not None and not isinstance(call['id'], str)):
                            raise ValueError('Invalid provider stream tool call')
                        function = call.get('function')
                        if function is not None and (not isinstance(function, dict) or any(function.get(field) is not None and not isinstance(function[field], str) for field in ('name', 'arguments'))):
                            raise ValueError('Invalid provider stream tool function')
                reason = choice.get('finish_reason')
                if reason is not None and (not isinstance(reason, str) or not reason):
                    raise ValueError('Invalid provider stream finish reason')
                seen_choices.add(index)
                if reason is not None:
                    finished_choices.add(index)
            if data.get('usage') is not None:
                if getattr(stream, 'magpie_usage_tracking', False) and getattr(stream, 'magpie_reported_usage', None) is None:
                    data.pop('usage', None)
                elif usage_provider:
                    apply_generation_usage(data, stream, usage_provider)
                usage = data.get('usage')
            if 'model' in data:
                data['model'] = alias
            yield 'data: ' + json.dumps(data, ensure_ascii=False, allow_nan=False) + '\n\n'
        if not seen_choices or seen_choices != finished_choices:
            raise ValueError('Provider stream ended before all choices finished')
        if getattr(stream, 'magpie_usage_tracking', False):
            reported = getattr(stream, 'magpie_reported_usage', None)
            usage = dict(reported) if isinstance(reported, dict) else None
        status = 'success'
        yield 'data: [DONE]\n\n'
    except asyncio.CancelledError:
        raise
    except Exception:
        status = 'error'
        yield 'data: {"error":{"message":"Provider stream failed","type":"provider_error"}}\n\n'
    finally:
        # Persist the outcome before awaiting cleanup: an adapter can hang or
        # raise while closing, and must not leave an already finished request
        # indefinitely marked as started.
        try:
            await finish(bind, request_id, started, status, usage, circuit,
                         status == 'error' if status in ('success', 'error') else None)
        finally:
            try:
                close = getattr(stream, 'aclose', None)
                if close:
                    async with asyncio.timeout(STREAM_CLOSE_TIMEOUT_SECONDS):
                        await close()
            except Exception:
                # Provider exceptions may contain credentials or response content.
                logger.warning('Could not close provider stream')
