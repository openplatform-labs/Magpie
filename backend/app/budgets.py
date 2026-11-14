"""Conservative accounting reserves. External provider billing is not controlled here."""
from decimal import Decimal
from fastapi import HTTPException
from sqlalchemy import select
from .models import BudgetReservation, KeyBudget


def reserve(db, key_id: int, request_id: str, price):
    budget = db.scalar(select(KeyBudget).where(KeyBudget.client_key_id == key_id).with_for_update())
    if budget is None:
        return
    if not price or price.currency != budget.currency:
        raise HTTPException(503, 'Budget requires a current model price in the configured currency')
    amount = budget.reserve_per_request
    if budget.spent_amount + budget.held_amount + amount > budget.limit_amount:
        raise HTTPException(429, 'Budget allowance exhausted')
    budget.held_amount += amount
    db.add(BudgetReservation(request_id=request_id, client_key_id=key_id, reserved_amount=amount, status='pending'))


def settle(db, reservation, amount: Decimal, status: str, note: str | None = None, actor: str | None = None, forced: bool | None = None):
    # Lock ordering is always budget first, then reservation, to avoid deadlocks.
    budget = db.scalar(select(KeyBudget).where(KeyBudget.client_key_id == reservation.client_key_id).with_for_update().execution_options(populate_existing=True))
    reservation = db.scalar(select(BudgetReservation).where(BudgetReservation.request_id == reservation.request_id).with_for_update().execution_options(populate_existing=True))
    if reservation.status != 'pending':
        return False
    budget.held_amount -= reservation.reserved_amount
    budget.spent_amount += amount
    reservation.settled_amount = amount
    reservation.status = status
    if status == 'manual':
        from datetime import datetime, timezone
        reservation.reconciled_at = datetime.now(timezone.utc)
        reservation.reconciliation_note = note
        reservation.reconciliation_actor = actor
        reservation.reconciliation_forced = forced
    return True
