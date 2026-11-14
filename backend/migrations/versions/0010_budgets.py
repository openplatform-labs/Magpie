"""Persistent per-key budget reservations and reconciliation."""
from alembic import op
import sqlalchemy as sa

revision = '0010_budgets'
down_revision = '0009_model_details'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('key_budgets',
        sa.Column('client_key_id', sa.Integer, sa.ForeignKey('client_keys.id'), primary_key=True),
        sa.Column('currency', sa.String(3), nullable=False),
        sa.Column('limit_amount', sa.Numeric(24, 10), nullable=False),
        sa.Column('reserve_per_request', sa.Numeric(24, 10), nullable=False),
        sa.Column('spent_amount', sa.Numeric(24, 10), nullable=False),
        sa.Column('held_amount', sa.Numeric(24, 10), nullable=False),
        sa.CheckConstraint('limit_amount >= 0 AND reserve_per_request > 0 AND spent_amount >= 0 AND held_amount >= 0', name='ck_budget_nonnegative'))
    op.create_table('budget_reservations',
        sa.Column('request_id', sa.String(36), sa.ForeignKey('usage_records.request_id'), primary_key=True),
        sa.Column('client_key_id', sa.Integer, sa.ForeignKey('key_budgets.client_key_id'), nullable=False),
        sa.Column('reserved_amount', sa.Numeric(24, 10), nullable=False),
        sa.Column('settled_amount', sa.Numeric(24, 10)),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('reconciled_at', sa.DateTime(timezone=True)),
        sa.Column('reconciliation_note', sa.String(500)),
        sa.CheckConstraint("status IN ('pending','settled','manual')", name='ck_reservation_status'),
        sa.CheckConstraint('reserved_amount > 0 AND (settled_amount IS NULL OR settled_amount >= 0)', name='ck_reservation_amounts'))
    op.create_index('ix_budget_reservation_key_status', 'budget_reservations', ['client_key_id', 'status'])


def downgrade():
    op.drop_table('budget_reservations')
    op.drop_table('key_budgets')
