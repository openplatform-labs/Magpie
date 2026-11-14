"""Preserve the administrator who manually reconciled a reservation."""
from alembic import op
import sqlalchemy as sa

revision = '0024_reconciliation_actor'
down_revision = '0023_usage_model_snapshot'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('budget_reservations', sa.Column('reconciliation_actor', sa.String(30), nullable=True))


def downgrade():
    raise RuntimeError('Reconciliation actors cannot be downgraded without losing history; restore a compatible backup instead')
