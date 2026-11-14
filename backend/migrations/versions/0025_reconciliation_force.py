"""Preserve whether a manual reconciliation was forced."""
from alembic import op
import sqlalchemy as sa

revision = '0025_reconciliation_force'
down_revision = '0024_reconciliation_actor'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('budget_reservations', sa.Column('reconciliation_forced', sa.Boolean(), nullable=True))


def downgrade():
    raise RuntimeError('Reconciliation history cannot be downgraded without data loss; restore a compatible backup instead')
