"""Separate prices by operation; preserve ambiguous legacy token prices."""
from alembic import op
import sqlalchemy as sa

revision = '0022_price_operations'
down_revision = '0021_usage_resolution'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_prices', sa.Column('operation', sa.String(30)))
    # A per-question price was only valid for decisions. Token prices could
    # have covered any capability, so never infer their intended operation.
    op.execute("UPDATE model_prices SET operation = 'decision' WHERE basis = 'question'")
    op.create_check_constraint('ck_price_operation', 'model_prices', "operation IS NULL OR operation IN ('generation', 'embedding', 'decision')")
    op.create_index('ix_price_model_operation_effective', 'model_prices', ['model_id', 'pricing_version', 'operation', 'effective_from'])


def downgrade():
    raise RuntimeError('Operation-specific prices cannot be downgraded without losing meaning; restore a compatible backup instead')
