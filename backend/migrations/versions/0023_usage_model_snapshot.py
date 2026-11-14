"""Preserve the provider and model selected for each new attempt."""
from alembic import op
import sqlalchemy as sa

revision = '0023_usage_model_snapshot'
down_revision = '0022_price_operations'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('usage_records', sa.Column('provider_id_snapshot', sa.Integer(), nullable=True))
    op.add_column('usage_records', sa.Column('provider_type_snapshot', sa.String(50), nullable=True))
    op.add_column('usage_records', sa.Column('provider_name_snapshot', sa.String(100), nullable=True))
    op.add_column('usage_records', sa.Column('upstream_model_snapshot', sa.String(200), nullable=True))


def downgrade():
    raise RuntimeError('Usage model snapshots cannot be downgraded without losing history; restore a compatible backup instead')
