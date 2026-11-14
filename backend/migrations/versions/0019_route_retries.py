"""Opt-in retry policy and per-attempt request correlation."""
from alembic import op
import sqlalchemy as sa

revision = '0019_route_retries'
down_revision = '0018_model_circuits'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_routes', sa.Column('retry_on_failure', sa.Boolean, nullable=False, server_default=sa.false()))
    op.add_column('usage_records', sa.Column('root_request_id', sa.String(36)))
    op.add_column('usage_records', sa.Column('attempt_number', sa.Integer, nullable=False, server_default='1'))
    op.execute('UPDATE usage_records SET root_request_id = request_id WHERE root_request_id IS NULL')
    op.create_index('ix_usage_root_request_id', 'usage_records', ['root_request_id'])


def downgrade():
    op.drop_index('ix_usage_root_request_id', table_name='usage_records')
    op.drop_column('usage_records', 'attempt_number')
    op.drop_column('usage_records', 'root_request_id')
    op.drop_column('model_routes', 'retry_on_failure')
