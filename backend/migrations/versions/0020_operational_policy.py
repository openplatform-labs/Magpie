"""Operator-controlled operational status thresholds."""
from alembic import op
import sqlalchemy as sa

revision = '0020_operational_policy'
down_revision = '0019_route_retries'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('operational_policy',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('size_warning_bytes', sa.BigInteger),
        sa.Column('stale_after_minutes', sa.Integer, nullable=False, server_default='60'),
        sa.Column('stale_count_warning', sa.Integer, nullable=False, server_default='1'),
        sa.CheckConstraint('id = 1', name='ck_operational_policy_singleton'),
        sa.CheckConstraint('size_warning_bytes IS NULL OR size_warning_bytes > 0', name='ck_operational_size_positive'),
        sa.CheckConstraint('stale_after_minutes > 0 AND stale_count_warning > 0', name='ck_operational_stale_positive'))
    op.execute('INSERT INTO operational_policy (id, stale_after_minutes, stale_count_warning) VALUES (1, 60, 1)')
    op.create_index('ix_usage_status_started', 'usage_records', ['status', 'started_at'])
    op.create_index('ix_reservation_status_request', 'budget_reservations', ['status', 'request_id'])


def downgrade():
    op.drop_index('ix_reservation_status_request', table_name='budget_reservations')
    op.drop_index('ix_usage_status_started', table_name='usage_records')
    op.drop_table('operational_policy')
