"""Client key expiry and per-minute request limits."""
from alembic import op
import sqlalchemy as sa

revision = '0004_limits'
down_revision = '0003_usage_audit'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('client_keys', sa.Column('expires_at', sa.DateTime(timezone=True)))
    op.add_column('client_keys', sa.Column('requests_per_minute', sa.Integer()))
    op.create_check_constraint('ck_client_keys_positive_rpm', 'client_keys', 'requests_per_minute IS NULL OR requests_per_minute > 0')
    op.create_table('rate_limit_counters',
        sa.Column('client_key_id', sa.Integer, sa.ForeignKey('client_keys.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('window_start', sa.DateTime(timezone=True), primary_key=True),
        sa.Column('count', sa.Integer, nullable=False),
        sa.CheckConstraint('count >= 0', name='ck_rate_count_nonnegative'))
    op.create_index('ix_rate_window_start', 'rate_limit_counters', ['window_start'])


def downgrade():
    op.drop_table('rate_limit_counters')
    op.drop_constraint('ck_client_keys_positive_rpm', 'client_keys', type_='check')
    op.drop_column('client_keys', 'requests_per_minute')
    op.drop_column('client_keys', 'expires_at')
