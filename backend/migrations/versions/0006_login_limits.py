"""Shared administrator login throttling."""
from alembic import op
import sqlalchemy as sa

revision = '0006_login_limits'
down_revision = '0005_admin_sessions'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('login_rate_counters',
        sa.Column('scope_hash', sa.String(64), primary_key=True),
        sa.Column('window_start', sa.DateTime(timezone=True), primary_key=True),
        sa.Column('count', sa.Integer, nullable=False),
        sa.CheckConstraint('count >= 0', name='ck_login_rate_count'))
    op.create_index('ix_login_window_start', 'login_rate_counters', ['window_start'])


def downgrade():
    op.drop_table('login_rate_counters')
