"""Local administrator accounts and revocable sessions."""
from alembic import op
import sqlalchemy as sa

revision = '0005_admin_sessions'
down_revision = '0004_limits'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('admin_users', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(100), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(256), nullable=False),
        sa.Column('active', sa.Boolean, nullable=False))
    op.create_table('admin_sessions', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('admin_users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean, nullable=False))
    op.create_table('bootstrap_lock', sa.Column('id', sa.Integer, primary_key=True),
        sa.CheckConstraint('id = 1', name='ck_bootstrap_lock_singleton'))
    op.execute('INSERT INTO bootstrap_lock (id) VALUES (1)')


def downgrade():
    op.drop_table('bootstrap_lock')
    op.drop_table('admin_sessions')
    op.drop_table('admin_users')
