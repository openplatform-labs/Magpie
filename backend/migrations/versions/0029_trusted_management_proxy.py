"""Optional request-bound management proxy; existing local accounts unchanged."""
from alembic import op
import sqlalchemy as sa

revision = '0029_trusted_management_proxy'
down_revision = '0028_admin_model_tests'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('trusted_proxy_requests',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('issuer', sa.String(256), nullable=False),
        sa.Column('subject', sa.String(36), nullable=False),
        sa.Column('actor', sa.String(30), nullable=False),
        sa.Column('method', sa.String(8), nullable=False),
        sa.Column('target', sa.String(250), nullable=False),
        sa.Column('body_sha256', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.BigInteger(), nullable=False))
    op.create_index('ix_trusted_proxy_requests_expires_at', 'trusted_proxy_requests', ['expires_at'])
    op.add_column('audit_logs', sa.Column('proxy_request_id', sa.String(36)))
    op.create_foreign_key('audit_proxy_request_fk', 'audit_logs', 'trusted_proxy_requests',
                          ['proxy_request_id'], ['id'])


def downgrade():
    raise RuntimeError('Delegation replay/audit evidence must be preserved; restore a compatible backup')
