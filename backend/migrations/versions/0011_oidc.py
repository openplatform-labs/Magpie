"""OIDC identity bindings and single-use login transactions."""
from alembic import op
import sqlalchemy as sa

revision = '0011_oidc'
down_revision = '0010_budgets'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('oidc_identities', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('issuer', sa.String(500), nullable=False), sa.Column('subject', sa.String(255), nullable=False),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('admin_users.id'), nullable=False),
        sa.UniqueConstraint('issuer', 'subject', name='uq_oidc_issuer_subject'))
    op.create_table('oidc_transactions', sa.Column('state_hash', sa.String(64), primary_key=True),
        sa.Column('browser_hash', sa.String(64), nullable=False), sa.Column('nonce_hash', sa.String(64), nullable=False),
        sa.Column('encrypted_verifier', sa.String, nullable=False), sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used', sa.Boolean, nullable=False))
    op.create_index('ix_oidc_transaction_expiry', 'oidc_transactions', ['expires_at'])


def downgrade():
    op.drop_table('oidc_transactions')
    op.drop_table('oidc_identities')
