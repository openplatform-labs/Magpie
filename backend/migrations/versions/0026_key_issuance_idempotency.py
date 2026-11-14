"""Prevent duplicate client key issuance for a repeated request identifier."""
from alembic import op
import sqlalchemy as sa

revision = '0026_key_issuance_idempotency'
down_revision = '0025_reconciliation_force'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('client_keys', sa.Column('creation_request_hash', sa.String(64), nullable=True))
    op.create_unique_constraint('uq_client_keys_creation_request_hash', 'client_keys', ['creation_request_hash'])


def downgrade():
    raise RuntimeError('Key issuance identifiers cannot be downgraded safely; restore a compatible backup instead')
