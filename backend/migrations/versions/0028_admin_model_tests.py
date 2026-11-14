"""Allow audited administrator model tests without issuing client keys."""
from alembic import op

revision = '0028_admin_model_tests'
down_revision = '0027_provider_groups'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('usage_records', 'client_key_id', nullable=True)


def downgrade():
    raise RuntimeError('Admin test usage cannot be safely downgraded; restore a compatible backup instead')
