"""Preserve existing connections while identifying dedicated Jev providers."""
from alembic import op
import sqlalchemy as sa

revision = '0027_provider_groups'
down_revision = '0026_key_issuance_idempotency'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('provider_connections', sa.Column('model_group', sa.String(20), nullable=False, server_default='general'))
    op.execute("UPDATE provider_connections SET model_group = 'decision' WHERE provider_type = 'typesafe'")
    op.create_check_constraint('ck_provider_model_group', 'provider_connections',
        "model_group IN ('general', 'decision', 'embedding')")


def downgrade():
    raise RuntimeError('Provider groups cannot be safely downgraded; restore a compatible backup instead')
