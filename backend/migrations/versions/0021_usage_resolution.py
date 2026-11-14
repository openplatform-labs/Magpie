"""Record an operator's resolution of an indeterminate request."""
from alembic import op
import sqlalchemy as sa

revision = '0021_usage_resolution'
down_revision = '0020_operational_policy'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('usage_records', sa.Column('resolved_at', sa.DateTime(timezone=True)))
    op.add_column('usage_records', sa.Column('resolution_actor', sa.String(30)))
    op.add_column('usage_records', sa.Column('resolution_note', sa.String(500)))


def downgrade():
    op.drop_column('usage_records', 'resolution_note')
    op.drop_column('usage_records', 'resolution_actor')
    op.drop_column('usage_records', 'resolved_at')
