"""Bind immutable price history to a model deployment version."""
from alembic import op
import sqlalchemy as sa

revision = '0008_price_versions'
down_revision = '0007_pricing'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_registrations', sa.Column('pricing_version', sa.Integer, nullable=False, server_default='1'))
    op.add_column('model_prices', sa.Column('pricing_version', sa.Integer, nullable=False, server_default='1'))


def downgrade():
    op.drop_column('model_prices', 'pricing_version')
    op.drop_column('model_registrations', 'pricing_version')
