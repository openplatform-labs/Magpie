"""Explicit embedding-space metadata for safe multi-model routes."""
from alembic import op
import sqlalchemy as sa

revision = '0014_embedding_space'
down_revision = '0013_routing'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_registrations', sa.Column('embedding_space', sa.String(100)))


def downgrade():
    op.drop_column('model_registrations', 'embedding_space')
