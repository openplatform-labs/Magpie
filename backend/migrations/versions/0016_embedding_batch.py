"""Embedding batch capability metadata."""
from alembic import op
import sqlalchemy as sa

revision = '0016_embedding_batch'
down_revision = '0015_budget_adjustments'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_registrations', sa.Column('supports_embedding_batch', sa.Boolean))
    op.add_column('model_registrations', sa.Column('embedding_max_batch_size', sa.Integer))
    op.create_check_constraint('ck_embedding_max_batch_positive', 'model_registrations', 'embedding_max_batch_size IS NULL OR embedding_max_batch_size > 0')


def downgrade():
    op.drop_constraint('ck_embedding_max_batch_positive', 'model_registrations', type_='check')
    op.drop_column('model_registrations', 'embedding_max_batch_size')
    op.drop_column('model_registrations', 'supports_embedding_batch')
