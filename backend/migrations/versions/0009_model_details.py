"""Optional model capability metadata."""
from alembic import op
import sqlalchemy as sa

revision = '0009_model_details'
down_revision = '0008_price_versions'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_registrations', sa.Column('description', sa.String(1000)))
    op.add_column('model_registrations', sa.Column('embedding_dimensions', sa.Integer))
    op.add_column('model_registrations', sa.Column('max_input_tokens', sa.Integer))
    op.add_column('model_registrations', sa.Column('supports_streaming', sa.Boolean))
    op.add_column('model_registrations', sa.Column('supports_tools', sa.Boolean))
    op.add_column('model_registrations', sa.Column('supports_reasoning', sa.Boolean))
    op.create_check_constraint('ck_model_dimensions_positive', 'model_registrations', 'embedding_dimensions IS NULL OR embedding_dimensions > 0')
    op.create_check_constraint('ck_model_input_tokens_positive', 'model_registrations', 'max_input_tokens IS NULL OR max_input_tokens > 0')


def downgrade():
    op.drop_constraint('ck_model_input_tokens_positive', 'model_registrations', type_='check')
    op.drop_constraint('ck_model_dimensions_positive', 'model_registrations', type_='check')
    for name in ('supports_reasoning','supports_tools','supports_streaming','max_input_tokens','embedding_dimensions','description'):
        op.drop_column('model_registrations', name)
