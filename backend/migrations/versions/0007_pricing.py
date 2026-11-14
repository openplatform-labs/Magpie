"""Immutable model pricing and per-request estimated cost."""
from alembic import op
import sqlalchemy as sa

revision = '0007_pricing'
down_revision = '0006_login_limits'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('model_prices', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('model_id', sa.Integer, sa.ForeignKey('model_registrations.id'), nullable=False),
        sa.Column('effective_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('currency', sa.String(3), nullable=False), sa.Column('basis', sa.String(20), nullable=False),
        sa.Column('input_per_million', sa.Numeric(18, 8)), sa.Column('output_per_million', sa.Numeric(18, 8)),
        sa.Column('per_question', sa.Numeric(18, 8)),
        sa.CheckConstraint("basis IN ('tokens', 'question')", name='ck_price_basis'))
    op.create_index('ix_price_model_effective', 'model_prices', ['model_id', 'effective_from'])
    op.add_column('usage_records', sa.Column('price_id', sa.Integer, sa.ForeignKey('model_prices.id')))
    op.add_column('usage_records', sa.Column('estimated_cost', sa.Numeric(24, 10)))
    op.add_column('usage_records', sa.Column('currency', sa.String(3)))


def downgrade():
    op.drop_column('usage_records', 'currency')
    op.drop_column('usage_records', 'estimated_cost')
    op.drop_column('usage_records', 'price_id')
    op.drop_table('model_prices')
