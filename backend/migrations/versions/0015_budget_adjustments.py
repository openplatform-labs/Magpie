"""Append-only corrections to settled budget amounts."""
from alembic import op
import sqlalchemy as sa

revision = '0015_budget_adjustments'
down_revision = '0014_embedding_space'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('budget_adjustments',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('request_id', sa.String(36), sa.ForeignKey('budget_reservations.request_id'), nullable=False),
        sa.Column('previous_amount', sa.Numeric(24, 10), nullable=False),
        sa.Column('revised_amount', sa.Numeric(24, 10), nullable=False),
        sa.Column('note', sa.String(500), nullable=False),
        sa.Column('actor', sa.String(30), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_budget_adjustments_request_id', 'budget_adjustments', ['request_id'])


def downgrade():
    op.drop_index('ix_budget_adjustments_request_id', table_name='budget_adjustments')
    op.drop_table('budget_adjustments')
