"""Shared cooldown state for model routing."""
from alembic import op
import sqlalchemy as sa

revision = '0018_model_circuits'
down_revision = '0017_capability_verification'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('model_circuits',
        sa.Column('model_id', sa.Integer, sa.ForeignKey('model_registrations.id'), primary_key=True),
        sa.Column('operation', sa.String(30), primary_key=True),
        sa.Column('config_version', sa.Integer, primary_key=True),
        sa.Column('failure_count', sa.Integer, nullable=False),
        sa.Column('open_until', sa.DateTime(timezone=True)))


def downgrade():
    op.drop_table('model_circuits')
