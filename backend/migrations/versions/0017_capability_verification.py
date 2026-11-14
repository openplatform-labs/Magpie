"""Track operator-recorded evidence for individual model capabilities."""
from alembic import op
import sqlalchemy as sa

revision = '0017_capability_verification'
down_revision = '0016_embedding_batch'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('model_registrations', sa.Column('verification_version', sa.Integer, nullable=False, server_default='1'))
    op.add_column('model_capabilities', sa.Column('verification_status', sa.String(30), nullable=False, server_default='unverified'))
    op.create_table('capability_verification_events',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('model_id', sa.Integer, sa.ForeignKey('model_registrations.id'), nullable=False),
        sa.Column('operation', sa.String(30), nullable=False),
        sa.Column('previous_status', sa.String(30), nullable=False),
        sa.Column('status', sa.String(30), nullable=False),
        sa.Column('note', sa.String(500), nullable=False),
        sa.Column('actor', sa.String(30), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_capability_verification_model', 'capability_verification_events', ['model_id', 'id'])


def downgrade():
    op.drop_index('ix_capability_verification_model', table_name='capability_verification_events')
    op.drop_table('capability_verification_events')
    op.drop_column('model_capabilities', 'verification_status')
    op.drop_column('model_registrations', 'verification_version')
