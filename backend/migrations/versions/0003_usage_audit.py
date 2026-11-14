"""Usage records and administration audit history."""
from alembic import op
import sqlalchemy as sa

revision = '0003_usage_audit'
down_revision = '0002_security'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('usage_records',
        sa.Column('request_id', sa.String(36), primary_key=True),
        sa.Column('client_key_id', sa.Integer, sa.ForeignKey('client_keys.id'), nullable=False),
        sa.Column('model_id', sa.Integer, sa.ForeignKey('model_registrations.id'), nullable=False),
        sa.Column('operation', sa.String(30), nullable=False), sa.Column('status', sa.String(20), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False), sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('duration_ms', sa.Integer), sa.Column('input_tokens', sa.Integer), sa.Column('output_tokens', sa.Integer),
        sa.Column('total_tokens', sa.Integer), sa.Column('question_count', sa.Integer))
    op.create_index('ix_usage_started_at', 'usage_records', ['started_at'])
    op.create_table('audit_logs', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False), sa.Column('actor', sa.String(30), nullable=False),
        sa.Column('action', sa.String(50), nullable=False), sa.Column('target_type', sa.String(30), nullable=False),
        sa.Column('target_id', sa.String(100), nullable=False))
    op.create_index('ix_audit_created_at', 'audit_logs', ['created_at'])

def downgrade():
    op.drop_table('audit_logs')
    op.drop_table('usage_records')
