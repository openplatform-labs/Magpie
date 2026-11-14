"""Model aliases with authorized, weighted target selection."""
from alembic import op
import sqlalchemy as sa

revision = '0013_routing'
down_revision = '0012_oidc_sessions'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('catalog_lock', sa.Column('id', sa.Integer, primary_key=True),
                    sa.CheckConstraint('id = 1', name='ck_catalog_lock_singleton'))
    op.execute('INSERT INTO catalog_lock (id) VALUES (1)')
    op.create_table('model_routes', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('alias', sa.String(100), nullable=False, unique=True),
        sa.Column('operation', sa.String(30), nullable=False), sa.Column('active', sa.Boolean, nullable=False),
        sa.CheckConstraint("operation IN ('generation','embedding','decision')", name='ck_route_operation'))
    op.create_table('route_targets', sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('route_id', sa.Integer, sa.ForeignKey('model_routes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('model_id', sa.Integer, sa.ForeignKey('model_registrations.id'), nullable=False),
        sa.Column('priority', sa.Integer, nullable=False), sa.Column('weight', sa.Integer, nullable=False),
        sa.UniqueConstraint('route_id', 'model_id', name='uq_route_model'),
        sa.CheckConstraint('priority >= 0 AND weight > 0', name='ck_route_target_weights'))
    op.add_column('usage_records', sa.Column('requested_alias', sa.String(100)))


def downgrade():
    op.drop_column('usage_records', 'requested_alias')
    op.drop_table('route_targets')
    op.drop_table('model_routes')
    op.drop_table('catalog_lock')
