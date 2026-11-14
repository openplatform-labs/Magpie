"""Associate sessions with their OIDC identity for precise revocation."""
from alembic import op
import sqlalchemy as sa

revision = '0012_oidc_sessions'
down_revision = '0011_oidc'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('admin_sessions', sa.Column('oidc_identity_id', sa.Integer))
    op.create_foreign_key('fk_session_oidc_identity', 'admin_sessions', 'oidc_identities',
                          ['oidc_identity_id'], ['id'], ondelete='SET NULL')


def downgrade():
    op.drop_constraint('fk_session_oidc_identity', 'admin_sessions', type_='foreignkey')
    op.drop_column('admin_sessions', 'oidc_identity_id')
