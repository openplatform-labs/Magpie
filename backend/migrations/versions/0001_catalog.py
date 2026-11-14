"""Initial model catalog.

Revision ID: 0001_catalog
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_catalog"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("provider_connections", sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("provider_type", sa.String(50), nullable=False),
        sa.Column("base_url", sa.String(500)), sa.Column("active", sa.Boolean, nullable=False))
    op.create_table("model_registrations", sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("alias", sa.String(100), nullable=False, unique=True),
        sa.Column("upstream_model", sa.String(200), nullable=False),
        sa.Column("provider_id", sa.Integer, sa.ForeignKey("provider_connections.id"), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False))
    op.create_table("model_capabilities", sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("model_id", sa.Integer, sa.ForeignKey("model_registrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("operation", sa.String(30), nullable=False), sa.Column("api_mode", sa.String(50), nullable=False),
        sa.UniqueConstraint("model_id", "operation", name="uq_model_operation"))


def downgrade():
    op.drop_table("model_capabilities")
    op.drop_table("model_registrations")
    op.drop_table("provider_connections")
