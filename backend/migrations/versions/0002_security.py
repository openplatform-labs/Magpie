"""Provider secrets and scoped client keys."""
from alembic import op
import sqlalchemy as sa

revision = "0002_security"
down_revision = "0001_catalog"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("provider_connections", sa.Column("encrypted_api_key", sa.String, nullable=True))
    op.create_table("client_keys", sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(100), nullable=False), sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(20), nullable=False), sa.Column("active", sa.Boolean, nullable=False))
    op.create_table("client_key_grants", sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("client_key_id", sa.Integer, sa.ForeignKey("client_keys.id", ondelete="CASCADE"), nullable=False),
        sa.Column("model_id", sa.Integer, sa.ForeignKey("model_registrations.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("client_key_id", "model_id", name="uq_client_key_model"))


def downgrade():
    op.drop_table("client_key_grants")
    op.drop_table("client_keys")
    op.drop_column("provider_connections", "encrypted_api_key")
