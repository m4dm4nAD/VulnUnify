"""watched_packages (supply-chain observation inventory)

Revision ID: 0006_watched_packages
Revises: 0005_roles_and_assignment
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_watched_packages"
down_revision = "0005_roles_and_assignment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "watched_packages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("source", sa.String(256), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("ecosystem", "name", "version", "source", name="uq_watched_package"),
    )
    op.create_index("ix_watched_packages_ecosystem", "watched_packages", ["ecosystem"])
    op.create_index("ix_watched_packages_name", "watched_packages", ["name"])


def downgrade() -> None:
    op.drop_table("watched_packages")
