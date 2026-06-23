"""initial schema: assets, findings, connector_runs

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("asset_type", sa.String(32), nullable=False),
        sa.Column("name", sa.String(512)),
        sa.Column("cloud_provider", sa.String(32)),
        sa.Column("region", sa.String(64)),
        sa.Column("asset_metadata", postgresql.JSONB(), server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_assets_identifier", "assets", ["identifier"], unique=True)
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("source_finding_id", sa.String(256), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("title", sa.String(1024), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("raw_severity", sa.String(64)),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("cve_ids", postgresql.JSONB(), server_default="[]"),
        sa.Column("cwe_ids", postgresql.JSONB(), server_default="[]"),
        sa.Column("cvss_base_score", sa.Float()),
        sa.Column("cvss_vector", sa.String(128)),
        sa.Column("location", postgresql.JSONB(), server_default="{}"),
        sa.Column("remediation", sa.Text()),
        sa.Column("refs", postgresql.JSONB(), server_default="[]"),
        sa.Column("tags", postgresql.JSONB(), server_default="{}"),
        sa.Column("raw", postgresql.JSONB(), server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column(
            "asset_id",
            sa.Integer(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"], unique=True)
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])

    op.create_table(
        "connector_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("connector", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_connector_runs_connector", "connector_runs", ["connector"])


def downgrade() -> None:
    op.drop_table("connector_runs")
    op.drop_table("findings")
    op.drop_table("assets")
