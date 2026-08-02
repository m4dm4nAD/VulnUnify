"""vuln radar: curated researcher accounts + normalized vuln-chatter items

Ambient threat-intel from free/keyless social APIs (Mastodon, Bluesky), filtered
by a curated source allowlist + a structural/LLM funnel, correlated to findings.

Revision ID: 0020_vuln_radar
Revises: 0019_user_oidc_subject
Create Date: 2026-08-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0020_vuln_radar"
down_revision = "0019_user_oidc_subject"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "radar_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("handle", sa.String(255), nullable=False),
        sa.Column("instance", sa.String(255), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("trust_weight", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("account_ref", sa.String(255), nullable=True),
        sa.Column("cursor", sa.String(255), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(16), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_radar_sources_platform", "radar_sources", ["platform"])

    op.create_table(
        "radar_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(),
                  sa.ForeignKey("radar_sources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("author_handle", sa.String(255), nullable=False),
        sa.Column("author_display", sa.String(255), nullable=True),
        sa.Column("posted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("cve_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("products", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("vuln_type", sa.String(64), nullable=True),
        sa.Column("severity_hint", sa.String(16), nullable=True),
        sa.Column("poc_mentioned", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("signals", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("classified_by", sa.String(16), nullable=False, server_default="heuristic"),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        sa.Column("matched_finding_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("platform", "external_id", name="uq_radar_item_platform_extid"),
    )
    op.create_index("ix_radar_items_source_id", "radar_items", ["source_id"])
    op.create_index("ix_radar_items_author_handle", "radar_items", ["author_handle"])
    op.create_index("ix_radar_items_posted_at", "radar_items", ["posted_at"])
    op.create_index("ix_radar_items_confidence", "radar_items", ["confidence"])
    op.create_index("ix_radar_items_status", "radar_items", ["status"])


def downgrade() -> None:
    op.drop_table("radar_items")
    op.drop_index("ix_radar_sources_platform", table_name="radar_sources")
    op.drop_table("radar_sources")
