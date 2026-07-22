"""intel feeds: intel_feeds table + watchlisted flags (custom feed sources)

Adds configurable threat-intel feeds (built-in KEV/EPSS + user-added CVE-list
sources) and a `watchlisted` flag on cve_intel + findings for CVEs flagged by a
custom feed (which nudges up their risk score).

Revision ID: 0012_intel_feeds
Revises: 0011_threat_intel
Create Date: 2026-07-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_intel_feeds"
down_revision = "0011_threat_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intel_feeds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(16), nullable=True),
        sa.Column("last_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_intel_feeds_name", "intel_feeds", ["name"], unique=True)

    op.add_column("cve_intel",
                  sa.Column("watchlisted", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_cve_intel_watchlisted", "cve_intel", ["watchlisted"])
    op.add_column("findings",
                  sa.Column("watchlisted", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_findings_watchlisted", "findings", ["watchlisted"])


def downgrade() -> None:
    op.drop_index("ix_findings_watchlisted", table_name="findings")
    op.drop_column("findings", "watchlisted")
    op.drop_index("ix_cve_intel_watchlisted", table_name="cve_intel")
    op.drop_column("cve_intel", "watchlisted")
    op.drop_index("ix_intel_feeds_name", table_name="intel_feeds")
    op.drop_table("intel_feeds")
