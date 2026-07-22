"""threat intel: cve_intel table + finding.risk_score + asset.criticality

Adds the threat-intelligence enrichment layer: per-CVE facts (CISA KEV, EPSS),
a composite risk_score on findings, and business criticality on assets — the
inputs to risk-based prioritization.

Revision ID: 0011_threat_intel
Revises: 0010_package_scans
Create Date: 2026-07-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_threat_intel"
down_revision = "0010_package_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_intel",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_ransomware", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("sources", sa.String(256), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_cve_intel_in_kev", "cve_intel", ["in_kev"])

    op.add_column("findings",
                  sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"))
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])
    op.add_column("findings",
                  sa.Column("in_kev", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_findings_in_kev", "findings", ["in_kev"])
    op.add_column("findings", sa.Column("epss_score", sa.Float(), nullable=True))

    op.add_column("assets",
                  sa.Column("criticality", sa.String(16), nullable=False, server_default="medium"))
    op.create_index("ix_assets_criticality", "assets", ["criticality"])


def downgrade() -> None:
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_column("assets", "criticality")
    op.drop_column("findings", "epss_score")
    op.drop_index("ix_findings_in_kev", table_name="findings")
    op.drop_column("findings", "in_kev")
    op.drop_index("ix_findings_risk_score", table_name="findings")
    op.drop_column("findings", "risk_score")
    op.drop_index("ix_cve_intel_in_kev", table_name="cve_intel")
    op.drop_table("cve_intel")
