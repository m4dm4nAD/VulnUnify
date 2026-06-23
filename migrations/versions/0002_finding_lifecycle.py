"""finding lifecycle: source/effective status, triage, SLA

Revision ID: 0002_finding_lifecycle
Revises: 0001_initial
Create Date: 2026-06-23
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_finding_lifecycle"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The old source-derived `status` becomes `source_status`.
    op.alter_column("findings", "status", new_column_name="source_status")
    op.drop_index("ix_findings_status", table_name="findings")

    op.add_column(
        "findings",
        sa.Column("effective_status", sa.String(32), nullable=False, server_default="open"),
    )
    op.create_index("ix_findings_effective_status", "findings", ["effective_status"])

    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True)))
    op.add_column(
        "findings",
        sa.Column("triage_state", sa.String(32), nullable=False, server_default="active"),
    )
    op.add_column("findings", sa.Column("triage_reason", sa.Text()))
    op.add_column("findings", sa.Column("triage_until", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("triaged_at", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("triaged_by", sa.String(128)))
    op.add_column("findings", sa.Column("sla_due_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    for col in (
        "sla_due_at",
        "triaged_by",
        "triaged_at",
        "triage_until",
        "triage_reason",
        "triage_state",
        "resolved_at",
    ):
        op.drop_column("findings", col)
    op.drop_index("ix_findings_effective_status", table_name="findings")
    op.drop_column("findings", "effective_status")
    op.alter_column("findings", "source_status", new_column_name="status")
    op.create_index("ix_findings_status", "findings", ["status"])
