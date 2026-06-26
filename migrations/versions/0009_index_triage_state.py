"""index findings.triage_state (it's filtered)

Revision ID: 0009_index_triage_state
Revises: 0008_error_logs
Create Date: 2026-06-26
"""
from alembic import op

revision = "0009_index_triage_state"
down_revision = "0008_error_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_findings_triage_state", "findings", ["triage_state"])


def downgrade() -> None:
    op.drop_index("ix_findings_triage_state", table_name="findings")
