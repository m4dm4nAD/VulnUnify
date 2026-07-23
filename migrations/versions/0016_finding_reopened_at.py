"""findings.reopened_at: when a resolved finding came back

Stamped by ingest when a source re-reports a finding that had resolved_at set.
Lets MTTR measure the latest remediation cycle (reopened_at -> resolved_at)
instead of the full first_seen -> resolved_at lifetime, which for a
resolved-then-reopened finding overstates remediation time by months.

Revision ID: 0016_finding_reopened_at
Revises: 0015_posture_snapshots
Create Date: 2026-07-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0016_finding_reopened_at"
down_revision = "0015_posture_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings",
                  sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "reopened_at")
