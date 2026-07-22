"""notification log: one row per delivered (finding, event) alert

Backs the Slack-webhook alerting added in services/notifications. The unique
(finding_id, event) constraint is what makes alerts fire-once.

Revision ID: 0013_notification_log
Revises: 0012_intel_feeds
Create Date: 2026-07-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_notification_log"
down_revision = "0012_intel_feeds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("finding_id", "event",
                            name="uq_notification_log_finding_event"),
    )
    op.create_index("ix_notification_log_finding_id", "notification_log", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_notification_log_finding_id", table_name="notification_log")
    op.drop_table("notification_log")
