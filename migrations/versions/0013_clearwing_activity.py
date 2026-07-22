"""clearwing scans: live activity line for in-progress scans

Adds `activity` — a human-readable "what the scan is doing right now" string,
streamed from Clearwing's per-stage events so the UI can show live progress.

Revision ID: 0013_clearwing_activity
Revises: 0012_clearwing_deepen
Create Date: 2026-07-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_clearwing_activity"
down_revision = "0012_clearwing_deepen"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("clearwing_scans", sa.Column("activity", sa.String(256), nullable=True))


def downgrade() -> None:
    op.drop_column("clearwing_scans", "activity")
