"""posture snapshots: periodic point-in-time posture rollups for trend charts

Findings are upserted in place, so posture history only exists from the first
snapshot onward. Written by services/posture (scheduler tick / startup / manual
sync), throttled to one per hour.

Revision ID: 0015_posture_snapshots
Revises: 0014_tighten_nullability
Create Date: 2026-07-22
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015_posture_snapshots"
down_revision = "0014_tighten_nullability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "posture_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("taken_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("open_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_info", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kev_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sla_breached_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_risk_open", sa.Float(), nullable=False, server_default="0"),
        sa.Column("by_source", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_posture_snapshots_taken_at", "posture_snapshots", ["taken_at"])


def downgrade() -> None:
    op.drop_index("ix_posture_snapshots_taken_at", table_name="posture_snapshots")
    op.drop_table("posture_snapshots")
