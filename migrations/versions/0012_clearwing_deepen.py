"""clearwing scans: pipeline options + richer result metrics + report artifacts

Deepened source-code hunter — expose exploit/patch/PR/disclosure options and
capture the fuller SourceHuntResult (verified/exploited counts, files, tokens,
duration, exit code) plus the SARIF + markdown report artifacts.

Revision ID: 0012_clearwing_deepen
Revises: 0011_clearwing_scans
Create Date: 2026-07-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_clearwing_deepen"
down_revision = "0011_clearwing_scans"
branch_labels = None
depends_on = None


_BOOL_COLS = ("exploit", "auto_patch", "auto_pr", "disclosures")
_INT_COLS = ("verified_count", "exploited_count", "files_ranked", "files_hunted", "tokens_used")


def upgrade() -> None:
    for col in _BOOL_COLS:
        op.add_column("clearwing_scans",
                      sa.Column(col, sa.Boolean(), nullable=False, server_default=sa.false()))
    for col in _INT_COLS:
        op.add_column("clearwing_scans",
                      sa.Column(col, sa.Integer(), nullable=False, server_default="0"))
    op.add_column("clearwing_scans", sa.Column("duration_seconds", sa.Float(), nullable=True))
    op.add_column("clearwing_scans", sa.Column("exit_code", sa.Integer(), nullable=True))
    op.add_column("clearwing_scans", sa.Column("sarif", sa.Text(), nullable=True))
    op.add_column("clearwing_scans", sa.Column("report_markdown", sa.Text(), nullable=True))


def downgrade() -> None:
    for col in ("report_markdown", "sarif", "exit_code", "duration_seconds",
                *reversed(_INT_COLS), *reversed(_BOOL_COLS)):
        op.drop_column("clearwing_scans", col)
