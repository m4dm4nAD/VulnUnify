"""package_scans.username: denormalized actor so scan attribution survives deletion

user_id is SET NULL on delete, which erased who ran a scan. Store the username
at write time (like audit_log.actor_username). Backfills existing rows from the
still-present users.

Revision ID: 0018_package_scan_username
Revises: 0017_audit_log
Create Date: 2026-08-02
"""
from alembic import op
import sqlalchemy as sa

revision = "0018_package_scan_username"
down_revision = "0017_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("package_scans", sa.Column("username", sa.String(128), nullable=True))
    op.execute(
        "UPDATE package_scans s SET username = u.username "
        "FROM users u WHERE s.user_id = u.id AND s.username IS NULL"
    )


def downgrade() -> None:
    op.drop_column("package_scans", "username")
