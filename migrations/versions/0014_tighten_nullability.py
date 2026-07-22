"""tighten nullability: add the NOT NULLs the models declare but 0001/0008 missed

Found by tests/integration/test_migration_drift.py: these columns were created
with server defaults but without nullable=False, so the deployed schema accepts
NULLs the models (and app code) assume can't exist. NULLs are backfilled first —
none should exist, since every insert path supplies a value or hits the server
default — then the constraint is added.

Statements are batched per table: one COALESCE UPDATE covering all its columns,
then one ALTER TABLE with every SET NOT NULL, so each table pays a single
ACCESS EXCLUSIVE acquisition and a single validation scan instead of one per
column (env.py runs the whole upgrade in one transaction, so per-column locks
would pile up across every later statement).

Revision ID: 0014_tighten_nullability
Revises: 0013_notification_log
Create Date: 2026-07-22
"""
from alembic import op

revision = "0014_tighten_nullability"
down_revision = "0013_notification_log"
branch_labels = None
depends_on = None

# table -> {column: SQL literal used to backfill any NULLs}
_TABLES = {
    "assets": {
        "asset_metadata": "'{}'::jsonb",
        "created_at": "now()",
        "updated_at": "now()",
    },
    "connector_runs": {"findings_count": "0"},
    "error_logs": {"created_at": "now()"},
    "findings": {
        "cve_ids": "'[]'::jsonb",
        "cwe_ids": "'[]'::jsonb",
        "location": "'{}'::jsonb",
        "refs": "'[]'::jsonb",
        "tags": "'{}'::jsonb",
        "raw": "'{}'::jsonb",
        "created_at": "now()",
        "updated_at": "now()",
    },
    "users": {"created_at": "now()"},
}


def upgrade() -> None:
    # Fail fast if another session holds a table lock, instead of queueing our
    # ACCESS EXCLUSIVE behind it and wedging all traffic on that table (SET
    # LOCAL is scoped to the migration transaction).
    op.execute("SET LOCAL lock_timeout = '10s'")
    for table, cols in _TABLES.items():
        sets = ", ".join(f"{c} = COALESCE({c}, {fill})" for c, fill in cols.items())
        nulls = " OR ".join(f"{c} IS NULL" for c in cols)
        op.execute(f"UPDATE {table} SET {sets} WHERE {nulls}")
        alters = ", ".join(f"ALTER COLUMN {c} SET NOT NULL" for c in cols)
        op.execute(f"ALTER TABLE {table} {alters}")


def downgrade() -> None:
    for table, cols in _TABLES.items():
        alters = ", ".join(f"ALTER COLUMN {c} DROP NOT NULL" for c in cols)
        op.execute(f"ALTER TABLE {table} {alters}")
