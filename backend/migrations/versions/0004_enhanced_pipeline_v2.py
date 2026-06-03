"""
0004 — Enhanced Pipeline v2: Subfinder, Dalfox, FP Engine columns

Adds:
  scans:               subfinder_data, dalfox_data, fp_reduction_data
  reconnaissance_results: subfinder_data, dalfox_data, fp_reduction_data,
                           fp_reduction_rate, false_positive_count
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision  = "0004"
down_revision = "0003"
branch_labels = None
depends_on    = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    """Idempotent column addition — safe to run multiple times."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = {c["name"] for c in insp.get_columns(table)}
    if column.name not in existing:
        op.add_column(table, column)


def upgrade() -> None:
    # ── scans ──────────────────────────────────────────────────────────────
    _add_column_if_missing("scans", sa.Column("subfinder_data",    sa.JSON(), nullable=True))
    _add_column_if_missing("scans", sa.Column("dalfox_data",       sa.JSON(), nullable=True))
    _add_column_if_missing("scans", sa.Column("fp_reduction_data", sa.JSON(), nullable=True))

    # ── reconnaissance_results ─────────────────────────────────────────────
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("subfinder_data", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("dalfox_data", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("fp_reduction_data", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("fp_reduction_rate", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("false_positive_count", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    # Downgrade is intentionally left as no-op to avoid data loss in production.
    pass
