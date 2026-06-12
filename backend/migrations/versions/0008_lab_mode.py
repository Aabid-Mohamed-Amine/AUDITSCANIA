"""0008 — Lab mode toggle: lab_mode column

Adds a boolean flag to control whether the Lab Challenge API
is used during Phase 3. True = current behaviour (use API hints).
False = pure active detection (no application-side hints).

Adds:
  scans: lab_mode (Boolean, default True)

Downgrade: no-op (data preservation policy).

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision      = "0008"
down_revision = "0007"
branch_labels = None
depends_on    = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = {c["name"] for c in insp.get_columns(table)}
    if column.name not in existing:
        op.add_column(table, column)


def upgrade() -> None:
    _add_column_if_missing(
        "scans",
        sa.Column("lab_mode", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
    )


def downgrade() -> None:
    pass
