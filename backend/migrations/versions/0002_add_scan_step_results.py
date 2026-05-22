"""Add scan_step_results table

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-21
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "scan_step_results" not in existing:
        op.create_table(
            "scan_step_results",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("scan_id", sa.Uuid(), nullable=False),
            sa.Column("step", sa.String(64), nullable=False),
            sa.Column("data", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("scan_id", "step", name="uq_scan_step"),
        )
        op.create_index("ix_scan_step_results_id", "scan_step_results", ["id"], unique=False)
        op.create_index("ix_scan_step_results_scan_id", "scan_step_results", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_table("scan_step_results")
