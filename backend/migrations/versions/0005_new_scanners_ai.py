"""0005 — FFUF, SQLMap, GitLeaks, AI analysis columns

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _add_column_if_missing(table: str, column: str, col_type) -> None:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    )
    if result.fetchone() is None:
        op.add_column(table, sa.Column(column, col_type, nullable=True))


def upgrade() -> None:
    for col in ("ffuf_data", "sqlmap_data", "gitleaks_data", "ai_analysis_data"):
        _add_column_if_missing("scans", col, JSON())
        _add_column_if_missing("reconnaissance_results", col, JSON())


def downgrade() -> None:
    for col in ("ffuf_data", "sqlmap_data", "gitleaks_data", "ai_analysis_data"):
        for table in ("scans", "reconnaissance_results"):
            op.drop_column(table, col)
