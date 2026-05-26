"""Professional pipeline: correlation engine + enhanced risk scoring columns

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-23
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {c["name"] for c in inspector.get_columns(table)}
    if column.name not in existing_cols:
        op.add_column(table, column)


def upgrade() -> None:
    # ── reconnaissance_results : Correlation Engine columns ─────────────────
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("correlated_data", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("exploitability_score", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("confidence_score", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("correlation_score", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("risk_component_scores", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("threat_intelligence_factor", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("cve_severity_factor", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("service_exposure_factor", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "reconnaissance_results",
        sa.Column("soc_report", sa.JSON(), nullable=True),
    )

    # ── scans : Correlation + SOC columns ───────────────────────────────────
    _add_column_if_missing(
        "scans",
        sa.Column("correlated_data", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "scans",
        sa.Column("soc_report", sa.JSON(), nullable=True),
    )
    _add_column_if_missing(
        "scans",
        sa.Column("current_phase", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    for col in [
        "correlated_data", "soc_report", "current_phase",
    ]:
        op.drop_column("scans", col)

    for col in [
        "correlated_data", "exploitability_score", "confidence_score",
        "correlation_score", "risk_component_scores",
        "threat_intelligence_factor", "cve_severity_factor",
        "service_exposure_factor", "soc_report",
    ]:
        op.drop_column("reconnaissance_results", col)
