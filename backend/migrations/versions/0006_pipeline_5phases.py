"""0006 — Pipeline 5 phases: katana_data persistence + idempotent safety checks

Contexte :
  - La refactorisation du pipeline en 5 phases (2026-06-02) ne nécessite PAS
    de nouvelle colonne pour soc_report.phases_summary.phase_3_exploitation :
    ces données vivent déjà dans le blob JSON soc_report (existant depuis 0003).
  - En revanche, katana_data (Phase 3 — crawler JS/SPA) n'était stocké qu'en
    Redis (pipeline context). Cette migration le persiste en DB pour éviter
    toute perte en cas de flush Redis.
  - La migration est idempotente : _add_column_if_missing vérifie l'existence
    avant chaque ADD COLUMN.

Adds:
  scans: katana_data (JSON)

Ensures (idempotent safety for migration 0005 targets):
  scans:                 ffuf_data, sqlmap_data, gitleaks_data, ai_analysis_data
  reconnaissance_results: ffuf_data, sqlmap_data, gitleaks_data, ai_analysis_data

Downgrade: no-op (data preservation > schema rollback in production).

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision      = "0006"
down_revision = "0005"
branch_labels = None
depends_on    = None


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    """Idempotent ADD COLUMN — safe to run multiple times on any environment."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = {c["name"] for c in insp.get_columns(table)}
    if column.name not in existing:
        op.add_column(table, column)


def upgrade() -> None:
    # ── scans — NEW: katana_data ──────────────────────────────────────────────
    # Katana (Phase 3 JS/SPA crawler) results were only cached in Redis.
    # Persisted here so raw crawl data survives Redis flushes and is available
    # for re-correlation without re-running the scan.
    _add_column_if_missing("scans", sa.Column("katana_data", sa.JSON(), nullable=True))

    # ── scans — idempotent safety (should exist from 0005) ────────────────────
    for col in ("ffuf_data", "sqlmap_data", "gitleaks_data", "ai_analysis_data"):
        _add_column_if_missing("scans", sa.Column(col, sa.JSON(), nullable=True))

    # ── reconnaissance_results — idempotent safety ────────────────────────────
    # 0005 added these to the DB; verify they exist on all environments.
    for col in ("ffuf_data", "sqlmap_data", "gitleaks_data", "ai_analysis_data"):
        _add_column_if_missing(
            "reconnaissance_results",
            sa.Column(col, sa.JSON(), nullable=True),
        )


def downgrade() -> None:
    # Intentional no-op: dropping JSON columns risks data loss in production.
    # To rollback: rename columns manually via a DBA script if absolutely needed.
    pass
