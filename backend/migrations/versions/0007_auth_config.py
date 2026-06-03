"""0007 — Generic authentication system: auth_config column

Contexte :
  - Ajout d'un système d'authentification générique (Phase 1.5 du pipeline).
  - L'auth_manager détecte le type d'auth (none, jwt_bearer, session_cookie,
    form_login, http_basic), effectue le login si des credentials sont fournis,
    puis propage headers/cookies à tous les scanners (ZAP, Nuclei, FFUF, SQLMap).
  - Cette colonne stocke le RÉSULTAT de la détection (auth_type, headers/cookies
    injectés, login_url, notes). Les credentials bruts (password) ne sont JAMAIS
    persistés — ils transitent uniquement vers le worker Celery.
  - Idempotente : _add_column_if_missing vérifie l'existence avant ADD COLUMN.

Adds:
  scans: auth_config (JSON)

Downgrade: no-op (data preservation > schema rollback in production).

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision      = "0007"
down_revision = "0006"
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
    # ── scans — NEW: auth_config ──────────────────────────────────────────────
    # Stores the AuthContext produced by Phase 1.5 (auth detection + login).
    # Contains injected headers/cookies, detected auth_type, login_url, notes.
    # Raw passwords are never stored here.
    _add_column_if_missing("scans", sa.Column("auth_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    # Intentional no-op: dropping JSON columns risks data loss in production.
    pass
