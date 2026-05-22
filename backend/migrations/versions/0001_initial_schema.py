"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-21

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    if "users" not in existing:
        op.create_table(
            "users",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("hashed_password", sa.String(255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("is_superuser", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_users_id", "users", ["id"], unique=False)
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ------------------------------------------------------------------
    # scans
    # ------------------------------------------------------------------
    # Use raw SQL to avoid SQLAlchemy re-creating the enum via _on_table_create
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed');
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END $$;
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          UUID        NOT NULL PRIMARY KEY,
            user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            target      VARCHAR(255) NOT NULL,
            status      scan_status NOT NULL,
            progress    INTEGER     NOT NULL,
            created_at  TIMESTAMP   NOT NULL,
            updated_at  TIMESTAMP   NOT NULL,
            shodan_data     JSON,
            virustotal_data JSON,
            abuseipdb_data  JSON,
            nmap_data       JSON,
            nuclei_data     JSON,
            zap_data        JSON,
            ai_analysis TEXT,
            risk_score  INTEGER,
            error_message TEXT
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_scans_id      ON scans (id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scans_target  ON scans (target)")

    # ------------------------------------------------------------------
    # reconnaissance_results
    # ------------------------------------------------------------------
    if "reconnaissance_results" not in existing:
        op.create_table(
            "reconnaissance_results",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("scan_id", sa.Uuid(), nullable=False),
            sa.Column("shodan_data", sa.JSON(), nullable=True),
            sa.Column("virustotal_data", sa.JSON(), nullable=True),
            sa.Column("abuseipdb_data", sa.JSON(), nullable=True),
            sa.Column("nmap_data", sa.JSON(), nullable=True),
            sa.Column("nuclei_data", sa.JSON(), nullable=True),
            sa.Column("zap_data", sa.JSON(), nullable=True),
            sa.Column("risk_score", sa.Integer(), nullable=True),
            sa.Column("abuseipdb_score", sa.Float(), nullable=True),
            sa.Column("virustotal_score", sa.Float(), nullable=True),
            sa.Column("port_exposure_score", sa.Float(), nullable=True),
            sa.Column("nuclei_score", sa.Float(), nullable=True),
            sa.Column("zap_score", sa.Float(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_reconnaissance_results_id", "reconnaissance_results", ["id"], unique=False
        )
        op.create_index(
            "ix_reconnaissance_results_scan_id",
            "reconnaissance_results",
            ["scan_id"],
            unique=False,
        )

    # ------------------------------------------------------------------
    # logs
    # ------------------------------------------------------------------
    if "logs" not in existing:
        op.create_table(
            "logs",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("scan_id", sa.Uuid(), nullable=False),
            sa.Column("level", sa.String(16), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_logs_id", "logs", ["id"], unique=False)
        op.create_index("ix_logs_scan_id", "logs", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_table("logs")
    op.drop_table("reconnaissance_results")
    op.drop_table("scans")
    op.drop_table("users")
    sa.Enum(name="scan_status").drop(op.get_bind(), checkfirst=True)
