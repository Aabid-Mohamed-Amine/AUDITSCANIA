import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Text, DateTime, Enum as SAEnum, JSON, Uuid, ForeignKey, Boolean,
)
from sqlalchemy.orm import relationship
from app.database import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    user_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target = Column(String(255), nullable=False, index=True)
    status = Column(
        SAEnum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.pending,
    )
    progress = Column(Integer, nullable=False, default=0)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    # Results (stored as JSON blobs)
    shodan_data = Column(JSON, nullable=True)
    virustotal_data = Column(JSON, nullable=True)
    abuseipdb_data = Column(JSON, nullable=True)
    nmap_data = Column(JSON, nullable=True)
    nuclei_data = Column(JSON, nullable=True)
    zap_data = Column(JSON, nullable=True)

    # Correlation Engine + SOC output
    correlated_data = Column(JSON, nullable=True)   # CorrelationReport (fast access)
    soc_report = Column(JSON, nullable=True)         # SOC Dashboard report

    # Active pipeline phase label (for live UI)
    current_phase = Column(String(64), nullable=True)

    # Enhanced scanner outputs (v2)
    subfinder_data    = Column(JSON, nullable=True)
    dalfox_data       = Column(JSON, nullable=True)
    fp_reduction_data = Column(JSON, nullable=True)

    # New scanners (v3)
    ffuf_data         = Column(JSON, nullable=True)
    sqlmap_data       = Column(JSON, nullable=True)
    gitleaks_data     = Column(JSON, nullable=True)
    katana_data       = Column(JSON, nullable=True)  # Phase 3 JS/SPA crawler (added 0006)

    # AI analysis
    ai_analysis      = Column(Text, nullable=True)
    ai_analysis_data = Column(JSON, nullable=True)

    # Auth detection result (stored after Phase 1.5 — no credentials stored)
    auth_config = Column(JSON, nullable=True)

    # Risk score 0-100 (computed after all recon)
    risk_score = Column(Integer, nullable=True)

    # Detection mode toggle (lab_mode=True → Lab Challenge API hints enabled)
    lab_mode = Column(Boolean, nullable=False, default=True, server_default="true")

    # Error message if status == failed
    error_message = Column(Text, nullable=True)

    recon_result = relationship("ReconnaissanceResult", back_populates="scan", uselist=False, passive_deletes=True)
    logs = relationship("ScanLog", back_populates="scan", order_by="ScanLog.created_at", passive_deletes=True)
    step_results = relationship("ScanStepResult", back_populates="scan", passive_deletes=True)

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target} status={self.status}>"
