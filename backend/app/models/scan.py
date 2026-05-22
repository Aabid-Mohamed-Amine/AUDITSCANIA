import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Text, DateTime, Enum as SAEnum, JSON, Uuid, ForeignKey,
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

    # AI analysis
    ai_analysis = Column(Text, nullable=True)

    # Risk score 0-100 (computed after all recon)
    risk_score = Column(Integer, nullable=True)

    # Error message if status == failed
    error_message = Column(Text, nullable=True)

    recon_result = relationship("ReconnaissanceResult", back_populates="scan", uselist=False, passive_deletes=True)
    logs = relationship("ScanLog", back_populates="scan", order_by="ScanLog.created_at", passive_deletes=True)
    step_results = relationship("ScanStepResult", back_populates="scan", passive_deletes=True)

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target} status={self.status}>"
