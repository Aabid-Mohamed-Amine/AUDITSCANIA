import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Uuid, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


class ScanStepResult(Base):
    __tablename__ = "scan_step_results"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step = Column(String(64), nullable=False)
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="step_results")

    __table_args__ = (
        UniqueConstraint("scan_id", "step", name="uq_scan_step"),
    )

    def __repr__(self) -> str:
        return f"<ScanStepResult scan_id={self.scan_id} step={self.step}>"
