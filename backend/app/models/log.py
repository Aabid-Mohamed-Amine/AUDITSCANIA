import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Uuid
from sqlalchemy.orm import relationship

from app.database import Base


class ScanLog(Base):
    __tablename__ = "logs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    level = Column(String(16), nullable=False, default="info")  # info | warning | error
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="logs")

    def __repr__(self) -> str:
        return f"<ScanLog scan_id={self.scan_id} level={self.level}>"
