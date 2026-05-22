import uuid
from datetime import datetime

from sqlalchemy import Column, Integer, DateTime, ForeignKey, JSON, Float, Uuid
from sqlalchemy.orm import relationship

from app.database import Base


class ReconnaissanceResult(Base):
    __tablename__ = "reconnaissance_results"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    shodan_data = Column(JSON, nullable=True)
    virustotal_data = Column(JSON, nullable=True)
    abuseipdb_data = Column(JSON, nullable=True)
    nmap_data = Column(JSON, nullable=True)
    nuclei_data = Column(JSON, nullable=True)
    zap_data = Column(JSON, nullable=True)

    risk_score = Column(Integer, nullable=True)
    abuseipdb_score = Column(Float, nullable=True)
    virustotal_score = Column(Float, nullable=True)
    port_exposure_score = Column(Float, nullable=True)
    nuclei_score = Column(Float, nullable=True)
    zap_score = Column(Float, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="recon_result")

    def __repr__(self) -> str:
        return f"<ReconResult scan_id={self.scan_id} risk={self.risk_score}>"
