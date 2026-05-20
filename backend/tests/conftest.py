import os
import pytest
from unittest.mock import AsyncMock, patch

# Must be set before any app import so pydantic-settings picks them up
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_KEY", "ci-test-secret-key-not-for-production")
os.environ.setdefault("SHODAN_API_KEY", "dummy")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "dummy")
os.environ.setdefault("ABUSEIPDB_API_KEY", "dummy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

_TEST_DB_URL = "sqlite:///./test.db"
_engine = create_engine(_TEST_DB_URL, connect_args={"check_same_thread": False})
_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    from app.models import user, scan, recon_result, log  # noqa: F401
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)
    _engine.dispose()
    try:
        if os.path.exists("test.db"):
            os.remove("test.db")
    except PermissionError:
        pass  # Windows: file still locked by SQLite; GC will release it


@pytest.fixture
def client(setup_test_db):
    def _override_get_db():
        db = _SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db

    with patch("app.api.websocket._redis_listener", new=AsyncMock(return_value=None)):
        with TestClient(app) as c:
            yield c

    app.dependency_overrides.clear()
