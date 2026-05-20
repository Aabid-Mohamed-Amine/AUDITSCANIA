from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Database ----
    DATABASE_URL: str = "postgresql://auditscan:auditscan_secret@postgres:5432/auditscan_db"

    # ---- Redis / Celery ----
    REDIS_URL: str = "redis://redis:6379/0"

    # ---- Security / JWT ----
    SECRET_KEY: str = "change_me_to_a_long_random_string"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24h

    # ---- External APIs ----
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # ---- Frontend ----
    FRONTEND_URL: str = "http://localhost:3000"

    # ---- Nmap Docker container name ----
    NMAP_CONTAINER_NAME: str = "auditscan-nmap-1"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
