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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8   # 8h
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---- External APIs ----
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # ---- Frontend / CORS ----
    FRONTEND_URL: str = "http://localhost:3001"
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:3001"

    # ---- Scanner microservices ----
    NMAP_URL: str = "http://nmap:9000"
    NUCLEI_URL: str = "http://nuclei:9001"
    ZAP_URL: str = "http://zap:9002"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
