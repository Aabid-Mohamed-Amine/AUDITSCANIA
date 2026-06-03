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
    NMAP_URL:      str = "http://nmap:9000"
    NUCLEI_URL:    str = "http://nuclei:9001"
    ZAP_URL:       str = "http://zap:9002"
    SUBFINDER_URL: str = "http://subfinder:9003"
    DALFOX_URL:    str = "http://dalfox:9004"
    TRIVY_URL:     str = "http://trivy:9005"
    FFUF_URL:      str = "http://ffuf:9006"
    SQLMAP_URL:    str = "http://sqlmap:9007"
    GITLEAKS_URL:  str = "http://gitleaks:9008"
    KATANA_URL:    str = "http://katana:9009"

    # ---- False Positive Engine ----
    FP_IGNORE_LOW_CONFIDENCE: bool = True
    FP_REQUIRE_ACTIVE_SOURCE: bool = True

    # ---- Auto Authentication ----
    # Si True et qu'aucun credential n'est fourni, le scanner tente
    # automatiquement : (1) enregistrer un compte aléatoire puis se connecter,
    # (2) tester des credentials par défaut (admin:admin, etc.).
    AUTO_AUTH_ENABLED: bool = True

    # ---- AI Analysis (optional) ----
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    AI_ANALYSIS_ENABLED: bool = False
    # Modèles supportés (vérifié juin 2026) :
    # gemini-2.5-flash (recommandé, gratuit) · gemini-2.0-flash-lite · gemini-1.5-flash
    AI_MODEL: str = "gemini-2.5-flash"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
