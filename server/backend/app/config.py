from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment/.env."""

    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite+aiosqlite:///./olopa_waitlist.db"
    cors_origins: str = "*"
    waitlist_rate_limit_per_hour: int = 5
    clickhouse_url: str = "http://localhost:8123"
    clickhouse_username: str = "default"
    clickhouse_password: str = ""
    clickhouse_database: str = "default"
    clickhouse_secure: bool = False
    ingest_queue_maxsize: int = 2000
    ingest_flush_interval_ms: int = 250
    ingest_flush_max_rows: int = 10000
    ingest_default_retry_after_ms: int = 500
    ingest_suggested_batch_bytes: int = 4_000_000
    telemetry_enabled: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Return singleton settings object for dependency injection."""
    return Settings()
