"""Application configuration loaded from environment variables / .env file."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    secret_key: str = "change-me-in-production"
    host: str = "127.0.0.1"
    port: int = 8000

    database_url: str = "postgresql+psycopg2://postgres:sentryscan_dev@localhost:5432/sentryscan"

    nmap_path: str = "nmap"
    hydra_path: str = "hydra"

    # Safety: nothing outside this allow-list may ever be scanned or credential-tested.
    authorized_targets: str = "127.0.0.1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    enable_live_scans: bool = False

    @property
    def authorized_targets_list(self) -> list[str]:
        return [t.strip() for t in self.authorized_targets.split(",") if t.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
