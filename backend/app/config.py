"""Application configuration management."""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings

# Base directory for the application (backend folder)
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Environment
    environment: str = "development"  # development, staging, production

    # Application
    app_name: str = "Threat Detection Explorer"
    debug: bool = True  # Enable debug logging

    # Database
    # For local development: sqlite+aiosqlite:///path/to/db.sqlite
    # For production: postgresql+asyncpg://user:password@host:port/database
    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'threat_detection.db'}"

    # Repository paths
    data_dir: Path = BASE_DIR / "data"
    repos_dir: Path = BASE_DIR / "data" / "repos"

    # Repository URLs
    sigma_repo_url: str = "https://github.com/SigmaHQ/sigma.git"
    elastic_repo_url: str = "https://github.com/elastic/detection-rules.git"
    splunk_repo_url: str = "https://github.com/splunk/security_content.git"
    sublime_repo_url: str = "https://github.com/sublime-security/sublime-rules.git"
    elastic_protections_repo_url: str = "https://github.com/elastic/protections-artifacts.git"
    lolrmm_repo_url: str = "https://github.com/magicsword-io/LOLRMM.git"

    # API settings
    api_prefix: str = "/api"

    # CORS settings - comma-separated list for env var, or list in code
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Scheduler settings
    enable_scheduler: bool = True  # Enable/disable automatic sync
    sync_schedule_hour: int = 2  # Hour to run daily sync (UTC)
    sync_schedule_minute: int = 0  # Minute to run daily sync

    # Frontend URL (for CORS in production)
    frontend_url: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        # Allow environment variables to override
        extra = "ignore"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Add frontend URL to CORS origins if set
        if self.frontend_url and self.frontend_url not in self.cors_origins:
            self.cors_origins.append(self.frontend_url)
        # In production, be more restrictive about debug
        if self.environment == "production":
            self.debug = False

    def get_repo_path(self, repo_name: str) -> Path:
        """Get the local path for a repository."""
        return self.repos_dir / repo_name

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"


settings = Settings()
