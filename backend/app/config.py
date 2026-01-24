"""Application configuration management."""

from pathlib import Path
from pydantic_settings import BaseSettings

# Base directory for the application (backend folder)
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Threat Detection Explorer"
    debug: bool = True  # Enable debug logging

    # Database - use absolute path
    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'threat_detection.db'}"

    # Repository paths - use absolute paths
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

    # CORS settings
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Scheduler settings
    enable_scheduler: bool = True  # Enable/disable automatic sync
    sync_schedule_hour: int = 2  # Hour to run daily sync (UTC)
    sync_schedule_minute: int = 0  # Minute to run daily sync

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def get_repo_path(self, repo_name: str) -> Path:
        """Get the local path for a repository."""
        return self.repos_dir / repo_name


settings = Settings()
