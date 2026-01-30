"""Repository synchronization service."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from git import Repo, GitCommandError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.repository import Repository

logger = logging.getLogger(__name__)


class RepositorySyncService:
    """Service for managing git repository synchronization."""

    REPO_CONFIGS = {
        "sigma": {
            "url": settings.sigma_repo_url,
            "name": "sigma",
        },
        "elastic": {
            "url": settings.elastic_repo_url,
            "name": "elastic",
        },
        "splunk": {
            "url": settings.splunk_repo_url,
            "name": "splunk",
        },
        "sublime": {
            "url": settings.sublime_repo_url,
            "name": "sublime",
        },
        "elastic_protections": {
            "url": settings.elastic_protections_repo_url,
            "name": "elastic_protections",
        },
        "lolrmm": {
            "url": settings.lolrmm_repo_url,
            "name": "lolrmm",
        },
        "elastic_hunting": {
            "url": settings.elastic_hunting_repo_url,
            "name": "elastic_hunting",
        },
    }

    def __init__(self, db: AsyncSession):
        """Initialize sync service with database session."""
        self.db = db

    async def get_repository(self, name: str) -> Optional[Repository]:
        """Get repository metadata by name."""
        result = await self.db.execute(
            select(Repository).where(Repository.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_repositories(self) -> list[Repository]:
        """Get all repository metadata."""
        result = await self.db.execute(select(Repository))
        return list(result.scalars().all())

    async def ensure_repository_exists(self, name: str) -> Repository:
        """Ensure repository metadata exists in database, creating if needed."""
        repo = await self.get_repository(name)
        if repo:
            return repo

        config = self.REPO_CONFIGS.get(name)
        if not config:
            raise ValueError(f"Unknown repository: {name}")

        repo = Repository(
            name=name,
            url=config["url"],
            status="idle",
            rule_count=0,
        )
        self.db.add(repo)
        await self.db.commit()
        await self.db.refresh(repo)
        return repo

    async def sync_repository(self, name: str) -> tuple[bool, str]:
        """Synchronize a repository from GitHub.

        Args:
            name: Repository name (sigma, elastic, splunk)

        Returns:
            Tuple of (success, message)
        """
        config = self.REPO_CONFIGS.get(name)
        if not config:
            return False, f"Unknown repository: {name}"

        repo_db = await self.ensure_repository_exists(name)
        repo_path = settings.get_repo_path(name)

        try:
            # Update status to syncing
            repo_db.status = "syncing"
            repo_db.error_message = None
            await self.db.commit()

            if repo_path.exists():
                # For shallow clones, delete and re-clone to get latest changes
                # This is more reliable than trying to pull shallow clones
                import shutil
                logger.info(f"Removing existing repo at {repo_path} for fresh clone")
                shutil.rmtree(repo_path)

            # Clone repository (fresh clone ensures we have latest)
            commit_hash = await self._clone_repository(config["url"], repo_path)
            message = f"Cloned {name} repository"

            # Update repository metadata
            repo_db.last_commit_hash = commit_hash
            repo_db.last_sync_at = datetime.utcnow()
            repo_db.status = "idle"
            await self.db.commit()

            logger.info(f"{message} (commit: {commit_hash[:8]})")
            return True, message

        except GitCommandError as e:
            error_msg = f"Git error: {str(e)}"
            logger.error(f"Failed to sync {name}: {error_msg}")
            repo_db.status = "error"
            repo_db.error_message = error_msg
            await self.db.commit()
            return False, error_msg

        except Exception as e:
            error_msg = f"Sync error: {str(e)}"
            logger.error(f"Failed to sync {name}: {error_msg}")
            repo_db.status = "error"
            repo_db.error_message = error_msg
            await self.db.commit()
            return False, error_msg

    async def _clone_repository(self, url: str, path: Path) -> str:
        """Clone a git repository.

        Args:
            url: Repository URL
            path: Local path to clone to

        Returns:
            Current commit hash
        """
        logger.info(f"Cloning {url} to {path}")
        path.parent.mkdir(parents=True, exist_ok=True)

        # Clone with depth=1 for faster initial clone
        repo = Repo.clone_from(url, path, depth=1)
        return repo.head.commit.hexsha

    async def _pull_repository(self, path: Path) -> str:
        """Pull updates for an existing repository.

        Args:
            path: Local repository path

        Returns:
            Current commit hash after pull
        """
        logger.info(f"Pulling updates for {path}")
        repo = Repo(path)

        # Just get the current commit - don't pull for shallow clones
        # as it can cause issues
        try:
            origin = repo.remotes.origin
            origin.fetch()
        except Exception as e:
            logger.warning(f"Fetch failed (may be shallow clone): {e}")

        return repo.head.commit.hexsha

    def get_repo_path(self, name: str) -> Path:
        """Get the local path for a repository."""
        return settings.get_repo_path(name)

    def get_current_commit(self, name: str) -> Optional[str]:
        """Get the current commit hash for a repository."""
        repo_path = self.get_repo_path(name)
        if not repo_path.exists():
            return None

        try:
            repo = Repo(repo_path)
            return repo.head.commit.hexsha
        except Exception:
            return None
