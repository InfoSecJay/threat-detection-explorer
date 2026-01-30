"""Detection rule ingestion service."""

import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.detection import Detection
from app.models.repository import Repository
from app.parsers import (
    SigmaParser, ElasticParser, SplunkParser,
    SublimeParser, ElasticProtectionsParser, LOLRMMParser,
    ElasticHuntingParser, BaseParser
)
from app.normalizers import (
    SigmaNormalizer, ElasticNormalizer, SplunkNormalizer,
    SublimeNormalizer, ElasticProtectionsNormalizer, LOLRMMNormalizer,
    ElasticHuntingNormalizer, BaseNormalizer, NormalizedDetection
)
from app.services.rule_discovery import RuleDiscoveryService
from app.services.ingestion_errors import (
    IngestionStats, ErrorStage, ErrorSeverity
)

logger = logging.getLogger(__name__)


class IngestionService:
    """Service for ingesting detection rules into the database."""

    def __init__(self, db: AsyncSession):
        """Initialize ingestion service with database session."""
        self.db = db
        self.discovery = RuleDiscoveryService()

        # Initialize parsers
        self.parsers: dict[str, BaseParser] = {
            "sigma": SigmaParser(),
            "elastic": ElasticParser(),
            "splunk": SplunkParser(),
            "sublime": SublimeParser(),
            "elastic_protections": ElasticProtectionsParser(),
            "lolrmm": LOLRMMParser(),
            "elastic_hunting": ElasticHuntingParser(),
        }

        # Initialize normalizers
        self.normalizers: dict[str, BaseNormalizer] = {
            "sigma": SigmaNormalizer(settings.sigma_repo_url),
            "elastic": ElasticNormalizer(settings.elastic_repo_url),
            "splunk": SplunkNormalizer(settings.splunk_repo_url),
            "sublime": SublimeNormalizer(settings.sublime_repo_url),
            "elastic_protections": ElasticProtectionsNormalizer(settings.elastic_protections_repo_url),
            "lolrmm": LOLRMMNormalizer(settings.lolrmm_repo_url),
            "elastic_hunting": ElasticHuntingNormalizer(settings.elastic_hunting_repo_url),
        }

    async def ingest_repository(self, repo_name: str) -> IngestionStats:
        """Ingest all detection rules from a repository.

        Args:
            repo_name: Name of the repository (sigma, elastic, splunk, etc.)

        Returns:
            IngestionStats with detailed statistics and error information
        """
        parser = self.parsers.get(repo_name)
        normalizer = self.normalizers.get(repo_name)

        if not parser or not normalizer:
            raise ValueError(f"Unknown repository: {repo_name}")

        stats = IngestionStats()
        stats.start_time = datetime.utcnow()

        logger.info(f"Starting ingestion for {repo_name}")

        # Clear existing rules for this repository
        await self._clear_repository_rules(repo_name)

        # Discover and process rules
        rules_to_store: list[Detection] = []
        batch_size = 100

        for relative_path in self.discovery.discover_rules(repo_name):
            stats.discovered += 1

            # Read file content
            content = self.discovery.get_rule_content(repo_name, relative_path)
            if content is None:
                stats.add_error(
                    file_path=relative_path,
                    stage=ErrorStage.READ,
                    message="Failed to read file content",
                    severity=ErrorSeverity.ERROR
                )
                continue

            # Check if parser can handle this file
            full_path = settings.get_repo_path(repo_name) / relative_path
            if not parser.can_parse(full_path):
                stats.skipped_by_filter += 1
                continue

            # Parse rule
            try:
                parsed = parser.parse(relative_path, content)
                if parsed is None:
                    stats.add_error(
                        file_path=relative_path,
                        stage=ErrorStage.PARSE,
                        message="Parser returned None (missing required fields or invalid format)",
                        severity=ErrorSeverity.WARNING
                    )
                    continue
                stats.parsed += 1
            except Exception as e:
                stats.add_error(
                    file_path=relative_path,
                    stage=ErrorStage.PARSE,
                    message=f"Parse exception: {type(e).__name__}: {str(e)}",
                    details=traceback.format_exc(),
                    severity=ErrorSeverity.ERROR
                )
                continue

            # Normalize rule
            try:
                normalized = normalizer.normalize(parsed)
                stats.normalized += 1

                # Convert to database model
                detection = self._to_detection_model(normalized)
                rules_to_store.append(detection)

                # Batch insert
                if len(rules_to_store) >= batch_size:
                    stored_count = await self._store_rules_safe(rules_to_store, stats)
                    stats.stored += stored_count
                    rules_to_store = []

            except Exception as e:
                stats.add_error(
                    file_path=relative_path,
                    stage=ErrorStage.NORMALIZE,
                    message=f"Normalization exception: {type(e).__name__}: {str(e)}",
                    details=traceback.format_exc(),
                    severity=ErrorSeverity.ERROR
                )

        # Store remaining rules
        if rules_to_store:
            stored_count = await self._store_rules_safe(rules_to_store, stats)
            stats.stored += stored_count

        # Update repository rule count
        await self._update_repository_count(repo_name, stats.stored)

        stats.end_time = datetime.utcnow()

        logger.info(
            f"Ingestion complete for {repo_name}: "
            f"discovered={stats.discovered}, parsed={stats.parsed}, "
            f"stored={stats.stored}, errors={stats.error_count}, "
            f"warnings={stats.warning_count}, "
            f"success_rate={stats.success_rate:.1f}%"
        )

        return stats

    async def _clear_repository_rules(self, repo_name: str) -> None:
        """Clear all rules for a repository before re-ingestion."""
        await self.db.execute(
            delete(Detection).where(Detection.source == repo_name)
        )
        await self.db.commit()

    async def _store_rules_safe(
        self,
        rules: list[Detection],
        stats: IngestionStats
    ) -> int:
        """Store a batch of rules to the database with error handling.

        Returns the number of rules successfully stored.
        """
        stored = 0
        for rule in rules:
            try:
                self.db.add(rule)
                stored += 1
            except Exception as e:
                stats.add_error(
                    file_path=rule.source_file,
                    stage=ErrorStage.STORE,
                    message=f"Database error: {type(e).__name__}: {str(e)}",
                    severity=ErrorSeverity.ERROR
                )

        try:
            await self.db.commit()
        except Exception as e:
            logger.error(f"Batch commit failed: {e}")
            await self.db.rollback()
            # Try to store rules one by one
            stored = 0
            for rule in rules:
                try:
                    self.db.add(rule)
                    await self.db.commit()
                    stored += 1
                except Exception as inner_e:
                    await self.db.rollback()
                    stats.add_error(
                        file_path=rule.source_file,
                        stage=ErrorStage.STORE,
                        message=f"Individual store failed: {type(inner_e).__name__}: {str(inner_e)}",
                        severity=ErrorSeverity.ERROR
                    )

        return stored

    async def _update_repository_count(self, repo_name: str, count: int) -> None:
        """Update the rule count for a repository."""
        result = await self.db.execute(
            select(Repository).where(Repository.name == repo_name)
        )
        repo = result.scalar_one_or_none()
        if repo:
            repo.rule_count = count
            await self.db.commit()

    def _to_detection_model(self, normalized: NormalizedDetection) -> Detection:
        """Convert normalized detection to database model."""
        return Detection(
            id=normalized.id,
            source=normalized.source,
            source_file=normalized.source_file,
            source_repo_url=normalized.source_repo_url,
            source_rule_url=normalized.source_rule_url,
            rule_id=normalized.rule_id,
            title=normalized.title,
            description=normalized.description,
            author=normalized.author,
            status=normalized.status,
            severity=normalized.severity,
            log_sources=normalized.log_sources,
            data_sources=normalized.data_sources,
            # Standardized taxonomy fields
            platform=normalized.platform,
            event_category=normalized.event_category,
            data_source_normalized=normalized.data_source_normalized,
            mitre_tactics=normalized.mitre_tactics,
            mitre_techniques=normalized.mitre_techniques,
            detection_logic=normalized.detection_logic,
            language=normalized.language,
            tags=normalized.tags,
            references=normalized.references,
            false_positives=normalized.false_positives,
            raw_content=normalized.raw_content,
            rule_created_date=normalized.rule_created_date,
            rule_modified_date=normalized.rule_modified_date,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

    async def get_ingestion_stats(self) -> dict:
        """Get overall ingestion statistics."""
        stats = {}

        # Count detections per source
        for source in ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm", "elastic_hunting"]:
            result = await self.db.execute(
                select(Detection).where(Detection.source == source)
            )
            stats[source] = len(result.scalars().all())

        stats["total"] = sum(stats.values())
        return stats
