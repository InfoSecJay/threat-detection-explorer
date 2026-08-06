"""Detection rule ingestion service."""

import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.utils.datetime_utils import utcnow

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.detection import Detection
from app.models.repository import Repository
from app.parsers import (
    SigmaParser, ElasticParser, SplunkParser,
    SublimeParser, ElasticProtectionsParser, LOLRMMParser,
    ElasticHuntingParser, SentinelParser, GoogleSecOpsParser,
    OktaParser, Auth0Parser, BaseParser
)
from app.normalizers import (
    SigmaNormalizer, ElasticNormalizer, SplunkNormalizer,
    SublimeNormalizer, ElasticProtectionsNormalizer, LOLRMMNormalizer,
    ElasticHuntingNormalizer, SentinelNormalizer, GoogleSecOpsNormalizer,
    OktaNormalizer, Auth0Normalizer,
    BaseNormalizer, NormalizedDetection
)
from app.services.repository_sync import ALL_REPOSITORY_NAMES
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
            "sentinel": SentinelParser(),
            "google_secops": GoogleSecOpsParser(),
            "okta": OktaParser(),
            "auth0": Auth0Parser(),
        }

        # Initialize normalizers — pass local repo paths so they can fall back
        # to `git log` for rule dates when the source format doesn't embed them.
        self.normalizers: dict[str, BaseNormalizer] = {
            "sigma": SigmaNormalizer(settings.sigma_repo_url, settings.get_repo_path("sigma")),
            "elastic": ElasticNormalizer(settings.elastic_repo_url, settings.get_repo_path("elastic")),
            "splunk": SplunkNormalizer(settings.splunk_repo_url, settings.get_repo_path("splunk")),
            "sublime": SublimeNormalizer(settings.sublime_repo_url, settings.get_repo_path("sublime")),
            "elastic_protections": ElasticProtectionsNormalizer(
                settings.elastic_protections_repo_url,
                settings.get_repo_path("elastic_protections"),
            ),
            "lolrmm": LOLRMMNormalizer(settings.lolrmm_repo_url, settings.get_repo_path("lolrmm")),
            "elastic_hunting": ElasticHuntingNormalizer(
                settings.elastic_hunting_repo_url,
                settings.get_repo_path("elastic_hunting"),
            ),
            "sentinel": SentinelNormalizer(settings.sentinel_repo_url, settings.get_repo_path("sentinel")),
            "google_secops": GoogleSecOpsNormalizer(
                settings.google_secops_repo_url,
                settings.get_repo_path("google_secops"),
            ),
            "okta": OktaNormalizer(
                settings.okta_repo_url,
                settings.get_repo_path("okta"),
            ),
            "auth0": Auth0Normalizer(
                settings.auth0_repo_url,
                settings.get_repo_path("auth0"),
            ),
        }

    async def ingest_repository(self, repo_name: str) -> IngestionStats:
        """Ingest all detection rules from a repository.

        Uses an upsert-then-cleanup pattern so that a mid-ingest crash
        never leaves the database with zero rows for a source. Previously
        this method did DELETE-then-INSERT, which wiped all existing rules
        before inserting new ones — a process crash between those two
        steps left the source empty (this happened to sentinel on
        2026-04-11).

        The new flow:
          1. Record `ingest_start` timestamp.
          2. Upsert every new rule via `session.merge()` (updates existing
             rows by PK, inserts new ones). Each row's `updated_at` is
             set to now(), which is >= `ingest_start`.
          3. After ALL rules are stored, delete stale rows whose
             `updated_at < ingest_start` — these are rules that existed
             in the previous ingest but are no longer in the upstream
             repo (deleted/moved files).
          4. If the process crashes mid-ingest, old rows (from the
             previous successful ingest) coexist with partially-updated
             new rows. No data is lost. The next successful ingest will
             merge everything cleanly and then delete stale rows.

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
        stats.start_time = utcnow()
        ingest_start = stats.start_time

        logger.info(f"Starting ingestion for {repo_name}")

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

                # Taxonomy coverage telemetry (Issue 2). Records whether
                # the canonical resolver found a mapping for this rule,
                # grouped by logsource fingerprint so drift reports
                # collapse identical misses.
                stats.record_taxonomy_result(
                    matched=normalized.taxonomy_matched,
                    fingerprint=normalized.taxonomy_fingerprint,
                    rule_id=normalized.rule_id,
                    source_file=normalized.source_file,
                    title=normalized.title,
                )

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

        # Remove rules that no longer exist in the upstream repo. Any row
        # whose updated_at is older than this ingest's start time was NOT
        # touched by merge() above, meaning its source file has been
        # deleted or moved upstream. Safe to remove.
        await self._cleanup_stale_rules(repo_name, ingest_start)

        # Update repository rule count
        await self._update_repository_count(repo_name, stats.stored)

        stats.end_time = utcnow()

        logger.info(
            f"Ingestion complete for {repo_name}: "
            f"discovered={stats.discovered}, parsed={stats.parsed}, "
            f"stored={stats.stored}, errors={stats.error_count}, "
            f"warnings={stats.warning_count}, "
            f"success_rate={stats.success_rate:.1f}%"
        )

        return stats

    async def _store_rules_safe(
        self,
        rules: list[Detection],
        stats: IngestionStats,
    ) -> int:
        """Upsert a batch of rules via session.merge().

        merge() checks the primary key: if a row with the same `id`
        already exists, it updates all columns (including `updated_at`);
        if not, it inserts a new row. This lets us skip the dangerous
        DELETE-before-INSERT pattern entirely.

        Returns the number of rules successfully stored.
        """
        stored = 0
        for rule in rules:
            try:
                await self.db.merge(rule)
                stored += 1
            except Exception as e:
                stats.add_error(
                    file_path=rule.source_file,
                    stage=ErrorStage.STORE,
                    message=f"Database error: {type(e).__name__}: {str(e)}",
                    severity=ErrorSeverity.ERROR,
                )

        try:
            await self.db.commit()
        except Exception as e:
            logger.error(f"Batch commit failed: {e}")
            await self.db.rollback()
            # Fall back to one-by-one merge
            stored = 0
            for rule in rules:
                try:
                    await self.db.merge(rule)
                    await self.db.commit()
                    stored += 1
                except Exception as inner_e:
                    await self.db.rollback()
                    stats.add_error(
                        file_path=rule.source_file,
                        stage=ErrorStage.STORE,
                        message=f"Individual store failed: {type(inner_e).__name__}: {str(inner_e)}",
                        severity=ErrorSeverity.ERROR,
                    )

        return stored

    async def _cleanup_stale_rules(
        self, repo_name: str, ingest_start: datetime
    ) -> None:
        """Delete rules that were NOT touched by the current ingest.

        Any row whose `updated_at` is older than `ingest_start` was not
        upserted during this ingest run, meaning the corresponding
        source file no longer exists in the upstream repo (deleted,
        renamed to something unparseable, moved outside the rule
        directory, etc.). Safe to remove.

        This runs AFTER all new rules are successfully stored, so a
        crash before this point leaves old + new rows coexisting
        (strictly better than the old DELETE-first approach which left
        zero rows on crash).
        """
        result = await self.db.execute(
            delete(Detection)
            .where(Detection.source == repo_name)
            .where(Detection.updated_at < ingest_start)
        )
        stale_count = result.rowcount or 0
        if stale_count > 0:
            logger.info(
                f"Removed {stale_count} stale {repo_name} rule(s) "
                f"no longer in upstream repo"
            )
        await self.db.commit()

    async def _update_repository_count(self, repo_name: str, count: int) -> None:
        """Update the rule count for a repository."""
        result = await self.db.execute(
            select(Repository).where(Repository.name == repo_name)
        )
        repo = result.scalar_one_or_none()
        if repo:
            repo.rule_count = count
            await self.db.commit()

    @staticmethod
    def _validate_date(dt: datetime | None) -> datetime | None:
        """Return None if a rule date is in the future (author typo)."""
        if dt and dt > utcnow():
            return None
        return dt

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
            mitre_tactics=normalized.mitre_tactics,
            mitre_techniques=normalized.mitre_techniques,
            mitre_groups=normalized.mitre_groups,
            mitre_software=normalized.mitre_software,
            detection_logic=normalized.detection_logic,
            language=normalized.language,
            tags=normalized.tags,
            references=normalized.references,
            false_positives=normalized.false_positives,
            raw_content=normalized.raw_content,
            # Extracted observable fields
            extracted_fields_used=normalized.extracted_fields_used,
            extracted_event_ids=normalized.extracted_event_ids,
            extracted_process_names=normalized.extracted_process_names,
            extracted_file_paths=normalized.extracted_file_paths,
            extracted_registry_keys=normalized.extracted_registry_keys,
            extracted_network_indicators=normalized.extracted_network_indicators,
            extracted_source_tables=normalized.extracted_source_tables,
            extracted_observables=normalized.extracted_observables,
            query_complexity=normalized.query_complexity,
            extracted_api_actions=normalized.extracted_api_actions,
            extracted_target_resources=normalized.extracted_target_resources,
            rule_created_date=self._validate_date(normalized.rule_created_date),
            rule_modified_date=self._validate_date(normalized.rule_modified_date),
            # Canonical taxonomy (final names after Phase 3 -- the
            # legacy single-value `platform` / `event_category` /
            # `data_source_normalized` and the raw `log_sources` /
            # `data_sources` are dropped).
            platforms=normalized.platforms,
            data_sources=normalized.data_sources,
            event_types=normalized.event_types,
            use_cases=normalized.use_cases,
            created_at=utcnow(),
            updated_at=utcnow(),
        )

    async def get_ingestion_stats(self) -> dict:
        """Get overall ingestion statistics."""
        stats = {}

        # Count detections per source
        for source in ALL_REPOSITORY_NAMES:
            result = await self.db.execute(
                select(Detection).where(Detection.source == source)
            )
            stats[source] = len(result.scalars().all())

        stats["total"] = sum(stats.values())
        return stats
