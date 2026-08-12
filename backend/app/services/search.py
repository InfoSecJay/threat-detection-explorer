"""Search and filter service for detection rules."""

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select, or_, and_, func, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.repository_sync import ALL_REPOSITORY_NAMES

logger = logging.getLogger(__name__)


@dataclass
class SearchFilters:
    """Search and filter parameters for detection queries."""

    # Text search
    search: Optional[str] = None
    # Lucene-syntax query — parsed via app.services.query_parser and
    # AND'd with the rest of the filters. Empty/None = no-op. Powers
    # the /query universal search bar.
    q: Optional[str] = None

    # Exact filters
    sources: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)

    # MITRE filters
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    # Threat-actor + software filters. Values are raw ATT&CK IDs
    # ("G0016", "S0002") — the FE resolves display names for pills.
    mitre_groups: list[str] = field(default_factory=list)
    mitre_software: list[str] = field(default_factory=list)

    # Tag filter
    tags: list[str] = field(default_factory=list)

    # Canonical taxonomy filters (Phase 3 final names).
    # `event_categories` / `data_sources_normalized` keys retained
    # for URL backwards-compat with the FilterPanel UI; they match
    # the renamed `event_types` / `data_sources` columns.
    platforms: list[str] = field(default_factory=list)
    event_categories: list[str] = field(default_factory=list)
    data_sources_normalized: list[str] = field(default_factory=list)

    # Analytic story / vendor use-case labels
    use_cases: list[str] = field(default_factory=list)

    # Extracted observable filters
    event_ids: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    query_complexity: list[str] = field(default_factory=list)
    api_actions: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)
    target_resources: list[str] = field(default_factory=list)
    source_tables: list[str] = field(default_factory=list)

    # Pagination
    offset: int = 0
    limit: int = 50

    # Sorting — default to newest-first by rule creation date so the
    # first thing a user sees is what shipped upstream most recently.
    sort_by: str = "rule_created_date"
    sort_order: str = "desc"


class SearchService:
    """Service for searching and filtering detection rules."""

    def __init__(self, db: AsyncSession):
        """Initialize search service with database session."""
        self.db = db

    async def search_detections(self, filters: SearchFilters) -> tuple[list[Detection], int]:
        """Search for detections with filters.

        Args:
            filters: Search and filter parameters

        Returns:
            Tuple of (detections list, total count)
        """
        # Build base query
        query = select(Detection)
        count_query = select(func.count(Detection.id))

        # Apply filters
        conditions = self._build_conditions(filters)
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))

        # Get total count
        count_result = await self.db.execute(count_query)
        total_count = count_result.scalar() or 0

        # Apply sorting
        query = self._apply_sorting(query, filters.sort_by, filters.sort_order)

        # Apply pagination
        query = query.offset(filters.offset).limit(filters.limit)

        # Execute query
        result = await self.db.execute(query)
        detections = list(result.scalars().all())

        return detections, total_count

    async def get_detection_by_id(self, detection_id: str) -> Optional[Detection]:
        """Get a single detection by ID.

        Args:
            detection_id: Detection UUID

        Returns:
            Detection or None if not found
        """
        result = await self.db.execute(
            select(Detection).where(Detection.id == detection_id)
        )
        return result.scalar_one_or_none()

    async def get_detections_by_ids(self, detection_ids: list[str]) -> list[Detection]:
        """Get multiple detections by their IDs.

        Args:
            detection_ids: List of detection UUIDs

        Returns:
            List of detections (in the order requested, if found)
        """
        if not detection_ids:
            return []

        result = await self.db.execute(
            select(Detection).where(Detection.id.in_(detection_ids))
        )
        detections = list(result.scalars().all())

        # Preserve the requested order
        id_to_detection = {d.id: d for d in detections}
        return [id_to_detection[id] for id in detection_ids if id in id_to_detection]

    async def compare_by_technique(
        self,
        technique: str,
        sources: Optional[list[str]] = None,
    ) -> dict[str, list[Detection]]:
        """Get detections for a technique, grouped by source.

        Args:
            technique: MITRE technique ID (e.g., "T1059")
            sources: Optional list of sources to include

        Returns:
            Dict mapping source name to list of detections
        """
        # Use text-based matching for cross-database compatibility (SQLite + PostgreSQL)
        query = select(Detection).where(
            cast(Detection.mitre_techniques, String).ilike(f'%"{technique}"%')
        )

        if sources:
            query = query.where(Detection.source.in_(sources))

        result = await self.db.execute(query)
        detections = result.scalars().all()

        # Group by source
        grouped: dict[str, list[Detection]] = {}
        for detection in detections:
            if detection.source not in grouped:
                grouped[detection.source] = []
            grouped[detection.source].append(detection)

        return grouped

    async def compare_by_keyword(
        self,
        keyword: str,
        sources: Optional[list[str]] = None,
    ) -> dict[str, list[Detection]]:
        """Get detections containing a keyword in detection logic.

        Args:
            keyword: Keyword to search for (e.g., "4688", "powershell")
            sources: Optional list of sources to include

        Returns:
            Dict mapping source name to list of detections
        """
        query = select(Detection).where(
            or_(
                Detection.detection_logic.ilike(f"%{keyword}%"),
                Detection.raw_content.ilike(f"%{keyword}%"),
            )
        )

        if sources:
            query = query.where(Detection.source.in_(sources))

        result = await self.db.execute(query)
        detections = result.scalars().all()

        # Group by source
        grouped: dict[str, list[Detection]] = {}
        for detection in detections:
            if detection.source not in grouped:
                grouped[detection.source] = []
            grouped[detection.source].append(detection)

        return grouped

    async def compare_by_platform(
        self,
        platform: str,
        sources: Optional[list[str]] = None,
    ) -> dict[str, list[Detection]]:
        """Get detections for a specific platform, grouped by source.

        Args:
            platform: Platform identifier (e.g., "windows", "aws", "okta")
            sources: Optional list of sources to include

        Returns:
            Dict mapping source name to list of detections
        """
        # Match the canonical platforms JSON-list column with the
        # quoted-substring trick (portable across SQLite + Postgres).
        query = select(Detection).where(
            cast(Detection.platforms, String).ilike(f'%"{platform.lower()}"%')
        )

        if sources:
            query = query.where(Detection.source.in_(sources))

        result = await self.db.execute(query)
        detections = result.scalars().all()

        # Group by source
        grouped: dict[str, list[Detection]] = {}
        for detection in detections:
            if detection.source not in grouped:
                grouped[detection.source] = []
            grouped[detection.source].append(detection)

        return grouped

    async def get_statistics(self) -> dict:
        """Get overall statistics about stored detections.

        Returns:
            Statistics dict with counts by source, severity, etc.
        """
        stats = {
            "total": 0,
            "by_source": {},
            "by_severity": {},
            "by_status": {},
            "top_techniques": [],
            "top_tactics": [],
        }

        # Count by source
        for source in ALL_REPOSITORY_NAMES:
            count_result = await self.db.execute(
                select(func.count(Detection.id)).where(Detection.source == source)
            )
            count = count_result.scalar() or 0
            stats["by_source"][source] = count
            stats["total"] += count

        # Count by severity
        for severity in ["low", "medium", "high", "critical", "unknown"]:
            count_result = await self.db.execute(
                select(func.count(Detection.id)).where(Detection.severity == severity)
            )
            stats["by_severity"][severity] = count_result.scalar() or 0

        # Count by status
        for status in ["stable", "experimental", "deprecated", "unknown"]:
            count_result = await self.db.execute(
                select(func.count(Detection.id)).where(Detection.status == status)
            )
            stats["by_status"][status] = count_result.scalar() or 0

        return stats

    async def get_unique_values(self, field_name: str) -> list[str]:
        """Get unique values for a field (for filter dropdowns).

        Args:
            field_name: Name of the field

        Returns:
            List of unique values
        """
        if field_name == "source":
            result = await self.db.execute(
                select(Detection.source).distinct()
            )
        elif field_name == "status":
            result = await self.db.execute(
                select(Detection.status).distinct()
            )
        elif field_name == "severity":
            result = await self.db.execute(
                select(Detection.severity).distinct()
            )
        elif field_name == "language":
            result = await self.db.execute(
                select(Detection.language).distinct()
            )
        else:
            return []

        return [r for r in result.scalars().all() if r]

    async def get_taxonomy_facet(self, column_name: str) -> list[dict]:
        """Return a faceted count for one canonical-taxonomy JSON column.

        Args:
            column_name: `platforms`, `data_sources`, or `event_types`
                         (final post-Phase-3 names).

        Returns:
            List of `{"value": str, "count": int}` sorted by descending
            count. Skips the `"unknown"` sentinel unless explicitly
            desired — we surface it separately so it doesn't pollute
            the top of the real-value list.

        The implementation loads the column across all detections and
        aggregates in Python. This is portable across SQLite + Postgres
        and cheap at current corpus size (~12k rows). If the corpus
        grows past ~100k, swap to native JSON unnesting (Postgres
        `jsonb_array_elements_text`, SQLite `json_each`).
        """
        allowed = {"platforms", "data_sources", "event_types", "use_cases", "mitre_groups", "mitre_software"}
        if column_name not in allowed:
            raise ValueError(f"Not a taxonomy column: {column_name!r}")
        column = getattr(Detection, column_name)
        result = await self.db.execute(select(column))
        counts: dict[str, int] = {}
        for row in result.scalars().all():
            if not row:
                continue
            values = row if isinstance(row, list) else []
            for v in values:
                if not isinstance(v, str):
                    continue
                counts[v] = counts.get(v, 0) + 1

        facet = [
            {"value": v, "count": c}
            for v, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
        return facet

    def _build_conditions(self, filters: SearchFilters) -> list:
        """Build SQLAlchemy filter conditions from search filters."""
        conditions = []

        # Lucene-syntax query (parse errors propagate up as
        # QueryParseError; the route layer turns them into 400s).
        if filters.q:
            from app.services.query_parser import parse_query
            clause = parse_query(filters.q)
            if clause is not None:
                conditions.append(clause)

        # Text search (title, description, detection_logic) — legacy
        # single-field substring search; still supported for
        # backwards compat with existing URLs. New callers should
        # prefer `q`.
        if filters.search:
            search_term = f"%{filters.search}%"
            conditions.append(
                or_(
                    Detection.title.ilike(search_term),
                    Detection.description.ilike(search_term),
                    Detection.detection_logic.ilike(search_term),
                    Detection.raw_content.ilike(search_term),
                )
            )

        # Source filter
        if filters.sources:
            conditions.append(Detection.source.in_(filters.sources))

        # Status filter
        if filters.statuses:
            conditions.append(Detection.status.in_(filters.statuses))

        # Severity filter
        if filters.severities:
            conditions.append(Detection.severity.in_(filters.severities))

        # Language filter
        if filters.languages:
            conditions.append(Detection.language.in_(filters.languages))

        # MITRE tactics filter
        # Use text-based matching for cross-database compatibility (SQLite + PostgreSQL)
        if filters.mitre_tactics:
            tactic_conditions = []
            for tactic in filters.mitre_tactics:
                tactic_conditions.append(
                    cast(Detection.mitre_tactics, String).ilike(f'%"{tactic}"%')
                )
            if tactic_conditions:
                conditions.append(or_(*tactic_conditions))

        # MITRE techniques filter
        if filters.mitre_techniques:
            technique_conditions = []
            for technique in filters.mitre_techniques:
                technique_conditions.append(
                    cast(Detection.mitre_techniques, String).ilike(f'%"{technique}"%')
                )
            if technique_conditions:
                conditions.append(or_(*technique_conditions))

        # MITRE groups (threat actors) filter — raw G-IDs
        if filters.mitre_groups:
            group_conditions = [
                cast(Detection.mitre_groups, String).ilike(f'%"{gid.upper()}"%')
                for gid in filters.mitre_groups
            ]
            if group_conditions:
                conditions.append(or_(*group_conditions))

        # MITRE software (malware + tools) filter — raw S-IDs
        if filters.mitre_software:
            software_conditions = [
                cast(Detection.mitre_software, String).ilike(f'%"{sid.upper()}"%')
                for sid in filters.mitre_software
            ]
            if software_conditions:
                conditions.append(or_(*software_conditions))

        # Tags filter
        if filters.tags:
            tag_conditions = []
            for tag in filters.tags:
                tag_conditions.append(
                    cast(Detection.tags, String).ilike(f'%"{tag}"%')
                )
            if tag_conditions:
                conditions.append(or_(*tag_conditions))

        # Canonical-taxonomy filters — match against the JSON array
        # columns (`platforms`, `data_sources`, `event_types`).
        # Any-match within a dimension, AND across dimensions. The
        # text-based `ilike` trick is portable across SQLite (local
        # dev) and Postgres (prod); the quoted match prevents
        # substring false positives because canonical values are
        # stored as JSON strings ("windows", not windows).
        if filters.platforms:
            plat_conds = [
                cast(Detection.platforms, String).ilike(f'%"{v}"%')
                for v in filters.platforms
            ]
            conditions.append(or_(*plat_conds))

        if filters.event_categories:
            # Filter key retained for URL backwards-compat; matches
            # the renamed `event_types` column.
            et_conds = [
                cast(Detection.event_types, String).ilike(f'%"{v}"%')
                for v in filters.event_categories
            ]
            conditions.append(or_(*et_conds))

        if filters.data_sources_normalized:
            # Filter key retained for URL backwards-compat; matches
            # the renamed `data_sources` column.
            ds_conds = [
                cast(Detection.data_sources, String).ilike(f'%"{v}"%')
                for v in filters.data_sources_normalized
            ]
            conditions.append(or_(*ds_conds))

        # Extracted Event IDs filter (JSON array, text-based matching)
        if filters.event_ids:
            event_id_conditions = []
            for eid in filters.event_ids:
                event_id_conditions.append(
                    cast(Detection.extracted_event_ids, String).ilike(f'%"{eid}"%')
                )
            if event_id_conditions:
                conditions.append(or_(*event_id_conditions))

        # Extracted Process Names filter (JSON array, text-based matching)
        if filters.process_names:
            process_name_conditions = []
            for pname in filters.process_names:
                process_name_conditions.append(
                    cast(Detection.extracted_process_names, String).ilike(f'%{pname}%')
                )
            if process_name_conditions:
                conditions.append(or_(*process_name_conditions))

        # Query complexity filter (scalar field)
        if filters.query_complexity:
            conditions.append(Detection.query_complexity.in_(filters.query_complexity))

        # Extracted API Actions filter (JSON array, text-based matching)
        if filters.api_actions:
            api_action_conditions = []
            for action in filters.api_actions:
                api_action_conditions.append(
                    cast(Detection.extracted_api_actions, String).ilike(f'%{action}%')
                )
            if api_action_conditions:
                conditions.append(or_(*api_action_conditions))

        # use_cases filter — quoted-substring match on the JSON list so
        # `Ransomware` doesn't false-positive on `Ransomware Family X`.
        if filters.use_cases:
            uc_conds = [
                cast(Detection.use_cases, String).ilike(f'%"{v}"%')
                for v in filters.use_cases
            ]
            conditions.append(or_(*uc_conds))

        # File paths — substring match (paths are hierarchical; user
        # typing `\\anydesk.exe` should hit a stored path fragment).
        if filters.file_paths:
            fp_conds = [
                cast(Detection.extracted_file_paths, String).ilike(f'%{p}%')
                for p in filters.file_paths
            ]
            conditions.append(or_(*fp_conds))

        # Registry keys — substring match (hierarchical HKLM\... paths).
        if filters.registry_keys:
            rk_conds = [
                cast(Detection.extracted_registry_keys, String).ilike(f'%{k}%')
                for k in filters.registry_keys
            ]
            conditions.append(or_(*rk_conds))

        # Network indicators (IPs, domains, URLs) — substring match.
        if filters.network_indicators:
            ni_conds = [
                cast(Detection.extracted_network_indicators, String).ilike(f'%{v}%')
                for v in filters.network_indicators
            ]
            conditions.append(or_(*ni_conds))

        # Target resources (cloud resources, identity targets) —
        # quoted-substring match on the JSON list.
        if filters.target_resources:
            tr_conds = [
                cast(Detection.extracted_target_resources, String).ilike(f'%"{v}"%')
                for v in filters.target_resources
            ]
            conditions.append(or_(*tr_conds))

        # Source tables (Sentinel KQL tables, Splunk index/sourcetype
        # references) — quoted-substring match.
        if filters.source_tables:
            st_conds = [
                cast(Detection.extracted_source_tables, String).ilike(f'%"{v}"%')
                for v in filters.source_tables
            ]
            conditions.append(or_(*st_conds))

        return conditions

    # Sort fields whose column stores a JSON list (platforms,
    # data_sources, event_types). These are sorted by their string
    # serialization so rules whose first list element is `"aws"` cluster
    # together before those starting with `"gcp"`. Not perfect for
    # multi-element lists but it matches what the user sees in the
    # cell's first tag, which is the intuitive expectation.
    _JSON_LIST_SORT_FIELDS = {"platforms", "data_sources", "event_types"}

    # Date fields where NULLs are semantically "unknown" and belong at
    # the bottom of both asc and desc sorts -- otherwise a huge cluster
    # of null-dated rules pushes the interesting extremes off the top.
    _NULLS_LAST_SORT_FIELDS = {
        "rule_created_date", "rule_modified_date",
    } | _JSON_LIST_SORT_FIELDS

    def _apply_sorting(self, query, sort_by: str, sort_order: str):
        """Apply sorting to query."""
        # Map sort field names to columns
        sort_columns = {
            "title": Detection.title,
            "source": Detection.source,
            "severity": Detection.severity,
            "status": Detection.status,
            "language": Detection.language,
            "created_at": Detection.created_at,
            "updated_at": Detection.updated_at,
            "rule_created_date": Detection.rule_created_date,
            "rule_modified_date": Detection.rule_modified_date,
            "platforms": Detection.platforms,
            "data_sources": Detection.data_sources,
            "event_types": Detection.event_types,
        }

        column = sort_columns.get(sort_by, Detection.title)

        # JSON list columns aren't natively orderable -- cast to string
        # (works on both Postgres jsonb and SQLite JSON-as-text) so the
        # DB can order them lexicographically. Portable, no dialect
        # branches needed.
        if sort_by in self._JSON_LIST_SORT_FIELDS:
            column = cast(column, String)

        nulls_last = sort_by in self._NULLS_LAST_SORT_FIELDS
        if sort_order.lower() == "desc":
            return query.order_by(
                column.desc().nullslast() if nulls_last else column.desc()
            )
        return query.order_by(
            column.asc().nullslast() if nulls_last else column.asc()
        )
