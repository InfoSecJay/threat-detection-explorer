"""Search and filter service for detection rules."""

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select, or_, and_, func, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection

logger = logging.getLogger(__name__)


@dataclass
class SearchFilters:
    """Search and filter parameters for detection queries."""

    # Text search
    search: Optional[str] = None

    # Exact filters
    sources: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)

    # MITRE filters
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Tag filter
    tags: list[str] = field(default_factory=list)

    # Log source filter
    log_sources: list[str] = field(default_factory=list)

    # Pagination
    offset: int = 0
    limit: int = 50

    # Sorting
    sort_by: str = "title"
    sort_order: str = "asc"


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
        query = select(Detection).where(
            Detection.mitre_techniques.contains([technique])
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
        for source in ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm"]:
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
        else:
            return []

        return [r for r in result.scalars().all() if r]

    def _build_conditions(self, filters: SearchFilters) -> list:
        """Build SQLAlchemy filter conditions from search filters."""
        conditions = []

        # Text search (title, description, detection_logic)
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

        # MITRE tactics filter
        if filters.mitre_tactics:
            # Check if any of the specified tactics are in the array
            tactic_conditions = []
            for tactic in filters.mitre_tactics:
                tactic_conditions.append(
                    Detection.mitre_tactics.contains([tactic])
                )
            if tactic_conditions:
                conditions.append(or_(*tactic_conditions))

        # MITRE techniques filter
        if filters.mitre_techniques:
            technique_conditions = []
            for technique in filters.mitre_techniques:
                technique_conditions.append(
                    Detection.mitre_techniques.contains([technique])
                )
            if technique_conditions:
                conditions.append(or_(*technique_conditions))

        # Tags filter
        if filters.tags:
            tag_conditions = []
            for tag in filters.tags:
                tag_conditions.append(Detection.tags.contains([tag]))
            if tag_conditions:
                conditions.append(or_(*tag_conditions))

        # Log sources filter
        if filters.log_sources:
            log_source_conditions = []
            for log_source in filters.log_sources:
                log_source_conditions.append(
                    Detection.log_sources.contains([log_source])
                )
            if log_source_conditions:
                conditions.append(or_(*log_source_conditions))

        return conditions

    def _apply_sorting(self, query, sort_by: str, sort_order: str):
        """Apply sorting to query."""
        # Map sort field names to columns
        sort_columns = {
            "title": Detection.title,
            "source": Detection.source,
            "severity": Detection.severity,
            "status": Detection.status,
            "created_at": Detection.created_at,
            "updated_at": Detection.updated_at,
            "rule_created_date": Detection.rule_created_date,
            "rule_modified_date": Detection.rule_modified_date,
        }

        column = sort_columns.get(sort_by, Detection.title)

        if sort_order.lower() == "desc":
            # For date columns, put nulls last when sorting desc
            if sort_by in ["rule_created_date", "rule_modified_date"]:
                return query.order_by(column.desc().nullslast())
            return query.order_by(column.desc())

        # For date columns, put nulls last when sorting asc
        if sort_by in ["rule_created_date", "rule_modified_date"]:
            return query.order_by(column.asc().nullslast())
        return query.order_by(column.asc())
