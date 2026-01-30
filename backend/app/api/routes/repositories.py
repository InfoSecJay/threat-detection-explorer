"""Repository management API routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.schemas import RepositoryResponse, SyncResponse, IngestionResponse, IngestionStatsSchema
from app.services.repository_sync import RepositorySyncService
from app.services.ingestion import IngestionService

router = APIRouter(prefix="/repositories", tags=["repositories"])


ALL_REPOSITORIES = ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm", "elastic_hunting", "sentinel"]


@router.get("", response_model=list[RepositoryResponse])
async def list_repositories(db: AsyncSession = Depends(get_db)):
    """List all repositories with their sync status."""
    sync_service = RepositorySyncService(db)

    # Ensure all repositories exist in DB
    for name in ALL_REPOSITORIES:
        await sync_service.ensure_repository_exists(name)

    repos = await sync_service.get_all_repositories()
    return repos


@router.get("/{name}", response_model=RepositoryResponse)
async def get_repository(name: str, db: AsyncSession = Depends(get_db)):
    """Get a specific repository's status."""
    sync_service = RepositorySyncService(db)
    repo = await sync_service.get_repository(name)

    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository not found: {name}")

    return repo


@router.post("/{name}/sync", response_model=SyncResponse)
async def sync_repository(name: str, db: AsyncSession = Depends(get_db)):
    """Trigger sync for a specific repository."""
    if name not in ALL_REPOSITORIES:
        raise HTTPException(status_code=400, detail=f"Invalid repository name: {name}")

    sync_service = RepositorySyncService(db)
    success, message = await sync_service.sync_repository(name)

    return SyncResponse(success=success, message=message, repository=name)


@router.post("/sync-all", response_model=list[SyncResponse])
async def sync_all_repositories(db: AsyncSession = Depends(get_db)):
    """Trigger sync for all repositories."""
    sync_service = RepositorySyncService(db)
    results = []

    for name in ALL_REPOSITORIES:
        success, message = await sync_service.sync_repository(name)
        results.append(SyncResponse(success=success, message=message, repository=name))

    return results


@router.post("/{name}/ingest", response_model=IngestionResponse)
async def ingest_repository(name: str, db: AsyncSession = Depends(get_db)):
    """Ingest detection rules from a synced repository."""
    if name not in ALL_REPOSITORIES:
        raise HTTPException(status_code=400, detail=f"Invalid repository name: {name}")

    # Check if repository is synced
    sync_service = RepositorySyncService(db)
    repo = await sync_service.get_repository(name)

    if not repo or not repo.last_sync_at:
        raise HTTPException(
            status_code=400,
            detail=f"Repository {name} has not been synced yet. Run sync first.",
        )

    # Run ingestion
    ingestion_service = IngestionService(db)
    try:
        stats = await ingestion_service.ingest_repository(name)
        stats_dict = stats.to_dict()

        # Determine success based on error count and stored rules
        has_errors = stats.error_count > 0
        success = stats.stored > 0

        if success and has_errors:
            message = f"Ingested {stats.stored} rules from {name} with {stats.error_count} errors"
        elif success:
            message = f"Successfully ingested {stats.stored} rules from {name}"
        else:
            message = f"Ingestion completed but no rules were stored. {stats.error_count} errors occurred."

        return IngestionResponse(
            success=success,
            message=message,
            stats=IngestionStatsSchema(**stats_dict),
        )
    except Exception as e:
        # Return empty stats on complete failure
        empty_stats = IngestionStatsSchema(
            discovered=0,
            skipped_by_filter=0,
            parsed=0,
            normalized=0,
            stored=0,
            error_count=1,
            warning_count=0,
            success_rate=0.0,
            duration_seconds=None,
            errors_by_stage={},
            sample_errors=[],
        )
        return IngestionResponse(
            success=False,
            message=f"Ingestion failed: {str(e)}",
            stats=empty_stats,
        )


@router.post("/ingest-all", response_model=list[IngestionResponse])
async def ingest_all_repositories(db: AsyncSession = Depends(get_db)):
    """Ingest detection rules from all synced repositories."""
    ingestion_service = IngestionService(db)
    sync_service = RepositorySyncService(db)
    results = []

    for name in ALL_REPOSITORIES:
        repo = await sync_service.get_repository(name)

        if not repo or not repo.last_sync_at:
            empty_stats = IngestionStatsSchema(
                discovered=0,
                skipped_by_filter=0,
                parsed=0,
                normalized=0,
                stored=0,
                error_count=0,
                warning_count=0,
                success_rate=0.0,
                duration_seconds=None,
                errors_by_stage={},
                sample_errors=[],
            )
            results.append(IngestionResponse(
                success=False,
                message=f"Repository {name} has not been synced yet",
                stats=empty_stats,
            ))
            continue

        try:
            stats = await ingestion_service.ingest_repository(name)
            stats_dict = stats.to_dict()

            has_errors = stats.error_count > 0
            success = stats.stored > 0

            if success and has_errors:
                message = f"Ingested {stats.stored} rules from {name} with {stats.error_count} errors"
            elif success:
                message = f"Successfully ingested {stats.stored} rules from {name}"
            else:
                message = f"Ingestion completed but no rules were stored. {stats.error_count} errors occurred."

            results.append(IngestionResponse(
                success=success,
                message=message,
                stats=IngestionStatsSchema(**stats_dict),
            ))
        except Exception as e:
            empty_stats = IngestionStatsSchema(
                discovered=0,
                skipped_by_filter=0,
                parsed=0,
                normalized=0,
                stored=0,
                error_count=1,
                warning_count=0,
                success_rate=0.0,
                duration_seconds=None,
                errors_by_stage={},
                sample_errors=[],
            )
            results.append(IngestionResponse(
                success=False,
                message=f"Ingestion failed for {name}: {str(e)}",
                stats=empty_stats,
            ))

    return results
