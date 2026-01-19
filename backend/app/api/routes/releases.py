"""GitHub releases API routes."""

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/releases", tags=["releases"])

# Repositories that have GitHub releases
RELEASE_REPOS = {
    "sigma": {
        "owner": "SigmaHQ",
        "repo": "sigma",
        "name": "SigmaHQ",
    },
    "elastic": {
        "owner": "elastic",
        "repo": "detection-rules",
        "name": "Elastic Detection Rules",
    },
    "splunk": {
        "owner": "splunk",
        "repo": "security_content",
        "name": "Splunk Security Content",
    },
}


@router.get("")
async def list_release_sources():
    """List all sources that have release notes available."""
    return [
        {"id": key, "name": value["name"], "owner": value["owner"], "repo": value["repo"]}
        for key, value in RELEASE_REPOS.items()
    ]


@router.get("/{source}")
async def get_releases(
    source: str,
    per_page: int = Query(5, ge=1, le=30),
):
    """Get GitHub releases for a specific source."""
    if source not in RELEASE_REPOS:
        raise HTTPException(
            status_code=404,
            detail=f"Source '{source}' does not have release notes. Available: {list(RELEASE_REPOS.keys())}",
        )

    repo_info = RELEASE_REPOS[source]
    owner = repo_info["owner"]
    repo = repo_info["repo"]

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/releases",
                params={"per_page": per_page},
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=10.0,
            )

            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Repository not found")

            if response.status_code == 403:
                raise HTTPException(
                    status_code=429,
                    detail="GitHub API rate limit exceeded. Try again later.",
                )

            response.raise_for_status()
            releases = response.json()

            # Transform to simpler format
            return [
                {
                    "id": release["id"],
                    "tag_name": release["tag_name"],
                    "name": release["name"] or release["tag_name"],
                    "published_at": release["published_at"],
                    "html_url": release["html_url"],
                    "body": release["body"] or "",
                    "author": release["author"]["login"] if release.get("author") else None,
                }
                for release in releases
            ]

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub API request timed out")
    except httpx.HTTPError as e:
        logger.error(f"GitHub API error: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch releases from GitHub")
