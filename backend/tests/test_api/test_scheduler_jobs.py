"""Tests for the /scheduler jobs response schema (#46, #24).

The `warnings` column was added after production rows already existed,
so the API must tolerate every shape those rows can carry: NULL
(Postgres before the startup migration runs), `[]` (the migration
default), a real list, and junk. Serialization must never 500 -- the
2026-08-28 detail-page outage was this exact class of bug.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api.routes.scheduler import SyncJobResponse


def _job(**overrides) -> SimpleNamespace:
    base = dict(
        id="job-1",
        job_type="full",
        repository=None,
        triggered_by="scheduled",
        status="completed",
        started_at=datetime(2026, 8, 29, 6, 0, 0),
        completed_at=datetime(2026, 8, 29, 6, 30, 0),
        duration_seconds=1800.0,
        rules_discovered=10,
        rules_stored=10,
        error_count=0,
        warning_count=0,
        repository_results={"sigma": {"sync_success": True}},
        warnings=[],
        error_message=None,
        created_at=datetime(2026, 8, 29, 6, 0, 0),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(
    "legacy_value",
    [None, [], {}, "not-a-list", 0],
    ids=["null", "empty-list", "dict", "string", "int"],
)
def test_legacy_warning_shapes_serialize_as_empty_list(legacy_value):
    resp = SyncJobResponse.model_validate(_job(warnings=legacy_value))
    assert resp.warnings == []


def test_real_warnings_pass_through():
    warning = {
        "code": "github_auth_failed",
        "source": "upstream_verifier",
        "message": "GitHub API returned 401 ...",
    }
    resp = SyncJobResponse.model_validate(_job(warnings=[warning]))
    assert resp.warnings == [warning]
    assert resp.model_dump()["warnings"][0]["code"] == "github_auth_failed"


def test_non_dict_entries_are_dropped():
    resp = SyncJobResponse.model_validate(
        _job(warnings=[{"code": "x"}, "stray", None, 3])
    )
    assert resp.warnings == [{"code": "x"}]


def test_missing_attribute_defaults_to_empty_list():
    """An ORM object from before the column existed has no attribute at
    all in some ad-hoc code paths; the schema default must cover it."""
    job = _job()
    del job.warnings
    resp = SyncJobResponse.model_validate(job)
    assert resp.warnings == []
