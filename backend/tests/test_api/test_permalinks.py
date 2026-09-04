"""Deterministic permalinks + alias resolution (#86 / teardown F10)."""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.models.detection_alias import DetectionAlias
from app.normalizers.base import _PERMALINK_NAMESPACE, NormalizedDetection


def _norm(**overrides) -> NormalizedDetection:
    base = dict(
        id="0" * 8 + "-0000-0000-0000-" + "0" * 12,
        source="sigma",
        source_file="rules/windows/a.yml",
        source_repo_url="https://x",
        title="A rule with a perfectly reasonable title",
        description="d", author="a", status="stable", severity="high",
        detection_logic="x",
        language="sigma",
        raw_content="raw",
        rule_id="c28c8fa1-5378-552f-9a0f-c6d186a406dc",
    )
    base.update(overrides)
    return NormalizedDetection(**base)


class TestDeterministicIds:
    def test_id_derives_from_source_and_rule_id_not_path(self):
        a = _norm(source_file="rules/windows/old_location.yml", id="aaaa")
        b = _norm(source_file="rules/emerging/new_location.yml", id="bbbb")
        assert a.id == b.id  # a file move must not change the permalink
        assert a.id == str(uuid.uuid5(_PERMALINK_NAMESPACE, "sigma:c28c8fa1-5378-552f-9a0f-c6d186a406dc"))
        assert a.legacy_id == "aaaa" and b.legacy_id == "bbbb"

    def test_same_rule_id_in_different_sources_differs(self):
        assert _norm(source="sigma").id != _norm(source="elastic").id

    def test_no_rule_id_keeps_the_path_hash(self):
        n = _norm(rule_id=None, id="path-hash-id")
        assert n.id == "path-hash-id" and n.legacy_id == "path-hash-id"


@pytest.fixture
async def client(db_session):
    canonical = str(uuid.uuid5(_PERMALINK_NAMESPACE, "sigma:upstream-1"))
    db_session.add(Detection(
        id=canonical, source="sigma", source_file="r.yml", source_repo_url="https://x",
        title="Aliased rule", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", rule_id="upstream-1",
    ))
    db_session.add(DetectionAlias(alias="legacy-hash-1", detection_id=canonical, kind="legacy"))
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        c.canonical = canonical  # type: ignore[attr-defined]
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_legacy_id_301s_to_canonical(client):
    r = await client.get("/api/detections/legacy-hash-1")
    assert r.status_code == 301
    assert r.headers["location"] == f"/api/v1/detections/{client.canonical}"
    followed = await client.get(r.headers["location"])
    assert followed.status_code == 200 and followed.json()["title"] == "Aliased rule"


@pytest.mark.asyncio
async def test_upstream_rule_id_resolves_via_column_even_without_alias_row(client):
    r = await client.get("/api/detections/upstream-1")
    assert r.status_code == 301
    assert r.headers["location"].endswith(client.canonical)


@pytest.mark.asyncio
async def test_canonical_id_serves_directly_no_redirect(client):
    r = await client.get(f"/api/detections/{client.canonical}")
    assert r.status_code == 200 and r.json()["id"] == client.canonical


@pytest.mark.asyncio
async def test_unknown_id_is_a_404(client):
    assert (await client.get("/api/detections/nope")).status_code == 404


@pytest.mark.asyncio
async def test_related_and_prerender_accept_aliases(client):
    assert (await client.get("/api/detections/legacy-hash-1/related")).status_code == 200
    pre = await client.get("/api/prerender/detection/legacy-hash-1")
    assert pre.status_code == 200 and "Aliased rule" in pre.text
