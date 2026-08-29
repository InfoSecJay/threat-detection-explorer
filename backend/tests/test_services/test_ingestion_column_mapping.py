"""Every NormalizedDetection field that is also a Detection column must
survive `_to_detection_model`.

The mapping is written out field by field, so a new field can be
computed correctly by every normalizer and still never reach the
database: `is_building_block` shipped exactly that way (#26 -- the
nightly sync ran, statuses updated, the flag stayed False everywhere).
This test sets a non-default sentinel on every shared field and reads
it back off the ORM row, so the next such omission fails here instead
of in production.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime

import pytest

from app.models.detection import Detection
from app.normalizers.base import NormalizedDetection
from app.services.ingestion import IngestionService

# NormalizedDetection fields that intentionally do NOT persist.
NOT_PERSISTED = {"taxonomy_matched", "taxonomy_fingerprint"}


def _sentinel(field: dataclasses.Field):
    origin = str(field.type)
    if "bool" in origin:
        return True
    if "list" in origin:
        return [{"k": "v"}] if "dict" in origin else ["sentinel"]
    if "datetime" in origin:
        return datetime(2024, 2, 3, 4, 5, 6)
    if "int" in origin:
        return 7
    return f"sentinel-{field.name}"


def test_every_shared_field_reaches_the_orm_row(db_session):
    svc = IngestionService(db_session)
    columns = {c.name for c in Detection.__table__.columns}
    values = {}
    for f in dataclasses.fields(NormalizedDetection):
        if f.name in columns and f.name not in NOT_PERSISTED:
            values[f.name] = _sentinel(f)
    # Required fields the sentinel loop may have typed differently.
    values.update(id="det-1", source="sigma", status="test", severity="high")

    row = svc._to_detection_model(NormalizedDetection(**values))

    for name, expected in values.items():
        assert getattr(row, name) == expected, f"{name} dropped by _to_detection_model"


@pytest.mark.parametrize("flag", [True, False])
def test_building_block_flag_persists(db_session, flag):
    svc = IngestionService(db_session)
    n = NormalizedDetection(
        id="d", source="elastic", source_file="f", source_repo_url="u",
        title="t", description=None, author=None, status="stable", severity="low",
        is_building_block=flag,
    )
    assert svc._to_detection_model(n).is_building_block is flag
