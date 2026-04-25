"""Drift test: every column on the Detection model must be mentioned in
``docs/schema.md``.

The doc is the reader's guide; the model is authoritative. This test
catches the worst case where a new column lands in the model but the
doc forgets to describe it. The check is intentionally loose — it
only requires the column NAME to appear somewhere in the doc, not the
full type signature, so prose changes don't trigger false alarms.

When this fails:
  - Open docs/schema.md
  - Decide which section the new field belongs to (1-10)
  - Add a row to that section's table
  - Re-run the test
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.detection import Detection


# ── Columns we DELIBERATELY omit from the doc ─────────────────────────
# Either internal-only (the test for this is what they're for) or
# subsumed by a parent description — keep this list short and
# annotated.
DOC_OMITTED_COLUMNS: set[str] = set()


def _doc_path() -> Path:
    """docs/schema.md from this test file's perspective."""
    return Path(__file__).resolve().parents[2].parent / "docs" / "schema.md"


def test_schema_doc_exists():
    assert _doc_path().exists(), (
        f"docs/schema.md not found at {_doc_path()}. The schema doc is "
        "the canonical reader's guide — restore it from git history if "
        "it was deleted."
    )


def test_every_detection_column_is_documented():
    doc_text = _doc_path().read_text(encoding="utf-8")

    columns_to_check = {
        col.name
        for col in Detection.__table__.columns
        if col.name not in DOC_OMITTED_COLUMNS
    }

    missing = sorted(c for c in columns_to_check if c not in doc_text)
    assert not missing, (
        f"docs/schema.md is missing {len(missing)} column name(s): {missing}. "
        "Add a row in the appropriate section of the doc, or — if the "
        "field is intentionally internal — append it to "
        "DOC_OMITTED_COLUMNS in this test with a comment explaining why."
    )
