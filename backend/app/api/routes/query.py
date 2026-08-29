"""Query language metadata routes.

Powers the /query docs page + typeahead. Exposes the field registry
directly from ``app.services.query_parser`` so the two are always in
sync — add a queryable dimension in the parser, it shows up on the
docs page without a second commit.
"""

from fastapi import APIRouter

from app.services.query_parser import field_reference
from app.services.taxonomy.event_ids import dictionary as event_id_dictionary

router = APIRouter(prefix="/query", tags=["query"])


@router.get("/event-ids")
async def get_event_id_dictionary():
    """Windows event-ID dictionary (issue #16): `{id: {label, provider,
    channel, event_types}}`. Single source of truth for the labels the
    UI shows next to raw IDs (facet, pills, detail page) and for the
    taxonomy refinement the worker applies at ingest. Static per deploy
    -- cache aggressively client-side.
    """
    return {"event_ids": event_id_dictionary()}


@router.get("/fields")
async def get_query_fields():
    """Return the full field registry for the Query Reference docs page.

    Each entry: `aliases` (list of names users type before the colon),
    `kind` (how the field matches — text/list/etc.), `columns` (the
    underlying detection columns; internal detail useful for
    understanding), `description`, `examples`.
    """
    return {"fields": field_reference()}
