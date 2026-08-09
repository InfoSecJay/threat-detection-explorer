"""Query language metadata routes.

Powers the /query docs page + typeahead. Exposes the field registry
directly from ``app.services.query_parser`` so the two are always in
sync — add a queryable dimension in the parser, it shows up on the
docs page without a second commit.
"""

from fastapi import APIRouter

from app.services.query_parser import field_reference

router = APIRouter(prefix="/query", tags=["query"])


@router.get("/fields")
async def get_query_fields():
    """Return the full field registry for the Query Reference docs page.

    Each entry: `aliases` (list of names users type before the colon),
    `kind` (how the field matches — text/list/etc.), `columns` (the
    underlying detection columns; internal detail useful for
    understanding), `description`, `examples`.
    """
    return {"fields": field_reference()}
