"""Per-vendor resolver functions.

Each module exports a single `resolve(parsed: ParsedRule) -> dict`
function that walks the vendor's parsed-rule shape, applies the
mapping YAML for that vendor, and returns canonical
platforms/data_sources/event_types.
"""

from app.services.taxonomy.vendors import (  # noqa: F401
    elastic,
    elastic_hunting,
    elastic_protections,
    google_secops,
    lolrmm,
    sentinel,
    sigma,
    splunk,
    sublime,
)
