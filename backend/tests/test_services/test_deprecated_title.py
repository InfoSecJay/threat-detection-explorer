"""Title-marker deprecation detection (teardown R11 / #109).

Vendors retire rules by renaming them in place: Elastic prefixes
"Deprecated - ", Sentinel wraps "[Deprecated]" as prefix or suffix.
The matcher must require an explicit marker; the bare word appearing
in a title describes what the rule DETECTS, not its lifecycle.
"""

import pytest

from app.services.ingestion import is_deprecated_title


@pytest.mark.parametrize(
    "title",
    [
        # Elastic convention
        "Deprecated - Unusual Discovery Activity by User",
        "Deprecated - M365 Exchange DLP Policy Deleted",
        "DEPRECATED - case insensitive",
        "Deprecated: colon separator",
        # Sentinel conventions
        "[Deprecated] Explicit MFA Deny",
        "[Deprecated] - Zinc Actor IOCs domains hashes IPs",
        "TI Map URL Entity to OfficeActivity Data [Deprecated]",
    ],
)
def test_marked_titles_match(title):
    assert is_deprecated_title(title)


@pytest.mark.parametrize(
    "title",
    [
        # The word alone is subject matter, not a lifecycle marker.
        "Deprecated TLS Version Usage",
        "Use of Deprecated APIs",
        "Detects deprecated protocol negotiation",
        "Deprecated cipher suite offered by client",
        # Word embedded mid-title.
        "Alert on deprecated - looking strings",  # lowercase mid-sentence prefix trap
        "",
    ],
)
def test_unmarked_titles_do_not_match(title):
    assert not is_deprecated_title(title)


def test_none_title():
    assert not is_deprecated_title(None)
