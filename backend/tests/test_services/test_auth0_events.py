"""Auth0 data.type event dictionary (issue #72)."""

from __future__ import annotations

from app.services.field_extractor import ExtractedFields, ExtractedObservable, _deduplicate_all
from app.services.observables import _context
from app.services.taxonomy.auth0_events import AUTH0_EVENT_INDEX, _load, lookup


class TestDictionary:
    def test_strict_load_passes(self):
        assert len(_load(strict=True)) >= 90

    def test_core_codes(self):
        assert lookup("fp").label == "Failed login: invalid password"
        assert lookup("s").category == "success"
        assert lookup("sapi").label == "Management API operation"
        assert lookup("limit_wc").category == "limit"
        assert lookup("nonexistent_code_xyz") is None

    def test_lookup_normalizes(self):
        assert lookup(" FP ") is lookup("fp")


class TestSurfacing:
    def _extract(self, field, values, negated=False):
        result = ExtractedFields()
        result.observables.append(ExtractedObservable(
            field=field, values=list(values), negated=negated,
            type="event", subtype="event_category",
        ))
        _deduplicate_all(result)
        return result

    def test_data_type_codes_reach_event_ids(self):
        r = self._extract("data.type", ["fp", "limit_wc"])
        assert "fp" in r.event_ids and "limit_wc" in r.event_ids

    def test_unknown_and_negated_codes_stay_off_the_surface(self):
        assert self._extract("data.type", ["not_a_code"]).event_ids == []
        assert self._extract("data.type", ["fp"], negated=True).event_ids == []

    def test_other_type_fields_do_not_surface(self):
        # elastic endgame.metadata.type is also event_category but its
        # values are not Auth0 codes.
        assert self._extract("endgame.metadata.type", ["detection"]).event_ids == []


class TestContext:
    def test_eventid_context_falls_back_to_auth0(self):
        ctx = _context("eventid", "fp", None)
        assert ctx == {"label": "Failed login: invalid password", "provider": "auth0", "channel": "Auth0 log events"}

    def test_windows_ids_still_win(self):
        ctx = _context("eventid", "4624", None)
        assert ctx is not None and ctx["provider"] != "auth0"

    def test_unknown_stays_none(self):
        assert _context("eventid", "zzz_nope", None) is None


def test_no_collision_with_windows_event_ids():
    from app.services.taxonomy.event_ids import EVENT_ID_INDEX

    assert not set(AUTH0_EVENT_INDEX) & set(EVENT_ID_INDEX)
