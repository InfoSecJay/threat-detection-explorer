"""DX-12 / #167: `content:` terms out of a query, and the result-row
snippet that says where the term occurs and whether it is an exclusion."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.query_parser import content_terms
from app.services.snippets import content_snippet, find_match, negated_hit


class TestContentTerms:
    def test_collects_content_aliases_in_order_and_nothing_else(self):
        assert content_terms('content:citrix') == ["citrix"]
        assert content_terms('raw:"signer name" logic:HKLM') == ["signer name", "HKLM"]
        assert content_terms('title:citrix powershell source:sigma') == []
        assert content_terms('content:citrix title:x content:foo') == ["citrix", "foo"]

    def test_negated_terms_and_wildcards(self):
        assert content_terms('NOT content:citrix') == []
        assert content_terms('-content:citrix content:okta') == ["okta"]
        assert content_terms('content:HKLM*') == ["HKLM"]

    def test_garbage_is_empty_not_an_error(self):
        assert content_terms("") == []
        assert content_terms('content:"unterminated') == []


class TestFindMatch:
    def test_earliest_term_wins_case_insensitively(self):
        assert find_match("Image|endswith: Citrix Receiver.exe", ["receiver", "CITRIX"]) == (16, 22, "CITRIX")
        assert find_match("nothing here", ["citrix"]) is None
        assert find_match("", ["citrix"]) is None


class TestNegatedHit:
    def test_only_negated_observables_mark_an_exclusion(self):
        allowlist = [{"field": "process.code_signature.subject_name", "values": ["Citrix Systems, Inc."], "negated": True}]
        both = allowlist + [{"field": "process.name", "values": ["citrix.exe"], "negated": False}]
        assert negated_hit(allowlist, "citrix") is True
        assert negated_hit(both, "citrix") is False
        assert negated_hit([{"field": "x", "values": ["other"], "negated": True}], "citrix") is False
        assert negated_hit(None, "citrix") is False
        # Tolerates the dict shape and junk entries.
        assert negated_hit({"observables": allowlist}, "citrix") is True
        assert negated_hit(["junk", None] + allowlist, "citrix") is True


class TestContentSnippet:
    def _det(self, logic: str, raw: str = "", observables=None):
        return SimpleNamespace(detection_logic=logic, raw_content=raw, extracted_observables=observables or [])

    def test_logic_first_with_context_and_ellipses(self):
        logic = "a" * 100 + "\n  not process.code_signature.subject_name : \"Citrix Systems\"\n" + "b" * 100
        snip = content_snippet(self._det(logic), ["citrix"])
        assert snip["field"] == "detection_logic" and snip["match"] == "Citrix" and snip["term"] == "citrix"
        assert snip["before"].startswith("...") and snip["after"].endswith("...")
        assert "\n" not in snip["before"] + snip["after"], "whitespace is flattened for one row"
        assert snip["before"].endswith('subject_name : "')
        assert snip["negated"] is False, "no observables -> plain hit"

    def test_falls_back_to_the_raw_body_and_reports_exclusions(self):
        det = self._det(
            "process where true",
            "title: Something\nfalsepositives:\n  - Citrix admin tooling\n",
            observables=[{"field": "signer", "values": ["Citrix Systems"], "negated": True}],
        )
        snip = content_snippet(det, ["citrix"])
        assert snip["field"] == "raw_content" and snip["match"] == "Citrix"
        assert snip["negated"] is True
        assert not snip["before"].startswith("..."), "match sits within CONTEXT of the start"

    def test_no_match_or_no_terms_is_none(self):
        assert content_snippet(self._det("process where true"), ["citrix"]) is None
        assert content_snippet(self._det("citrix"), []) is None
