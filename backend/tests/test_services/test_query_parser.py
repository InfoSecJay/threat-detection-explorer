"""Tests for the Lucene-syntax query parser.

The parser is the whole reason users get autocomplete + shareable
URLs on the search bar. The DB-side clause it emits is what makes
`actor:APT29 AND severity:high` actually filter. If any of these
tests break, the search bar produces wrong results — no fallback.
"""

import pytest
from sqlalchemy import Column
from sqlalchemy.sql.elements import ColumnElement

from app.services.query_parser import (
    QueryParseError,
    field_reference,
    parse_query,
)


def _sql(clause: ColumnElement | None) -> str:
    """Render a clause to a lowercased SQL string for comparison.

    Lowercased because SQLite renders `ILIKE` as
    `lower(col) LIKE lower(pattern)`, which changes what's in the
    string. Comparing everything lower-case masks that difference.
    """
    assert clause is not None
    return str(clause.compile(compile_kwargs={"literal_binds": True})).lower()


class TestEmptyAndTrivial:
    def test_empty_returns_none(self):
        assert parse_query("") is None
        assert parse_query("   ") is None
        assert parse_query(None) is None

    def test_bare_word_matches_curated_fields(self):
        s = _sql(parse_query("powershell"))
        # Multi-field OR across title/description/tags
        assert "detections.title" in s and "'%powershell%'" in s
        assert "detections.description" in s
        assert "detections.tags" in s

    def test_bare_word_casts_json_tags_on_postgres(self):
        """Bare-word search must CAST the JSON tags column to text.

        Postgres has no `json ILIKE` operator — without the cast every
        bare-word query 500s in production while passing on SQLite,
        which stores JSON as text. Compile against the pg dialect to
        catch it where it actually breaks.
        """
        from sqlalchemy.dialects import postgresql

        clause = parse_query("windows")
        assert clause is not None
        s = str(
            clause.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        ).lower()
        assert "cast(detections.tags as varchar)" in s
        # Plain text columns must NOT get a needless cast.
        assert "cast(detections.title" not in s


class TestFieldQueries:
    def test_title_field(self):
        s = _sql(parse_query("title:mimikatz"))
        assert "detections.title" in s and "'%mimikatz%'" in s
        # Only title — no OR across other fields
        assert "detections.description" not in s

    def test_quoted_phrase(self):
        s = _sql(parse_query('title:"cobalt strike"'))
        assert "detections.title" in s and "'%cobalt strike%'" in s

    def test_source_field(self):
        s = _sql(parse_query("source:sigma"))
        assert "detections.source" in s and "'%sigma%'" in s

    def test_wildcard(self):
        s = _sql(parse_query("title:power*"))
        assert "detections.title" in s and "'power%'" in s and "%%" not in s

    def test_list_column_uses_quoted_substring(self):
        """Technique T1059 must not false-match T1059.001."""
        s = _sql(parse_query("tech:T1059"))
        # The `"T1059"` (with quotes in the LIKE pattern) is what
        # prevents the sub-technique false-match.
        assert '\'%"t1059"%\'' in s


class TestBooleanCombination:
    def test_and(self):
        s = _sql(parse_query("source:sigma AND severity:high"))
        assert "sigma" in s and "high" in s
        assert " and " in s

    def test_or(self):
        s = _sql(parse_query("source:sigma OR source:elastic"))
        assert "sigma" in s and "elastic" in s
        assert " or " in s

    def test_not(self):
        s = _sql(parse_query("severity:critical NOT source:sigma"))
        assert " not " in s

    def test_grouping(self):
        s = _sql(parse_query("(source:sigma OR source:elastic) AND severity:high"))
        assert " or " in s
        assert " and " in s

    def test_implicit_and(self):
        """Adjacent terms without an operator behave as AND."""
        s = _sql(parse_query("severity:high source:sigma"))
        assert " and " in s


class TestMitreAliasResolution:
    def test_actor_by_name_resolves_to_gid(self):
        """`actor:APT29` must translate to the underlying G0016 filter."""
        s = _sql(parse_query("actor:APT29"))
        assert '"g0016"' in s

    def test_actor_by_alias_resolves(self):
        """`actor:"Cozy Bear"` also maps to G0016."""
        s = _sql(parse_query('actor:"Cozy Bear"'))
        assert '"g0016"' in s

    def test_actor_by_id_passes_through(self):
        s = _sql(parse_query("group:G0016"))
        assert '"g0016"' in s

    def test_malware_by_name(self):
        s = _sql(parse_query("malware:Mimikatz"))
        assert '"s0002"' in s

    def test_software_by_id(self):
        s = _sql(parse_query("tool:S0154"))
        assert '"s0154"' in s

    def test_unknown_actor_name_passes_through_uppercased(self):
        """Unknown names are used verbatim — no silent miss.

        A rule tagged with an obscure actor name we haven't registered
        can still be found by typing that exact name.
        """
        s = _sql(parse_query("actor:UnknownGroup"))
        assert "unknowngroup" in s


class TestErrorHandling:
    def test_unknown_field_raises(self):
        with pytest.raises(QueryParseError) as exc:
            parse_query("priority:high")
        assert "unknown field" in str(exc.value)

    def test_unknown_field_offers_suggestion(self):
        """Typo 'severty' should suggest 'severity'."""
        with pytest.raises(QueryParseError) as exc:
            parse_query("severty:high")
        assert exc.value.suggestion is not None
        assert exc.value.suggestion in ("sev", "severity")

    def test_malformed_query_raises(self):
        with pytest.raises(QueryParseError):
            parse_query('title:"unclosed')


class TestFieldReference:
    def test_reference_shape(self):
        ref = field_reference()
        assert isinstance(ref, list)
        assert all("aliases" in r and "kind" in r and "description" in r for r in ref)

    def test_reference_covers_core_fields(self):
        """Every field the FE search bar advertises must be in the registry."""
        ref = field_reference()
        all_aliases = {a for r in ref for a in r["aliases"]}
        for expected in ("title", "source", "severity", "actor", "malware", "tech", "platform"):
            assert expected in all_aliases
