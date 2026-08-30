"""Sublime MQL findings from the 2026-08-30 semantic review (#59)."""

from __future__ import annotations

from app.services.field_extractor import extract_sublime_fields


def _obs(r, field):
    return [o for o in r.observables if o.field == field]


def test_call_expressions_are_fields():
    r = extract_sublime_fields(
        'type.inbound and strings.ilike(beta.ocr(file.message_screenshot()).text, "*DocuSign*") '
        "and ml.link_analysis(.).effective_url.scheme =~ 'blob' "
        "and any(attachments, regex.icontains(beta.file.parse_ics(.).product_id, 'Trafft'))"
    )
    assert _obs(r, "beta.ocr.text")[0].values == ["*DocuSign*"]
    assert _obs(r, "ml.link_analysis.effective_url.scheme")[0].values == ["blob"]
    assert _obs(r, "beta.file.parse_ics.product_id")[0].values == ["Trafft"]


def test_varargs_capture_every_literal():
    r = extract_sublime_fields('strings.ilike(subject.subject, "*shared*", "*updated*", "*sign*")')
    assert _obs(r, "subject.subject")[0].values == ["*shared*", "*updated*", "*sign*"]


def test_case_insensitive_equality_and_not_in():
    r = extract_sublime_fields(
        'any(body.links, .display_text =~ "Open") and sender.email.domain.root_domain not in ("google.com") '
        "and any(body.links, .href_url.domain.domain not in $org_domains)"
    )
    assert _obs(r, "body.links.display_text")[0].values == ["Open"]
    o = _obs(r, "sender.email.domain.root_domain")[0]
    assert o.values == ["google.com"] and o.negated is True
    assert "body.links.href_url.domain.domain" in r.fields_used


def test_not_blocks_negate_and_stay_off_surfaces():
    r = extract_sublime_fields(
        'type.inbound and not any(body.links, strings.ilike(.href_url.domain.root_domain, "docusign.*")) '
        'and not sender.email.domain.root_domain == "justpaste.it" '
        'and not (sender.email.domain.root_domain == "lulu.com" or sender.email.domain.root_domain == "hudu.com") '
        'and sender.email.domain.root_domain == "evil.example"'
    )
    assert _obs(r, "body.links.href_url.domain.root_domain")[0].negated is True
    by = {o.values[0]: o.negated for o in _obs(r, "sender.email.domain.root_domain")}
    assert by == {"justpaste.it": True, "lulu.com": True, "hudu.com": True, "evil.example": False}


def test_parent_scope_resolves_two_dots():
    r = extract_sublime_fields(
        'any(attachments, any(file.explode(.), ..file_type == "html" and any(.scan.strings.strings, . =~ "VIEW RFP DOCUMENT")))'
    )
    assert _obs(r, "attachments.file_type")[0].values == ["html"]
    assert _obs(r, "file.explode.scan.strings.strings")[0].values == ["VIEW RFP DOCUMENT"]


def test_transforms_are_not_predicates_and_list_members_count():
    r = extract_sublime_fields(
        'strings.concat(sender.display_name, " (", sender.email.email, ")") == "x" '
        "and any([body.current_thread.text, subject.subject], regex.icontains(., 'job offer'))"
    )
    assert _obs(r, "sender.display_name") == []
    assert "subject.subject" in r.fields_used and "body.current_thread.text" in r.fields_used


def test_field_map_for_resolved_paths():
    r = extract_sublime_fields(
        'any(body.links, .href_url.scheme == "mailto") and any(file.explode(attachments), any(.scan.url.urls, .domain.domain == "doc.clickup.com"))'
    )
    assert (_obs(r, "body.links.href_url.scheme")[0].type, _obs(r, "body.links.href_url.scheme")[0].subtype) == ("email", "url")
    o = _obs(r, "file.explode.scan.url.urls.domain.domain")[0]
    assert (o.type, o.subtype) == ("email", "url")
