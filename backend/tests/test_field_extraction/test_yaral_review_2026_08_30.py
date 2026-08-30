"""Fixes from the 2026-08-30 semantic review of production YARA-L rules.

Each test pins a failure reproduced on live Google SecOps rules:
  - `//` inside a string literal (`"https://..."`) was stripped as a
    comment, losing the URL and swallowing the following lines into
    the value.
  - Regex bodies (`= /.../`, `re.regex(...)`) landed verbatim on the
    target_resources / api_actions / network_indicators surfaces.
  - `target.resource.attribute.labels["visibility"] = "people_with_link"`
    put the label VALUE on target_resources.
  - A lowercased, `\\\\`-escaped registry key never reached
    registry_keys (surface check was case-sensitive on `\\CurrentVersion\\`
    and the literal kept its YARA-L escaping).
  - `graph.relations.relationship = "EXECUTES"` classified as
    network/network_field (`"ip" in "relationship"` heuristic).
"""

from app.services.taxonomy.canonical import is_valid_observable
from app.services.yaral_extractor import _strip_comments, extract_yaral_fields


def _obs(result, field):
    return [o for o in result.observables if o.field == field]


# -- 1. Comment stripping must respect string / regex literals --------------


URL_THEN_COMMENT = '''
  events:
    $group.metadata.event_type = "NETWORK_HTTP"
    $group.target.url = "https://graph.microsoft.com/v1.0/groups" nocase
    // real comment: the method is checked below
    $group.network.http.method = "GET"
  condition:
    $group
'''


class TestCommentStripping:
    def test_url_literal_survives_and_following_line_is_separate(self):
        r = extract_yaral_fields(URL_THEN_COMMENT)
        url = _obs(r, "target.url")
        assert url and url[0].values == ["https://graph.microsoft.com/v1.0/groups"]
        method = _obs(r, "network.http.method")
        assert method and method[0].values == ["GET"]
        assert "https://graph.microsoft.com/v1.0/groups" in r.network_indicators
        # The comment text never becomes part of a value or a field.
        assert not any("real comment" in v for o in r.observables for v in o.values)
        assert not any("comment" in f for f in r.fields_used)

    def test_scanner_skips_literals_and_strips_line_and_block_comments(self):
        text = (
            '$e.target.url = "http://a/b" // trailing\n'
            '$e.x = `raw//not-a-comment` /* block\ncomment */ $e.y = /re\\/x/ // c2\n'
            '$e.z = "q" // tail'
        )
        out = _strip_comments(text)
        assert '"http://a/b"' in out
        assert "trailing" not in out
        assert "`raw//not-a-comment`" in out
        assert "block" not in out and "comment */" not in out
        # Regex literal with an escaped slash is preserved verbatim and
        # the `//` after it is still a comment.
        assert "/re\\/x/" in out
        assert "c2" not in out
        assert "tail" not in out
        # Line structure is preserved (the events regex is line-aware).
        assert out.count("\n") == text.count("\n")

    def test_escaped_quote_inside_string_does_not_end_literal(self):
        text = '$e.a = "say \\"hi\\" // still string" // comment\n$e.b = "x"'
        out = _strip_comments(text)
        assert 'still string"' in out
        assert "comment" not in out
        assert '$e.b = "x"' in out


# -- 2. Regex values stay off the flat surfaces -----------------------------


REGEX_RESOURCE = '''
  events:
    $ws.metadata.event_type = "USER_RESOURCE_ACCESS"
    $ws.target.resource.name = /.*token|.*assig|.*ps2xml/
    $ws.metadata.product_event_type = /DenialOfService/
    $ws.target.url = /login\\.microsoftonline\\.com/ nocase
    re.regex($ws.target.process.command_line, `(?i)-enc\\s+[A-Za-z0-9+/=]{20,}`)
  condition:
    $ws
'''


class TestRegexValuesOffSurfaces:
    def test_regex_resource_name_keeps_observable_not_surface(self):
        r = extract_yaral_fields(REGEX_RESOURCE)
        res = _obs(r, "target.resource.name")
        assert res and res[0].values == [".*token|.*assig|.*ps2xml"]
        assert res[0].type == "cloud" and res[0].subtype == "resource"
        assert r.target_resources == []

    def test_regex_product_event_type_is_not_an_api_action(self):
        r = extract_yaral_fields(REGEX_RESOURCE)
        pet = _obs(r, "metadata.product_event_type")
        assert pet and pet[0].values == ["DenialOfService"]
        assert r.api_actions == []
        assert r.event_ids == []

    def test_regex_url_is_not_a_network_indicator(self):
        r = extract_yaral_fields(REGEX_RESOURCE)
        url = _obs(r, "target.url")
        assert url and url[0].values == ["login\\.microsoftonline\\.com"]
        assert r.network_indicators == []

    def test_re_regex_command_line_keeps_pattern_observable(self):
        r = extract_yaral_fields(REGEX_RESOURCE)
        cl = _obs(r, "target.process.command_line")
        assert cl and cl[0].subtype == "command_line_pattern"
        assert cl[0].values == ["(?i)-enc\\s+[A-Za-z0-9+/=]{20,}"]
        # The pattern body is not a process name / path / indicator.
        assert r.process_names == []
        assert r.file_paths == []
        assert r.network_indicators == []

    def test_literal_values_still_reach_surfaces(self):
        body = '''
  events:
    $e.target.resource.name = "projects/prod/secrets/db-password"
    $e.metadata.product_event_type = "google.iam.admin.v1.CreateServiceAccountKey"
    $e.target.url = "https://evil.example/payload"
  condition:
    $e
'''
        r = extract_yaral_fields(body)
        assert r.target_resources == ["projects/prod/secrets/db-password"]
        assert r.api_actions == ["google.iam.admin.v1.CreateServiceAccountKey"]
        assert r.network_indicators == ["https://evil.example/payload"]


# -- 3. Resource attribute labels are request parameters --------------------


LABELS = '''
  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
    $e.target.resource.attribute.labels["visibility"] = "people_with_link"
    $e.target.resource.attribute.labels["enable"] = "false"
    $e.target.resource.name = "Shared Drive Finance"
  condition:
    $e
'''


class TestResourceLabels:
    def test_label_values_never_reach_target_resources(self):
        r = extract_yaral_fields(LABELS)
        assert "people_with_link" not in r.target_resources
        assert "false" not in r.target_resources
        assert r.target_resources == ["Shared Drive Finance"]

    def test_label_observable_is_typed_cloud_request_params(self):
        r = extract_yaral_fields(LABELS)
        vis = _obs(r, "target.resource.attribute.labels.visibility")
        assert vis and vis[0].values == ["people_with_link"]
        assert (vis[0].type, vis[0].subtype) == ("cloud", "request_params")
        en = _obs(r, "target.resource.attribute.labels.enable")
        assert en and en[0].values == ["false"]
        assert (en[0].type, en[0].subtype) == ("cloud", "request_params")
        assert "target.resource.attribute.labels.visibility" in r.fields_used


# -- 4. Lowercased, escaped registry keys ------------------------------------


LSASS_REGISTRY = '''
  events:
    $registry.metadata.event_type = "REGISTRY_CREATION"
    strings.contains(strings.to_lower($registry.target.registry.registry_key), "microsoft\\\\windows nt\\\\currentversion\\\\silentprocessexit\\\\lsass.exe")
  condition:
    $registry
'''


class TestRegistrySurface:
    def test_lowercased_escaped_key_reaches_registry_keys(self):
        r = extract_yaral_fields(LSASS_REGISTRY)
        key = _obs(r, "target.registry.registry_key")
        assert key and key[0].type == "registry"
        # YARA-L `\\\\` is one backslash in the matched value.
        assert key[0].values == [
            "microsoft\\windows nt\\currentversion\\silentprocessexit\\lsass.exe"
        ]
        assert r.registry_keys == [
            "microsoft\\windows nt\\currentversion\\silentprocessexit\\lsass.exe"
        ]

    def test_double_quoted_literal_escapes_are_unescaped(self):
        body = r'''
  events:
    $e.target.registry.registry_key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    $e.target.file.full_path = "C:\\Windows\\Temp\\x.exe"
  condition:
    $e
'''
        r = extract_yaral_fields(body)
        assert r.registry_keys == ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]
        assert r.file_paths == ["C:\\Windows\\Temp\\x.exe"]

    def test_backtick_literal_is_raw(self):
        body = '''
  events:
    re.regex($e.target.process.file.full_path, `\\\\powershell\\.exe$`) nocase
  condition:
    $e
'''
        r = extract_yaral_fields(body)
        path = _obs(r, "target.process.file.full_path")
        # Raw literal: the regex body is kept exactly as written.
        assert path and path[0].values == ["\\\\powershell\\.exe$"]
        assert "powershell.exe" in r.process_names


# -- 5. YARA-L scope overrides for misclassified UDM paths ------------------


GRAPH = '''
  events:
    $e.graph.relations.relationship = "EXECUTES"
    $e.graph.entity.file.prevalence.day_count = 1
    $e.graph.entity.file.prevalence.rolling_max < 5
  condition:
    $e
'''


class TestScopeOverrides:
    def test_relationship_is_event_action_not_network(self):
        r = extract_yaral_fields(GRAPH)
        rel = _obs(r, "graph.relations.relationship")
        assert rel and rel[0].values == ["EXECUTES"]
        assert (rel[0].type, rel[0].subtype) == ("event", "event_action")
        assert r.network_indicators == []
        assert r.api_actions == []

    def test_prevalence_is_pinned_file_subtype(self):
        r = extract_yaral_fields(GRAPH)
        prev = _obs(r, "graph.entity.file.prevalence.day_count")
        assert prev and prev[0].values == ["1"]
        assert prev[0].type == "file"
        assert is_valid_observable(prev[0].type, prev[0].subtype)
        assert "graph.entity.file.prevalence.rolling_max" in r.fields_used
        assert r.file_paths == []

    def test_every_emitted_pair_is_pinned(self):
        for body in (URL_THEN_COMMENT, REGEX_RESOURCE, LABELS, LSASS_REGISTRY, GRAPH):
            for o in extract_yaral_fields(body).observables:
                assert is_valid_observable(o.type, o.subtype), (o.field, o.type, o.subtype)
