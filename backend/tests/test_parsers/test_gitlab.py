"""GitLab TLDR parser: Sigma documents embedded in Markdown.

The fixture below is synthetic but carries every shape the upstream
files use, plus the traps that would make a naive Markdown reader miss
or invent rules:

- headings inside shell fences (`# Admin area` comments);
- a ```yaml fence nested in a list item (an atomic-test snippet);
- a ```yaml fence OUTSIDE ``## Detection``;
- a multi-document fence (base rules + a correlation) and a second,
  supplementary fence with a correlation of correlations;
- sample events marked [match] / [no-match], whose JSON must not leak
  into the prose fields.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.parsers.gitlab import GitLabParser

THREAT_PATH = Path("Detections/platforms/GitLab/Threat Detections/bulk_access.md")
VULN_PATH = Path("Detections/platforms/GitLab/Vulnerability Detections/lfi_probe.md")

BULK_ACCESS_MD = """\
---
schema: 1
offering: [saas, self-managed]
tier: [premium, ultimate]
log_sources: [api_json, audit, production_json]
audit_events: [repository_git_operation]
detects_from: "17.2"
sample_source: lab-capture
scenarios: [data-exfiltration, some-new-scenario]
cicd_techniques: [cicd.exfiltration.clone_git_repositories]
---

# About

This detection watches bulk repository reads.

## Understanding The Threat

An adversary clones everything.

## Logs

The signal is in `api_json.log` and `production_json.log`.

- Linux package: `/var/log/gitlab/gitlab-rails/api_json.log`

### Sample Event Logs

Captured on a lab instance.

<details>
<summary>Archive download [match: GitLab bulk repository access]</summary>

```json
{"method": "GET", "route": "/api/:version/projects/:id/repository/archive", "status": 200, "SAMPLE_MARKER": 1}
```

</details>
<details>
<summary>Project listing [no-match]</summary>

```json
{"method": "GET", "route": "/api/:version/projects", "status": 200}
```

</details>

## Detection

The logic is two base rules and a correlation; deploy the correlation.

```yaml
title: GitLab repository read through the API
id: 11111111-1111-4111-8111-111111111111
name: gitlab_repo_read_api
status: experimental
description: Base rule, successful repository archive reads through the REST API.
references:
    - https://docs.gitlab.com/api/repositories/
author: Example Author
date: 2026-10-01
modified: 2026-11-02
tags:
    - attack.collection
    - attack.t1213.003
    - gitlab.selfmanaged
logsource:
    product: gitlab
    service: api_json.log
    category: application
detection:
    selection:
        method: GET
        route: '/api/:version/projects/:id/repository/archive'  # the archive endpoint
        status: 200
    filter_known_sources:
        remote_ip|cidr: '198.51.100.0/24'
    condition: selection and not filter_known_sources
falsepositives:
    - Backup jobs that archive every repository nightly; verify the token belongs to the backup service.
level: informational
---
title: GitLab repository fetched over HTTP
id: 22222222-2222-4222-8222-222222222222
name: gitlab_repo_read_ui
status: experimental
description: Base rule, Git fetches served by the Rails controller.
references:
    - https://docs.gitlab.com/administration/logs/
author: Example Author
date: 2026-10-01
tags:
    - attack.collection
    - attack.t1213.003
    - gitlab.selfmanaged
logsource:
    product: gitlab
    service: production_json.log
    category: application
detection:
    selection:
        controller: 'Repositories::GitHttpController'
        action: git_upload_pack
    condition: selection
falsepositives:
    - CI runners cloning repositories.
level: low
---
title: GitLab bulk repository access
id: 33333333-3333-4333-8333-333333333333
name: gitlab_bulk_repo_access
status: experimental
description: One account reading many projects in an hour.
references:
    - https://docs.gitlab.com/api/repositories/
author: Example Author
date: 2026-10-01
tags:
    - attack.collection
    - attack.defense_impairment
    - attack.t1213.003
    - gitlab.selfmanaged
correlation:
    type: value_count
    rules:
        - gitlab_repo_read_api
        - gitlab_repo_read_ui
    group-by:
        - username
    timespan: 1h
    condition:
        field: meta.project
        gte: 20
falsepositives:
    - Migrations.
level: high
```

Where correlations of correlations are supported, wrap it:

```yaml
title: GitLab bulk repository harvesting
id: 44444444-4444-4444-8444-444444444444
status: experimental
description: The bulk access correlation seen repeatedly.
references:
    - https://docs.gitlab.com/api/repositories/
author: Example Author
date: 2026-10-01
tags:
    - attack.collection
    - gitlab.selfmanaged
correlation:
    type: temporal
    rules:
        - gitlab_bulk_repo_access
    group-by:
        - username
    timespan: 1h
falsepositives:
    - Migrations.
level: high
```

### Raw Log Query

```shell
# Admin area and project settings
zgrep -h archive /var/log/gitlab/gitlab-rails/api_json.log*
```

### Atomic Test

#### Test Steps

1. Download one archive:

   ```shell
   # REST API
   curl --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects/1/repository/archive"
   ```

2. A tuning example that is not a rule:

   ```yaml
   logsource:
       product: gitlab
   detection:
       selection: {method: GET}
   ```

## Response

1. Initial Assessment
   - Identify the actor.

### References

- [GitLab Docs: Repositories API](https://docs.gitlab.com/api/repositories/)
"""

LFI_MD = """\
---
schema: 1
offering: [self-managed]
tier: [free, premium, ultimate]
log_sources: [api_json]
cves:
  - id: CVE-2099-0001
    affected:
      - {from: "18.7", before: "18.11.12"}
      - {before: "19.0.9"}
    fixed_in: ["18.11.12", "19.0.9"]
    advisory_url: https://example.com/advisory/CVE-2099-0001
    last_verified: "2026-10-28"
  - id: CVE-2099-0002
    affected:
      - {from: "19.0", before: "19.0.9"}
    fixed_in: ["19.0.9"]
    advisory_url: https://example.com/advisory/CVE-2099-0002
    last_verified: "2026-10-28"
sample_source: constructed
scenarios: [compromised-instance]
---

# About

LFI probing.

## Logs

### Sample Event Logs

Values outside the temp directories are anomalous.

<details>
<summary>Probe [match]</summary>

```json
{"status": 400}
```

</details>

## Detection

```yaml
title: GitLab LFI probe
id: 55555555-5555-4555-8555-555555555555
status: experimental
description: Unauthenticated metadata.path outside the temp directories.
author: Example Author
date: 2026-09-14
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2099-0001
    - gitlab.selfmanaged
logsource:
    category: application
    product: gitlab
    service: api_json.log
detection:
    selection:
        params|contains: 'metadata.path'
    condition: selection
falsepositives:
    - Authorized scanner.
level: high
```

## Response

Rotate credentials.
"""


@pytest.fixture
def parser():
    return GitLabParser()


@pytest.fixture
def rules(parser):
    out = parser.parse_all(THREAT_PATH, BULK_ACCESS_MD)
    assert out is not None
    return {r.extra["id"][:1]: r for r in out}


# -- can_parse: path components, not substrings ------------------------------


@pytest.mark.parametrize("path, expected", [
    ("Detections/platforms/GitLab/Threat Detections/deploy_key_created.md", True),
    ("Detections/platforms/GitLab/Vulnerability Detections/lfi.md", True),
    ("/data/repos/gitlab/Detections/platforms/GitLab/Threat Detections/x.md", True),
    # Not Markdown.
    ("Detections/platforms/GitLab/Threat Detections/x.yml", False),
    # Repo docs and tooling are not detections.
    ("README.md", False),
    ("docs/CONTRACT.md", False),
    ("skills/tldr/references/gitlab-logs-and-audit-events.md", False),
    # A sibling platform, and a name that merely STARTS with gitlab.
    ("Detections/platforms/GitHub/Threat Detections/x.md", False),
    ("Detections/platforms/GitLabRunner/Threat Detections/x.md", False),
    # The clone directory is called gitlab; that alone must not match.
    ("/data/repos/gitlab/docs/platforms/x.md", False),
    ("Detections/platforms/GitLab/tests/x.md", False),
])
def test_can_parse(parser, path, expected):
    assert parser.can_parse(Path(path)) is expected


# -- document discovery ------------------------------------------------------


def test_every_sigma_document_becomes_a_rule(parser):
    out = parser.parse_all(THREAT_PATH, BULK_ACCESS_MD)
    assert [r.title for r in out] == [
        "GitLab repository read through the API",
        "GitLab repository fetched over HTTP",
        "GitLab bulk repository access",
        "GitLab bulk repository harvesting",
    ]
    assert len({r.extra["id"] for r in out}) == 4
    assert all(r.source == "gitlab" and r.file_path == str(THREAT_PATH) for r in out)


def test_list_item_yaml_fence_is_not_a_rule(parser):
    """The atomic-test tuning snippet has `logsource:` but is nested in
    a list item; upstream's own parser ignores those and so do we."""
    out = parser.parse_all(THREAT_PATH, BULK_ACCESS_MD)
    assert len(out) == 4


def test_yaml_fence_outside_detection_section_is_ignored(parser):
    text = BULK_ACCESS_MD.replace(
        "## Understanding The Threat\n",
        "## Understanding The Threat\n\n```yaml\ntitle: Not a rule\nlogsource:\n    product: gitlab\n"
        "detection:\n    selection: {a: b}\n    condition: selection\n```\n",
    )
    assert "Not a rule" not in [r.title for r in parser.parse_all(THREAT_PATH, text)]


def test_parse_returns_the_first_document(parser):
    assert parser.parse(THREAT_PATH, BULK_ACCESS_MD).title == "GitLab repository read through the API"


@pytest.mark.parametrize("text", [
    "",
    "# About\n\nNo detection section here.\n",
    "# About\n\n## Detection\n\nProse only.\n",
    "# About\n\n## Detection\n\n```yaml\ntitle: [unclosed\nlogsource: {}\n```\n",
    # A Sigma-looking document with no title is not indexable.
    "## Detection\n\n```yaml\nid: x\nlogsource: {product: gitlab}\ndetection: {condition: a}\n```\n",
])
def test_files_without_usable_sigma_return_none(parser, text):
    assert parser.parse_all(THREAT_PATH, text) is None
    assert parser.parse(THREAT_PATH, text) is None


def test_missing_frontmatter_still_yields_the_rules(parser):
    body = BULK_ACCESS_MD.split("---\n", 2)[2]
    out = parser.parse_all(THREAT_PATH, body)
    assert len(out) == 4
    assert out[0].extra["scenarios"] == []


def test_crlf_and_bom_are_tolerated(parser):
    text = "﻿" + BULK_ACCESS_MD.replace("\n", "\r\n")
    out = parser.parse_all(THREAT_PATH, text)
    assert len(out) == 4
    assert "\r" not in out[0].raw_content


# -- per-document content ----------------------------------------------------


def test_rule_metadata(rules):
    r = rules["1"]
    assert r.status == "experimental"
    assert r.severity == "informational"
    assert r.author == "Example Author"
    assert r.log_source == {
        "product": "gitlab", "category": "application",
        "service": "api_json.log", "services": ["api_json.log"],
    }
    assert r.mitre_attack["techniques"] == ["T1213.003"]
    assert r.mitre_attack["tactics"] == ["TA0009"]
    assert r.detection_logic_raw["condition"] == "selection and not filter_known_sources"
    assert r.extra["references"] == ["https://docs.gitlab.com/api/repositories/"]
    assert r.extra["slug"] == "bulk_access"
    assert r.extra["detection_type"] == "threat"
    assert str(r.extra["date"]) == "2026-10-01" and str(r.extra["modified"]) == "2026-11-02"


def test_tags_keep_vendor_tags_and_add_file_level_ones(rules):
    assert rules["1"].tags == [
        "gitlab.selfmanaged", "tldr.threat", "cicd.exfiltration.clone_git_repositories",
    ]


def test_v18_tactic_tag_is_a_tactic_not_a_leftover_tag(rules):
    r = rules["3"]
    assert "TA0112" in r.mitre_attack["tactics"]
    assert "attack.defense_impairment" not in r.tags


def test_raw_content_is_the_documents_own_yaml_verbatim(rules):
    raw = rules["1"].raw_content
    assert raw.startswith("title: GitLab repository read through the API\n")
    # Comments survive: the text is sliced, not re-serialized.
    assert "# the archive endpoint" in raw
    assert "GitLab repository fetched over HTTP" not in raw
    assert raw.endswith("level: informational\n")
    assert "```" not in raw and "---" not in raw


def test_correlation_raw_content_is_deployable(rules):
    """A correlation is prefixed with the documents it references."""
    raw = rules["3"].raw_content
    docs = raw.split("\n---\n")
    assert [d.splitlines()[0] for d in docs] == [
        "title: GitLab repository read through the API",
        "title: GitLab repository fetched over HTTP",
        "title: GitLab bulk repository access",
    ]


def test_correlation_of_correlations_resolves_transitively(rules):
    r = rules["4"]
    assert r.extra["is_correlation"] is True
    # Fence 2 references a correlation in fence 1, which references the
    # two base rules: all three precede it, in file order.
    assert r.raw_content.count("\n---\n") == 3
    assert r.log_source["services"] == ["api_json.log", "production_json.log"]
    assert r.log_source["service"] is None
    assert len(r.extra["base_rules"]) == 2


def test_correlation_logic_and_logsource(rules):
    r = rules["3"]
    assert r.detection_logic_raw["correlation"]["type"] == "value_count"
    assert r.log_source["services"] == ["api_json.log", "production_json.log"]
    assert [b["logsource"]["service"] for b in r.extra["base_rules"]] == [
        "api_json.log", "production_json.log",
    ]


def test_building_block_needs_both_a_reference_and_informational_level(rules):
    # Referenced by the correlation and shipped at informational.
    assert rules["1"].extra["is_building_block"] is True
    # Referenced, but shipped at a real level: still alertable.
    assert rules["2"].extra["is_building_block"] is False
    # Correlations are never building blocks, referenced or not.
    assert rules["3"].extra["is_building_block"] is False
    assert rules["4"].extra["is_building_block"] is False


def test_scenarios_become_labels_and_unknown_slugs_survive(rules):
    assert rules["1"].extra["scenarios"] == ["Data exfiltration", "Some new scenario"]


# -- prose fields ------------------------------------------------------------


def test_guide_keeps_prose_and_drops_samples_sigma_and_references(rules):
    guide = rules["1"].extra["investigation_guide"]
    assert guide.startswith("# About")
    for kept in ("## Understanding The Threat", "## Detection", "### Raw Log Query",
                 "### Atomic Test", "## Response", "Identify the actor.",
                 "# Admin area and project settings"):
        assert kept in guide
    for dropped in ("schema: 1", "SAMPLE_MARKER", "## Logs", "<details>",
                    "title: GitLab repository read through the API",
                    "### References", "GitLab Docs: Repositories API"):
        assert dropped not in guide
    # The nested tuning snippet is prose, not a Sigma fence: it stays.
    assert "selection: {method: GET}" in guide
    assert "\n\n\n" not in guide


def test_every_rule_of_a_file_shares_the_guide(rules):
    assert len({r.extra["investigation_guide"] for r in rules.values()}) == 1


def test_deploy_notes_are_per_rule(rules):
    api = rules["1"].extra["deploy_notes"]
    assert "**Applies to:** GitLab.com (SaaS), GitLab Self-Managed (Premium, Ultimate)" in api
    assert "**Log source:** `api_json.log`" in api
    assert "production_json.log`  " not in api.split("\n\n")[0]
    assert "**Signal exists from:** GitLab 17.2" in api
    # Audit events are listed only on a rule that reads the audit log.
    assert "Audit events" not in api
    assert "The signal is in `api_json.log` and `production_json.log`." in api
    assert "SAMPLE_MARKER" not in api and "Captured on a lab instance" not in api
    corr = rules["3"].extra["deploy_notes"]
    assert "**Log source:** `api_json.log`, `production_json.log`" in corr


def test_sample_markers_and_atomic_test_are_recorded(rules):
    assert rules["1"].extra["samples"] == {"match": 1, "no_match": 1}
    assert rules["1"].extra["has_atomic_test"] is True


# -- vulnerability files -----------------------------------------------------


def test_vulnerability_file(parser):
    out = parser.parse_all(VULN_PATH, LFI_MD)
    assert len(out) == 1
    r = out[0]
    assert r.extra["detection_type"] == "vulnerability"
    assert r.tags == ["cve.2099-0001", "gitlab.selfmanaged", "tldr.vulnerability"]
    assert r.mitre_attack["tactics"] == ["TA0001"]
    # Only the CVE this document is tagged with contributes its advisory.
    assert r.extra["references"] == ["https://example.com/advisory/CVE-2099-0001"]
    notes = r.extra["deploy_notes"]
    assert "**CVE-2099-0001:** affects 18.7 up to (not including) 18.11.12; before 19.0.9. Fixed in 18.11.12, 19.0.9." in notes
    assert "CVE-2099-0002" not in notes
    # The Logs section opens with the samples heading: its introduction
    # is the collection note, the sample itself is not.
    assert "Values outside the temp directories are anomalous." in notes
    assert '"status": 400' not in notes
    assert r.extra["has_atomic_test"] is False
    assert r.extra["samples"] == {"match": 1, "no_match": 0}
