"""Deterministic metadata-completeness scoring (issue #10; reworked
for teardown F09 / #85).

0-100, computed at ingest time from the normalized rule. Stored as
`quality_score` (int) + `quality_details` (JSON: per-dimension score +
issue list). This measures rule metadata completeness per DEBMM Tier 1
conventions -- documentation, mapping, specificity, testability --
explicitly NOT detection efficacy: a noisy rule can score 95 and a
brilliant one 40.

**Scored against what the format can express** (rubric v2). The v1
rubric scored every rule against the same 100 points, which turned the
score into a schema-similarity leaderboard: an excellent Sublime MQL
rule lost 20 points for ATT&CK tags MQL cannot carry and 8 more for a
false-positive field its format does not have. Each source now has a
capability profile listing the checks its format/repo conventions
cannot express; those checks are excluded from both the numerator and
the denominator, and the total is renormalized to 100 over the
applicable points. Skipped checks are reported per dimension under
`na` (by their issue string) so the UI can mark them "n/a for this
format" rather than failed.

Profiles are grounded in measured field presence (50 recent rules per
source, 2026-08-31): a check is inapplicable only where presence is
~0% because the FORMAT lacks the field, not merely because authors
skip it.

Deterministic on purpose: same rule in, same score out, no models, no
randomness. Score changes therefore mean the RULE changed (or the
rubric version did -- bump RUBRIC_VERSION on any weight change and let
the nightly re-ingest recompute the corpus; no migrations).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.normalizers.base import NormalizedDetection

RUBRIC_VERSION = 2

# ---------------------------------------------------------------------------
# Capability profiles: check ids a source's format / repo conventions
# cannot express. "mitre" excludes the whole ATT&CK dimension.
# ---------------------------------------------------------------------------
_CHECKS_ALL = frozenset({
    "author", "references", "mitre", "false_positives",
    "atomic", "intel_ref", "embedded_tests",
})

INAPPLICABLE: dict[str, frozenset[str]] = {
    # Panther python rules carry no author field (attribution is the repo).
    "panther": frozenset({"author", "embedded_tests"}),
    "pypanther": frozenset({"author"}),
    # Sublime MQL: no ATT&CK tags, no false-positive field, no author
    # field; Atomic Red Team has no email atomics and the repo's test
    # suites live outside the rule file.
    "sublime": frozenset({"author", "mitre", "false_positives", "atomic", "embedded_tests"}),
    # Sentinel YAML: no references / falsePositives keys.
    "sentinel": frozenset({"references", "intel_ref", "false_positives", "embedded_tests"}),
    "elastic_protections": frozenset({"references", "intel_ref", "false_positives", "embedded_tests"}),
    # Chronicle YARA-L community rules: no ATT&CK meta, no FP field.
    "google_secops": frozenset({"mitre", "false_positives", "embedded_tests"}),
    "elastic_hunting": frozenset({"false_positives", "embedded_tests"}),
    # Formats with no embedded-test convention (Splunk `tests:` and
    # Panther `RuleTest(` are the two we can detect).
    "elastic": frozenset({"embedded_tests"}),
    "sigma": frozenset({"embedded_tests"}),
    # LOLRMM is an RMM-tool catalog: its references document the tool
    # itself (vendor sites), and neither Atomic Red Team nor
    # threat-research writeups exist per RMM entry -- the "why" is the
    # tool being an RMM, stated in every rule.
    "lolrmm": frozenset({"atomic", "intel_ref", "embedded_tests"}),
    "okta": frozenset({"embedded_tests"}),
    "auth0": frozenset({"embedded_tests"}),
}

# Issue strings for skipped checks -- the UI matches checks by these,
# so a skipped check is marked n/a instead of failed.
_NA_ISSUE = {
    "author": "no author",
    "references": "no references",
    "false_positives": ["no false-positive analysis", "false positives are boilerplate, not analysis"],
    "atomic": "no Atomic Red Team reference",
    "intel_ref": "no threat-research reference",
    "embedded_tests": "no embedded test cases",
}

# False-positive entries that are boilerplate, not analysis. Compared
# on normalized (lowercase, stripped) full-entry equality — substring
# matching would wrongly flag real analysis that MENTIONS these words.
_BOILERPLATE_FPS = frozenset({
    "unknown", "none", "unlikely", "n/a", "na", "tbd", "-",
    "legitimate admin activity", "legitimate administrative activity",
    "legitimate administrator activity", "administrative activity",
    "legitimate use", "legitimate usage", "rare legitimate use",
})

# Words that signal the description/FP text tells an analyst what to
# DO, not just what fired.
_INVESTIGATION_CUES = re.compile(
    r"\b(investigat|verify|confirm|review|triage|correlate|check whether|"
    r"check if|validate|baseline|if confirmed|escalat|follow.?up)",
    re.IGNORECASE,
)

_ATOMIC_RE = re.compile(r"atomic[\s_-]?red[\s_-]?team|atomics/T\d{4}", re.IGNORECASE)

# Threat-research outlets: a reference pointing at actual intel gives
# the rule a reproducible "why". Deliberately a recognizable-name list,
# not "any URL" — vendor doc links score under metadata, not here.
_INTEL_REF_RE = re.compile(
    r"thedfirreport\.com|redcanary\.com|mandiant\.com|unit42\.paloaltonetworks|"
    r"elastic\.co/security-labs|splunk\.com/en_us/blog|crowdstrike\.com/blog|"
    r"sentinelone\.com/labs|microsoft\.com/en-us/security/blog|huntress\.com|"
    r"welivesecurity\.com|securelist\.com|talosintelligence\.com|"
    r"research\.checkpoint\.com|cisa\.gov|trendmicro\.com/en_us/research|"
    r"wiz\.io/blog|dfir\.ch|thehackernews\.com|virustotal\.com/gui|"
    r"blog\.(?:google|talosintelligence|sekoia)",
    re.IGNORECASE,
)

_EMULATION_RE = re.compile(
    r"caldera|attack[\s_-]?range|stratus[\s_-]?red[\s_-]?team|simuland|"
    r"purple[\s_-]?team|detection[\s_-]?lab|threat[\s_-]?emulation|prelude",
    re.IGNORECASE,
)

# Vendor-embedded test blocks in raw rule content.
_EMBEDDED_TESTS_RE = re.compile(
    r"^tests:|\bRuleTest\(|^Tests:\s*$|unit_tests:", re.IGNORECASE | re.MULTILINE
)


def _mark_na(na_out: list[str], check: str) -> None:
    marker = _NA_ISSUE.get(check)
    if isinstance(marker, list):
        na_out.extend(marker)
    elif marker:
        na_out.append(marker)


def _dim(score: int, of: int, issues: list[str], na: list[str]) -> dict:
    return {"score": min(score, of), "of": of, "issues": issues, "na": na}


def _score_metadata(n: "NormalizedDetection", skip: frozenset[str]) -> dict:
    issues: list[str] = []
    na: list[str] = []
    score = 0
    of = 20
    if n.title and len(n.title.strip()) >= 10:
        score += 4
    else:
        issues.append("title missing or trivial")
    if n.description and len(n.description.strip()) >= 20:
        score += 4
    else:
        issues.append("no meaningful description")
    if n.rule_id:
        score += 3
    else:
        issues.append("no stable rule id")
    if "author" in skip:
        of -= 3
        _mark_na(na, "author")
    elif n.author:
        score += 3
    else:
        issues.append("no author")
    if "references" in skip:
        of -= 3
        _mark_na(na, "references")
    elif n.references:
        score += 3
    else:
        issues.append("no references")
    if n.rule_created_date or n.rule_modified_date:
        score += 3
    else:
        issues.append("no creation/modification date")
    return _dim(score, of, issues, na)


def _score_mitre(n: "NormalizedDetection") -> dict:
    issues: list[str] = []
    score = 0
    techniques = n.mitre_techniques or []
    if techniques:
        score += 8
        if len(techniques) >= 2:
            score += 3
        if any("." in t for t in techniques):
            score += 3
        else:
            issues.append("no sub-technique precision")
    else:
        issues.append("no ATT&CK technique mapping")
    if n.mitre_tactics:
        score += 4
    else:
        issues.append("no ATT&CK tactic")
    if (n.mitre_groups or []) or (n.mitre_software or []):
        score += 2
    return _dim(score, 20, issues, [])


def _score_specificity(n: "NormalizedDetection") -> dict:
    issues: list[str] = []
    complexity_pts = {"simple": 4, "moderate": 8, "complex": 12}
    score = complexity_pts.get((n.query_complexity or "").lower(), 0)
    if score == 0:
        issues.append("query complexity unknown")
    fields = n.extracted_fields_used or []
    score += min(len(fields), 8)
    if not fields:
        issues.append("no telemetry fields extracted")
    return _dim(score, 20, issues, [])


def _score_documentation(n: "NormalizedDetection", skip: frozenset[str]) -> dict:
    issues: list[str] = []
    na: list[str] = []
    score = 0
    of = 20
    desc = (n.description or "").strip()
    if len(desc) >= 200:
        score += 8
    elif len(desc) >= 80:
        score += 5
    elif len(desc) >= 20:
        score += 2
    else:
        issues.append("description too short to guide triage")

    fps = [f.strip() for f in (n.false_positives or []) if isinstance(f, str) and f.strip()]
    if "false_positives" in skip:
        of -= 8
        _mark_na(na, "false_positives")
    else:
        concrete = [
            f for f in fps
            if f.lower().strip(".") not in _BOILERPLATE_FPS and len(f) >= 20
        ]
        if concrete:
            score += 8
        elif fps:
            score += 3
            issues.append("false positives are boilerplate, not analysis")
        else:
            issues.append("no false-positive analysis")

    cue_text = " ".join([desc, " ".join(fps)])
    if _INVESTIGATION_CUES.search(cue_text):
        score += 4
    else:
        issues.append("no investigation guidance")
    return _dim(score, of, issues, na)


def _score_testability(n: "NormalizedDetection", skip: frozenset[str]) -> dict:
    issues: list[str] = []
    na: list[str] = []
    score = 0
    of = 20
    refs = " ".join(r for r in (n.references or []) if isinstance(r, str))
    tags = " ".join(t for t in (n.tags or []) if isinstance(t, str))
    haystack = " ".join([refs, tags])
    has_atomic = bool(_ATOMIC_RE.search(haystack))

    if "atomic" in skip:
        of -= 8
        _mark_na(na, "atomic")
    elif has_atomic:
        score += 8
    else:
        issues.append("no Atomic Red Team reference")

    if "intel_ref" in skip:
        of -= 6
        _mark_na(na, "intel_ref")
    elif _INTEL_REF_RE.search(refs):
        score += 6
    else:
        issues.append("no threat-research reference")

    if _EMULATION_RE.search(haystack):
        score += 3

    if "embedded_tests" in skip:
        of -= 3
        _mark_na(na, "embedded_tests")
    elif n.raw_content and _EMBEDDED_TESTS_RE.search(n.raw_content):
        score += 3
    elif not has_atomic:
        issues.append("no embedded test cases")
    return _dim(score, of, issues, na)


def score_detection(n: "NormalizedDetection") -> tuple[int, dict]:
    """Score one normalized rule. Returns (total, details-json).

    Total is renormalized to 100 over the points the rule's format can
    actually express, so an MQL email rule and a Sigma rule are graded
    on their own applicable rubric, not each other's schema.
    """
    skip = INAPPLICABLE.get(n.source, frozenset())
    dimensions = {"metadata": _score_metadata(n, skip)}
    if "mitre" not in skip:
        dimensions["mitre"] = _score_mitre(n)
    dimensions["specificity"] = _score_specificity(n)
    dimensions["documentation"] = _score_documentation(n, skip)
    dimensions["testability"] = _score_testability(n, skip)

    raw = sum(d["score"] for d in dimensions.values())
    applicable = sum(d["of"] for d in dimensions.values())
    total = round(100 * raw / applicable) if applicable else 0
    return total, {
        "version": RUBRIC_VERSION,
        "total": total,
        "raw": raw,
        "applicable_points": applicable,
        "dimensions": dimensions,
    }
