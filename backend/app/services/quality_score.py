"""Deterministic rule-hygiene scoring (issue #10).

0-100, five dimensions x 20 points, computed at ingest time from the
normalized rule. Stored as `quality_score` (int) + `quality_details`
(JSON: per-dimension score + issue list). This is a HYGIENE score per
DEBMM Tier 1 conventions — metadata completeness, mapping, docs,
testability — explicitly NOT detection efficacy: a noisy rule can
score 95 and a brilliant one 40.

Deterministic on purpose: same rule in, same score out, no models, no
randomness. Score changes therefore mean the RULE changed (or the
rubric version did — bump RUBRIC_VERSION on any weight change and let
the nightly re-ingest recompute the corpus; no migrations).

Depends on the extraction rebuild (issue #6): the specificity
dimension reads `query_complexity` and `extracted_fields_used`, which
were noise before the per-source extractors were rebuilt.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.normalizers.base import NormalizedDetection

RUBRIC_VERSION = 1

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


def _dim(score: int, of: int, issues: list[str]) -> dict:
    return {"score": min(score, of), "of": of, "issues": issues}


def _score_metadata(n: "NormalizedDetection") -> dict:
    issues: list[str] = []
    score = 0
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
    if n.author:
        score += 3
    else:
        issues.append("no author")
    if n.references:
        score += 3
    else:
        issues.append("no references")
    if n.rule_created_date or n.rule_modified_date:
        score += 3
    else:
        issues.append("no creation/modification date")
    return _dim(score, 20, issues)


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
    return _dim(score, 20, issues)


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
    return _dim(score, 20, issues)


def _score_documentation(n: "NormalizedDetection") -> dict:
    issues: list[str] = []
    score = 0
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
    return _dim(score, 20, issues)


def _score_testability(n: "NormalizedDetection") -> dict:
    issues: list[str] = []
    score = 0
    refs = " ".join(r for r in (n.references or []) if isinstance(r, str))
    tags = " ".join(t for t in (n.tags or []) if isinstance(t, str))
    haystack = " ".join([refs, tags])

    if _ATOMIC_RE.search(haystack):
        score += 8
    else:
        issues.append("no Atomic Red Team reference")
    if _INTEL_REF_RE.search(refs):
        score += 6
    else:
        issues.append("no threat-research reference")
    if _EMULATION_RE.search(haystack):
        score += 3
    if n.raw_content and _EMBEDDED_TESTS_RE.search(n.raw_content):
        score += 3
    elif not _ATOMIC_RE.search(haystack):
        issues.append("no embedded test cases")
    return _dim(score, 20, issues)


def score_detection(n: "NormalizedDetection") -> tuple[int, dict]:
    """Score one normalized rule. Returns (total, details-json)."""
    dimensions = {
        "metadata": _score_metadata(n),
        "mitre": _score_mitre(n),
        "specificity": _score_specificity(n),
        "documentation": _score_documentation(n),
        "testability": _score_testability(n),
    }
    total = sum(d["score"] for d in dimensions.values())
    return total, {
        "version": RUBRIC_VERSION,
        "total": total,
        "dimensions": dimensions,
    }
