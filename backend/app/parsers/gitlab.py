"""GitLab TLDR detection parser.

GitLab's TLDR project (gitlab-security-oss/tldr) publishes each detection
as ONE Markdown file under ``Detections/platforms/GitLab/<kind>/``:

    ---                          <- YAML frontmatter (offering, tier,
    schema: 1                       log_sources, cves, scenarios, ...)
    ---
    # About
    ## Understanding The Threat
    ## Logs                      <- sample events in <details> blocks,
                                    each marked [match] / [no-match]
    ## Detection                 <- the Sigma, in ```yaml fences
    ### Raw Log Query
    ### Atomic Test
    ## Response
    ### References

The Sigma fence is multi-document: a file carries one to five Sigma
documents (a UI rule and an API rule, or base rules plus the
correlations that count them), and every document has its own UUID,
title, level and logsource. Upstream's contract freezes those UUIDs, so
the catalog indexes ONE ENTRY PER SIGMA DOCUMENT -- ``parse_all`` returns
them all; ``parse`` returns the first for callers that want one.

What each entry carries:

- the Sigma document's own metadata and logic (title, id, level, tags,
  logsource, detection / correlation);
- ``raw_content``: the document's YAML sliced verbatim from the file.
  A correlation is prefixed with the documents it references so the
  text is deployable as it stands;
- the file's prose, shared by every document in it: the investigation
  guide (the file minus frontmatter, sample events, Sigma fences and
  the reference list) and the deploy notes (offering, tier, log files,
  audit events, affected versions, plus the Logs section's own text).

Fence discovery follows upstream's parser (tldr/parse.py): only
unindented ``yaml`` fences inside ``## Detection`` that contain a
top-level ``logsource:`` or ``correlation:`` key are Sigma. Fences
nested in list items (atomic-test snippets) are not.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule
from app.parsers.sigma import SigmaParser

logger = logging.getLogger(__name__)

_SIGMA = SigmaParser()

# Markdown structure (same tolerances as upstream's parser).
_FENCE_OPEN_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})[ \t]*([^\s`]*)(?:[ \t]+[^`]*)?$")
_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
_LIST_ITEM_RE = re.compile(r"^ {0,3}(?:[-*+]|\d{1,9}[.)])[ \t]+\S")
_DETAILS_OPEN_RE = re.compile(r"<details\b[^>]*>", re.IGNORECASE)
_SUMMARY_RE = re.compile(r"<summary\b[^>]*>(.*?)</summary\s*>", re.IGNORECASE)
_LINE_SPLIT_RE = re.compile(r"\r\n|\n|\r")
_SIGMA_KEY_RE = re.compile(r"^(?:logsource|correlation):", re.MULTILINE)
_DOC_SEPARATOR_RE = re.compile(r"^---[ \t]*$")
# Sample marker at the end of a <summary>: [match], [match: <rule>], [no-match].
_MARKER_RE = re.compile(r"\[(match|no-match)(?::\s*([^\]]+))?\]\s*$")

_KIND_BY_DIR = {
    "threat detections": "threat",
    "vulnerability detections": "vulnerability",
}

# Frontmatter slug -> label. Unknown slugs fall back to a readable form
# of the slug, so a new upstream value is shown, not dropped.
_SCENARIO_TITLES = {
    "credential-exposure-and-token-abuse": "Credential exposure and token abuse",
    "compromised-user-account": "Compromised user account",
    "ci-cd-abuse": "CI/CD abuse",
    "compromised-instance": "Compromised instance",
    "misconfigured-project-or-group-settings": "Misconfigured project or group settings",
    "data-exfiltration": "Data exfiltration",
    "abuse-and-resource-misuse": "Abuse and resource misuse",
}
_OFFERING_LABELS = {
    "self-managed": "GitLab Self-Managed",
    "dedicated": "GitLab Dedicated",
    "saas": "GitLab.com (SaaS)",
}


@dataclass
class _Fence:
    lang: str
    text: str
    line_start: int  # 0-based index of the opening fence line
    line_end: int    # 0-based index of the closing fence line
    indent: int
    in_list: bool


@dataclass
class _Heading:
    level: int
    title: str
    line: int  # 0-based


@dataclass
class _SigmaDoc:
    data: dict
    text: str
    order: int
    deps: list["_SigmaDoc"] = field(default_factory=list)

    @property
    def is_correlation(self) -> bool:
        return isinstance(self.data.get("correlation"), dict)


def _split_lines(text: str) -> list[str]:
    lines = _LINE_SPLIT_RE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _split_frontmatter(lines: list[str]) -> tuple[dict, int]:
    """(frontmatter mapping, index of the first body line). An absent or
    unreadable block yields ({}, 0): the Sigma is still worth indexing."""
    if not lines or lines[0].rstrip() != "---":
        return {}, 0
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            try:
                data = yaml.safe_load("\n".join(lines[1:i]))
            except yaml.YAMLError:
                return {}, i + 1
            return (data if isinstance(data, dict) else {}), i + 1
    return {}, 0


def _scan(lines: list[str], start: int) -> tuple[list[_Heading], list[_Fence]]:
    """One pass over the body: ATX headings and fenced blocks. Headings
    inside a fence (shell comments, mostly) are not headings."""
    headings: list[_Heading] = []
    fences: list[_Fence] = []
    in_list = False
    i = start
    while i < len(lines):
        line = lines[i]
        m = _FENCE_OPEN_RE.match(line)
        if m:
            indent, marker, lang = len(m.group(1)), m.group(2), m.group(3).lower()
            close_re = re.compile(rf"^ {{0,3}}{re.escape(marker[0])}{{{len(marker)},}}[ \t]*$")
            j = i + 1
            while j < len(lines) and not close_re.match(lines[j]):
                j += 1
            body = [ln[indent:] if ln[:indent].strip() == "" else ln.lstrip(" ") for ln in lines[i + 1:j]]
            fences.append(_Fence(
                lang=lang, text="\n".join(body), line_start=i,
                line_end=min(j, len(lines) - 1), indent=indent,
                in_list=indent > 0 and in_list,
            ))
            i = j + 1
            continue
        h = _HEADING_RE.match(line)
        if h:
            headings.append(_Heading(len(h.group(1)), h.group(2).strip(), i))
            in_list = False
        elif _LIST_ITEM_RE.match(line):
            in_list = True
        elif line.strip() and not line.startswith((" ", "\t")):
            in_list = False
        i += 1
    return headings, fences


def _section_range(
    headings: list[_Heading], total: int, level: int, title: str,
) -> Optional[tuple[int, int]]:
    """(heading line, exclusive end line) of the first heading with this
    level and title (case-insensitive); the section runs to the next
    heading of the same or a higher level."""
    wanted = title.casefold()
    for idx, h in enumerate(headings):
        if h.level == level and h.title.casefold() == wanted:
            end = total
            for nxt in headings[idx + 1:]:
                if nxt.level <= h.level:
                    end = nxt.line
                    break
            return h.line, end
    return None


def _tidy(lines: list[str]) -> str:
    """Join, trim, and collapse the blank runs that cutting blocks out
    of a document leaves behind."""
    text = "\n".join(line.rstrip() for line in lines).strip()
    return re.sub(r"\n{3,}", "\n\n", text)


def _split_documents(fence_text: str) -> list[str]:
    """Split a multi-document YAML fence on its ``---`` lines, keeping
    each document's text verbatim (comments included)."""
    docs: list[list[str]] = [[]]
    for line in fence_text.split("\n"):
        if _DOC_SEPARATOR_RE.match(line):
            docs.append([])
        else:
            docs[-1].append(line)
    return [text for text in ("\n".join(d).strip("\n") for d in docs) if text.strip()]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _humanize(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").strip().capitalize()


class GitLabParser(BaseParser):
    """Parser for GitLab TLDR detections (Sigma embedded in Markdown)."""

    @property
    def source_name(self) -> str:
        return "gitlab"

    def can_parse(self, file_path: Path) -> bool:
        """Markdown under Detections/platforms/GitLab/. Matched on path
        components, not substrings, so a README elsewhere in the repo
        or a sibling platform directory is never picked up."""
        if file_path.suffix.lower() != ".md":
            return False
        parts = [p.lower() for p in file_path.parts]
        anchor = ["detections", "platforms", "gitlab"]
        if not any(parts[i:i + 3] == anchor for i in range(len(parts) - 3)):
            return False
        return not self._is_in_excluded_dir(file_path, {"tests", "test", "deprecated", ".git"})

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """The first Sigma document of the file. Ingestion calls
        ``parse_all``; this exists for the single-rule parser contract."""
        rules = self.parse_all(file_path, content)
        return rules[0] if rules else None

    def parse_all(self, file_path: Path, content: str) -> Optional[list[ParsedRule]]:
        """Every Sigma document in the file, in document order; None when
        the file has no usable Sigma (a parse failure, reported as one)."""
        try:
            return self._parse_all(file_path, content)
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:  # noqa: BLE001 -- one bad file must not sink the ingest
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    # ------------------------------------------------------------------

    def _parse_all(self, file_path: Path, content: str) -> Optional[list[ParsedRule]]:
        lines = _split_lines(content.lstrip("﻿"))
        frontmatter, body_start = _split_frontmatter(lines)
        headings, fences = _scan(lines, body_start)
        total = len(lines)

        detection_range = _section_range(headings, total, 2, "Detection")
        if detection_range is None:
            logger.debug(f"Skipping {file_path}: no Detection section")
            return None
        sigma_fences = [
            f for f in fences
            if f.lang in ("yaml", "yml") and f.indent == 0 and not f.in_list
            and detection_range[0] < f.line_start < detection_range[1]
            and _SIGMA_KEY_RE.search(f.text)
        ]

        docs: list[_SigmaDoc] = []
        for fence in sigma_fences:
            for text in _split_documents(fence.text):
                data = yaml.safe_load(text)
                if not isinstance(data, dict) or not data.get("title"):
                    logger.warning(f"{file_path}: Sigma document without a title skipped")
                    continue
                if not (isinstance(data.get("detection"), dict) or isinstance(data.get("correlation"), dict)):
                    logger.warning(f"{file_path}: {data.get('title')!r} has no detection or correlation block")
                    continue
                docs.append(_SigmaDoc(data=data, text=text, order=len(docs)))
        if not docs:
            logger.debug(f"Skipping {file_path}: no Sigma documents")
            return None

        self._link_correlations(docs)
        referenced = {id(dep) for doc in docs for dep in doc.deps}

        kind = _KIND_BY_DIR.get(file_path.parent.name.lower(), "")
        samples = self._sample_counts(lines, headings, total)
        atomic = _section_range(headings, total, 3, "Atomic Test")
        has_atomic_test = bool(atomic and _tidy(lines[atomic[0] + 1:atomic[1]]))
        guide = self._build_guide(lines, body_start, headings, sigma_fences, total)
        logs_text = self._logs_prose(lines, headings, total)

        rules: list[ParsedRule] = []
        for doc in docs:
            rules.append(self._to_parsed_rule(
                doc, file_path, frontmatter, kind,
                referenced=id(doc) in referenced,
                guide=guide, logs_text=logs_text,
                samples=samples, has_atomic_test=has_atomic_test,
            ))
        return rules

    @staticmethod
    def _link_correlations(docs: list[_SigmaDoc]) -> None:
        """Resolve each correlation's ``rules:`` (Sigma names or ids)
        to the documents of the same file."""
        by_ref: dict[str, _SigmaDoc] = {}
        for doc in docs:
            for key in ("name", "id"):
                ref = doc.data.get(key)
                if isinstance(ref, str) and ref.strip():
                    by_ref.setdefault(ref.strip(), doc)
        for doc in docs:
            if not doc.is_correlation:
                continue
            for ref in _as_list(doc.data["correlation"].get("rules")):
                dep = by_ref.get(str(ref).strip())
                if dep is not None and dep is not doc and dep not in doc.deps:
                    doc.deps.append(dep)

    @staticmethod
    def _closure(doc: _SigmaDoc) -> list[_SigmaDoc]:
        """Every document a correlation depends on, transitively, in
        file order (a temporal correlation can reference correlations)."""
        seen: dict[int, _SigmaDoc] = {}
        stack = list(doc.deps)
        while stack:
            dep = stack.pop()
            if id(dep) in seen or dep is doc:
                continue
            seen[id(dep)] = dep
            stack.extend(dep.deps)
        return sorted(seen.values(), key=lambda d: d.order)

    @staticmethod
    def _sample_counts(lines: list[str], headings: list[_Heading], total: int) -> dict:
        """Marked sample events under ``## Logs``: the file's embedded
        positive and negative test cases."""
        logs = _section_range(headings, total, 2, "Logs")
        counts = {"match": 0, "no_match": 0}
        if logs is None:
            return counts
        for line in lines[logs[0] + 1:logs[1]]:
            s = _SUMMARY_RE.search(line)
            if not s:
                continue
            m = _MARKER_RE.search(s.group(1).strip())
            if m:
                counts["match" if m.group(1) == "match" else "no_match"] += 1
        return counts

    @staticmethod
    def _build_guide(
        lines: list[str], body_start: int, headings: list[_Heading],
        sigma_fences: list[_Fence], total: int,
    ) -> Optional[str]:
        """The file's prose as one Markdown document: everything except
        the Logs section (deploy notes + bulky sample events), the Sigma
        fences (shown as the rule's logic) and the reference list (in
        ``references``)."""
        skip: set[int] = set()
        logs = _section_range(headings, total, 2, "Logs")
        if logs:
            skip.update(range(logs[0], logs[1]))
        refs = _section_range(headings, total, 3, "References")
        if refs:
            skip.update(range(refs[0], refs[1]))
        for fence in sigma_fences:
            skip.update(range(fence.line_start, fence.line_end + 1))
        text = _tidy([ln for i, ln in enumerate(lines) if i >= body_start and i not in skip])
        return text or None

    @staticmethod
    def _logs_prose(lines: list[str], headings: list[_Heading], total: int) -> Optional[str]:
        """What the Logs section says about collecting the signal: the
        text before ``### Sample Event Logs``, or, when the section opens
        with that heading, its introduction up to the first sample."""
        logs = _section_range(headings, total, 2, "Logs")
        if logs is None:
            return None
        samples = _section_range(headings, total, 3, "Sample Event Logs")
        if samples is None or not (logs[0] < samples[0] < logs[1]):
            end = logs[1]
        else:
            end = samples[0]
        text = _tidy(lines[logs[0] + 1:end])
        if not text and samples is not None:
            intro: list[str] = []
            for line in lines[samples[0] + 1:samples[1]]:
                if _DETAILS_OPEN_RE.search(line):
                    break
                intro.append(line)
            text = _tidy(intro)
        return text or None

    def _to_parsed_rule(
        self, doc: _SigmaDoc, file_path: Path, frontmatter: dict, kind: str, *,
        referenced: bool, guide: Optional[str], logs_text: Optional[str],
        samples: dict, has_atomic_test: bool,
    ) -> ParsedRule:
        rule = doc.data
        closure = self._closure(doc) if doc.is_correlation else []
        base_rules = [d for d in closure if not d.is_correlation]

        # Logsource: the document's own, or, for a correlation, the
        # logsources of the base rules it counts.
        own = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
        sources = [own] if own else [
            d.data["logsource"] for d in base_rules if isinstance(d.data.get("logsource"), dict)
        ]
        services = list(dict.fromkeys(
            str(s["service"]).strip() for s in sources if s.get("service")
        ))
        first = sources[0] if sources else {}
        log_source = {
            "product": first.get("product") or "gitlab",
            "category": first.get("category"),
            "service": services[0] if len(services) == 1 else None,
            "services": services,
        }

        tags = [str(t) for t in _as_list(rule.get("tags")) if t]
        mitre_attack = _SIGMA._extract_mitre_from_tags(tags)
        extra_tags = [f"tldr.{kind}"] if kind else []
        extra_tags += [str(t) for t in _as_list(frontmatter.get("cicd_techniques")) if t]
        kept_tags = list(dict.fromkeys(
            [t for t in tags if not _SIGMA._is_mitre_tag(t)] + extra_tags
        ))

        level = str(rule.get("level") or "unknown")
        # A base rule that a correlation counts and that upstream ships
        # at `informational` is signal for that correlation, not an
        # alert ("not meant to alert on its own" in the files' own
        # words). Referenced rules with a real level stay alertable.
        is_building_block = referenced and not doc.is_correlation and level.lower() == "informational"

        # A correlation alone is not deployable: prefix what it counts.
        raw_parts = [d.text for d in closure] + [doc.text]
        raw_content = "\n---\n".join(raw_parts).rstrip() + "\n"

        cve_tags = {t.lower()[4:] for t in tags if t.lower().startswith("cve.")}
        cves = [
            c for c in _as_list(frontmatter.get("cves"))
            if isinstance(c, dict) and str(c.get("id") or "").lower().removeprefix("cve-") in cve_tags
        ]
        references = [str(r) for r in _as_list(rule.get("references")) if r]
        for cve in cves:
            url = cve.get("advisory_url")
            if isinstance(url, str) and url and url not in references:
                references.append(url)

        scenarios = [str(s) for s in _as_list(frontmatter.get("scenarios")) if s]

        return ParsedRule(
            source=self.source_name,
            file_path=str(file_path),
            raw_content=raw_content,
            title=str(rule["title"]),
            description=rule.get("description"),
            author=rule.get("author"),
            status=rule.get("status", "unknown"),
            severity=level,
            log_source=log_source,
            tags=kept_tags,
            mitre_attack=mitre_attack,
            detection_logic_raw=(
                {"correlation": rule["correlation"]} if doc.is_correlation else rule["detection"]
            ),
            false_positives=[f for f in _as_list(rule.get("falsepositives")) if f],
            extra={
                "id": rule.get("id"),
                "name": rule.get("name"),
                "date": rule.get("date"),
                "modified": rule.get("modified"),
                "references": references,
                "is_correlation": doc.is_correlation,
                "is_building_block": is_building_block,
                # (detection, logsource) of the base rules a correlation
                # counts, for observable extraction.
                "base_rules": [
                    {"detection": d.data.get("detection"), "logsource": d.data.get("logsource")}
                    for d in base_rules
                ],
                "detection_type": kind or None,
                "slug": file_path.stem,
                "scenarios": [_SCENARIO_TITLES.get(s, _humanize(s)) for s in scenarios],
                "investigation_guide": guide,
                "deploy_notes": self._deploy_notes(frontmatter, services, cves, logs_text),
                "samples": dict(samples),
                "has_atomic_test": has_atomic_test,
            },
        )

    @staticmethod
    def _deploy_notes(
        frontmatter: dict, services: list[str], cves: list[dict], logs_text: Optional[str],
    ) -> Optional[str]:
        """What has to be true for the rule to see anything: where it
        applies, which log it reads, and (vulnerability rules) which
        versions are affected, followed by the file's own Logs text."""
        facts: list[str] = []
        offerings = [_OFFERING_LABELS.get(str(o), str(o)) for o in _as_list(frontmatter.get("offering"))]
        tiers = [str(t).capitalize() for t in _as_list(frontmatter.get("tier"))]
        if offerings:
            line = f"**Applies to:** {', '.join(offerings)}"
            if tiers:
                line += f" ({', '.join(tiers)})"
            facts.append(line)
        if services:
            facts.append("**Log source:** " + ", ".join(f"`{s}`" for s in services))
        if "audit_json.log" in services:
            events = [str(e) for e in _as_list(frontmatter.get("audit_events")) if e]
            if events:
                facts.append("**Audit events:** " + ", ".join(f"`{e}`" for e in events))
        if frontmatter.get("detects_from"):
            facts.append(f"**Signal exists from:** GitLab {frontmatter['detects_from']}")
        for cve in cves:
            ranges = []
            for r in _as_list(cve.get("affected")):
                if not isinstance(r, dict) or not r.get("before"):
                    continue
                start = r.get("from")
                ranges.append(
                    f"{start} up to (not including) {r['before']}" if start and str(start) != "0"
                    else f"before {r['before']}"
                )
            fixed = ", ".join(str(v) for v in _as_list(cve.get("fixed_in")))
            line = f"**{cve.get('id')}:**"
            if ranges:
                line += " affects " + "; ".join(ranges) + "."
            if fixed:
                line += f" Fixed in {fixed}."
            facts.append(line)
        parts = ["  \n".join(facts)] if facts else []
        if logs_text:
            parts.append(logs_text)
        return "\n\n".join(parts) or None
