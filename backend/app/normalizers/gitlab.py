"""GitLab TLDR detection normalizer.

One ``ParsedRule`` per Sigma document (see ``app.parsers.gitlab``):

- Sigma metadata maps as it does for SigmaHQ rules; language is ``sigma``.
- A correlation document gets ``rule_modality="correlation"`` and the
  observables of the base rules it counts, since those are the events
  it ultimately keys on.
- A base rule shipped at ``informational`` for a correlation to count
  is a building block.
- The file's prose becomes the investigation guide and the deploy
  notes; upstream's customer-facing scenarios become ``use_cases``.
- Rule links point at gitlab.com, whose blob route is ``/-/blob/``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import yaml

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import ExtractedFields, extract_sigma_fields
from app.services.upstream_refs import branch_for

_COMPLEXITY_RANK = {"simple": 0, "moderate": 1, "complex": 2}
_LIST_ATTRS = (
    "source_tables", "fields_used", "event_ids", "process_names", "file_paths",
    "registry_keys", "network_indicators", "api_actions", "target_resources",
)


# GitLab's request and audit logs use short generic field names
# (`action`, `format`, `path`, `route`) that the shared Sigma classifier
# reads with other products in mind: `format` as an email attachment
# type, `action` as a firewall verdict, `path` as a file path. This
# table states what they are in a GitLab log. It is applied only to
# this source, so no other source's classification moves.
_API_ACTION = ("cloud", "api_action")
_FIELD_TYPES: dict[str, tuple[str, str]] = {
    # What was called: the API route template, the Rails
    # `Controller#action` / `METHOD route` caller id, the audit event
    # name, the controller class, the GraphQL field.
    "route": _API_ACTION,
    "meta.caller_id": _API_ACTION,
    "controller": _API_ACTION,
    "event_name": _API_ACTION,
    "details.event_name": _API_ACTION,
    "event_type": _API_ACTION,
    "query_analysis.used_fields": _API_ACTION,
    # Rails action name (`create`, `destroy`): only meaningful next to
    # its controller, so it stays off the API-action surface.
    "action": ("event", "event_action"),
    "method": ("network", "http_method"),
    "format": ("other", "unknown"),
    "path": ("network", "url"),
    "uri": ("network", "url"),
    "ua": ("network", "user_agent"),
    "meta.project": ("cloud", "resource"),
    "meta.root_namespace": ("cloud", "resource"),
    "entity_path": ("cloud", "resource"),
}

# RFC 5737 documentation ranges: upstream ships them as "replace with
# your runner / scanner addresses" placeholders, not as indicators.
_DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def _apply_gitlab_field_types(extracted: ExtractedFields) -> None:
    for obs in extracted.observables:
        mapped = _FIELD_TYPES.get(obs.field.lower())
        if mapped is None:
            continue
        obs.type, obs.subtype = mapped
        if obs.negated:
            continue
        values = [str(v) for v in obs.values if v is not None and re.search(r"[A-Za-z0-9]", str(v))]
        target = None
        if mapped == _API_ACTION:
            target = extracted.api_actions
        elif mapped == ("cloud", "resource"):
            target = extracted.target_resources
        if target is not None:
            target.extend(v for v in values if v not in target)
    extracted.network_indicators = [
        v for v in extracted.network_indicators if not str(v).startswith(_DOC_NETS)
    ]


def _merge_extractions(parts: list[ExtractedFields]) -> ExtractedFields:
    """Union several extractions, order-preserving and de-duplicated."""
    merged = ExtractedFields()
    seen_obs: set[tuple] = set()
    for part in parts:
        for attr in _LIST_ATTRS:
            target = getattr(merged, attr)
            for value in getattr(part, attr):
                if value not in target:
                    target.append(value)
        for obs in part.observables:
            key = (obs.field, tuple(obs.values), obs.type, obs.subtype, obs.negated)
            if key not in seen_obs:
                seen_obs.add(key)
                merged.observables.append(obs)
        if _COMPLEXITY_RANK.get(part.query_complexity, 0) > _COMPLEXITY_RANK.get(merged.query_complexity, 0):
            merged.query_complexity = part.query_complexity
    return merged


class GitLabNormalizer(BaseNormalizer):
    """Normalizer for GitLab TLDR detections."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}
        log_source = parsed.log_source or {}
        is_correlation = bool(extra.get("is_correlation"))

        if is_correlation:
            parts = [
                extract_sigma_fields(base.get("detection") or {}, logsource=base.get("logsource") or {})
                for base in extra.get("base_rules") or []
                if isinstance(base, dict)
            ]
            for part in parts:
                _apply_gitlab_field_types(part)
            extracted = _merge_extractions(parts)
            # Aggregation over a window on top of the base selections.
            if _COMPLEXITY_RANK.get(extracted.query_complexity, 0) < _COMPLEXITY_RANK["moderate"]:
                extracted.query_complexity = "moderate"
            self._add_correlation_fields(parsed.detection_logic_raw, extracted)
        else:
            extracted = extract_sigma_fields(
                parsed.detection_logic_raw if isinstance(parsed.detection_logic_raw, dict) else {},
                logsource=log_source,
            )
            _apply_gitlab_field_types(extracted)

        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=self.parse_date(extra.get("date")),
            embedded_modified=self.parse_date(extra.get("modified")),
        )

        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        rule_id = extra.get("id")
        # Several rules share one file, so the path alone cannot key the
        # fallback id: qualify it with the Sigma id.
        id_seed = f"{parsed.file_path}#{rule_id}" if rule_id else f"{parsed.file_path}#{parsed.title}"

        samples = extra.get("samples") or {}
        test_evidence = []
        if samples.get("match"):
            test_evidence.append("sample_events")
        if extra.get("has_atomic_test"):
            test_evidence.append("atomic_test")

        return NormalizedDetection(
            id=self.generate_id(parsed.source, id_seed),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, parsed.source),
            rule_id=str(rule_id) if rule_id else None,
            title=parsed.title,
            description=parsed.description,
            author=parsed.author or "GitLab",
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            is_building_block=bool(extra.get("is_building_block")),
            rule_modality="correlation" if is_correlation else "rule",
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            mitre_groups=parsed.mitre_attack.get("groups", []),
            mitre_software=parsed.mitre_attack.get("software", []),
            detection_logic=self._format_logic(parsed.detection_logic_raw),
            language="sigma",
            tags=parsed.tags,
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            investigation_guide=extra.get("investigation_guide"),
            deploy_notes=extra.get("deploy_notes"),
            raw_content=parsed.raw_content,
            extracted_fields_used=extracted.fields_used,
            extracted_event_ids=extracted.event_ids,
            extracted_process_names=extracted.process_names,
            extracted_file_paths=extracted.file_paths,
            extracted_registry_keys=extracted.registry_keys,
            extracted_network_indicators=extracted.network_indicators,
            extracted_source_tables=extracted.source_tables,
            extracted_observables=[o.to_dict() if hasattr(o, "to_dict") else {"field": o.field, "values": o.values, "type": o.type, "subtype": o.subtype, "negated": o.negated} for o in extracted.observables],
            query_complexity=extracted.query_complexity,
            extracted_api_actions=extracted.api_actions,
            extracted_target_resources=extracted.target_resources,
            rule_created_date=rule_created,
            rule_modified_date=rule_modified,
            platforms=platforms,
            data_sources=data_sources,
            event_types=event_types,
            use_cases=list(extra.get("scenarios") or []),
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
            test_evidence=test_evidence,
        )

    @staticmethod
    def _add_correlation_fields(logic: Any, extracted: ExtractedFields) -> None:
        """A correlation also reads the fields it groups and counts by."""
        corr = logic.get("correlation") if isinstance(logic, dict) else None
        if not isinstance(corr, dict):
            return
        names = list(corr.get("group-by") or []) if isinstance(corr.get("group-by"), list) else []
        condition = corr.get("condition")
        if isinstance(condition, dict) and isinstance(condition.get("field"), str):
            names.append(condition["field"])
        for name in names:
            if isinstance(name, str) and name and name not in extracted.fields_used:
                extracted.fields_used.append(name)

    @staticmethod
    def _format_logic(logic: Any) -> str:
        if not isinstance(logic, dict):
            return str(logic)
        try:
            return yaml.dump(logic, default_flow_style=False, sort_keys=False, allow_unicode=True)
        except Exception:  # noqa: BLE001 -- display text only
            return str(logic)

    def build_source_rule_url(self, file_path: str, source: str) -> str:
        """gitlab.com serves files at ``/-/blob/<ref>/<path>``; the path
        is percent-encoded because the rule directories contain spaces.
        Pinned to the indexed commit when a clone is on disk, like every
        other source (the ``/blob/<sha>/`` shape upstream_refs expects)."""
        path = quote(file_path.replace("\\", "/").lstrip("/"))
        repo_url = self.repo_url[:-4] if self.repo_url.endswith(".git") else self.repo_url
        sha = self._git_service.head_sha() if self._git_service is not None else None
        return f"{repo_url}/-/blob/{sha or branch_for(source)}/{path}"
