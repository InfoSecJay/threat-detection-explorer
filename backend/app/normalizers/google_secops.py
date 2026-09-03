"""Google SecOps (Chronicle) detection rule normalizer.

Converts ParsedRule output from `GoogleSecOpsParser` into the canonical
`NormalizedDetection` shape. Chronicle rules carry explicit
`platform` / `data_source` meta fields, so we lean on those directly
rather than inferring from the query body.

Field extraction runs through `services.yaral_extractor` (issue #6
tail): UDM-path terms in the `events:` block become typed observables,
`metadata.log_type` values become source tables, and
`product_event_type` values become event IDs (numeric) or API actions.
"""

from app.services.taxonomy.canonical import VENDOR_RULE_TYPE_MODALITY
from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.yaral_extractor import extract_yaral_fields


# Map Chronicle `platform` meta values to canonical platform tokens.
# Chronicle uses Title Case product names; canonical is snake_case.
_PLATFORM_MAP: dict[str, str] = {
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "google cloud platform": "gcp",
    "google workspace": "google_workspace",
    "workspace": "google_workspace",
    "microsoft": "microsoft_365",
    "microsoft 365": "microsoft_365",
    "microsoft entra id": "azure",
    "entra id": "azure",
    "azure ad": "azure",
    "github": "github",
    "okta": "okta",
    "onelogin": "onelogin",
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "network": "network_appliance",
    "sap": "cross_platform",  # SAP is platform-agnostic enterprise app
}

# Map Chronicle `data_source` meta values to canonical data_source tokens.
_DATA_SOURCE_MAP: dict[str, str] = {
    "aws cloudtrail": "aws_cloudtrail",
    "aws guardduty": "aws_guardduty",
    "aws vpc flow logs": "aws_vpc_flow",
    "azure activity": "azure_activity",
    "azure ad": "entra_id_signin",
    "entra id": "entra_id_signin",
    "microsoft entra id": "entra_id_signin",
    "google workspace": "google_workspace_audit",
    "github audit log": "github_audit",
    "okta system log": "okta_system_log",
    "okta": "okta_system_log",
    "onelogin": "siem_alert",
    "windows event log": "windows_security_event_log",
    "sysmon": "sysmon",
    "linux syslog": "linux_syslog",
    "gcp audit logs": "gcp_audit",
}


class GoogleSecOpsNormalizer(BaseNormalizer):
    """Normalizer for Google SecOps (Chronicle) YARA-L 2.0 detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}

        # Chronicle YARA-L rules don't carry embedded created/modified
        # dates. Fall back to git log (added by GitService).
        rule_created, rule_modified = self._resolve_rule_dates(parsed.file_path)

        # Canonical taxonomy (resolver reads parsed.log_source + extra).
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        # Detection logic: pass through the YARA-L body verbatim.
        detection_logic = parsed.detection_logic_raw if isinstance(
            parsed.detection_logic_raw, str
        ) else str(parsed.detection_logic_raw)

        # References meta field is comma/newline-separated in some
        # rules; treat as a single ref unless it looks like a list.
        refs_raw = extra.get("references")
        references = self.normalize_references(refs_raw) if refs_raw else []

        extracted = extract_yaral_fields(detection_logic)

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path),
            rule_id=extra.get("rule_id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author or "Google Cloud Security",
            status=self.normalize_status(parsed.status) if parsed.status in {
                "stable", "experimental", "deprecated"
            } else "stable",
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=detection_logic,
            language="yaral",
            # meta `type`: alert | hunt (#105)
            rule_modality=VENDOR_RULE_TYPE_MODALITY.get(str(parsed.extra.get("type") or "").lower(), "rule"),
            tags=parsed.tags,
            references=references,
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            # YARA-L extraction (issue #6 tail) -- UDM-path terms in the
            # events: block, see services/yaral_extractor.py.
            extracted_fields_used=extracted.fields_used,
            extracted_event_ids=extracted.event_ids,
            extracted_process_names=extracted.process_names,
            extracted_file_paths=extracted.file_paths,
            extracted_registry_keys=extracted.registry_keys,
            extracted_network_indicators=extracted.network_indicators,
            extracted_source_tables=extracted.source_tables,
            extracted_observables=[
                {"field": o.field, "values": o.values, "type": o.type,
                 "subtype": o.subtype, "negated": o.negated}
                for o in extracted.observables
            ],
            query_complexity=extracted.query_complexity,
            extracted_api_actions=extracted.api_actions,
            extracted_target_resources=extracted.target_resources,
            rule_created_date=rule_created,
            rule_modified_date=rule_modified,
            platforms=platforms,
            data_sources=data_sources,
            event_types=event_types,
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
        )
