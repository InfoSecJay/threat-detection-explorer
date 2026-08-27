"""Field extraction service for parsing detection logic across formats.

Extracts observable artifacts (process names, file paths, registry keys, Event IDs,
network indicators, API actions, target resources) from detection query logic.
Supports Sigma, Elastic (EQL/KQL/Lucene/ES|QL), Splunk (SPL), Sentinel (KQL),
and Sublime (MQL) formats.

Domain-aware extraction maps fields by security domain:
  - Endpoint (Windows/Linux/macOS): process, file, registry, Event IDs
  - Cloud (AWS/Azure/GCP): API actions, principals, resources, regions
  - Identity (Okta/Entra ID): event actions, actors, targets, auth factors
  - Email: sender domains, recipients, subjects, attachments, URLs
  - DNS: query names, query types, response codes
  - Network: IPs, ports, protocols, directions
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ExtractedObservable:
    """A single observable artifact extracted from detection logic."""
    field: str              # Original field name (e.g., "process.name", "CommandLine")
    values: list[str]       # Values/patterns matched
    type: str               # Observable type: process, file, registry, network, cloud, identity, email, dns, etc.
    subtype: str            # e.g., process_name, api_action, sender_domain, query_name
    negated: bool = False   # Whether this is a NOT/exclusion condition


@dataclass
class ExtractedFields:
    """Structured result of field extraction from a detection rule."""
    source_tables: list[str] = field(default_factory=list)
    fields_used: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)
    # Domain-specific extraction
    api_actions: list[str] = field(default_factory=list)          # Cloud/Identity API actions/event types
    target_resources: list[str] = field(default_factory=list)     # Cloud resources, identity targets
    observables: list[ExtractedObservable] = field(default_factory=list)
    query_complexity: str = "simple"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            "source_tables": self.source_tables,
            "fields_used": self.fields_used,
            "event_ids": self.event_ids,
            "process_names": self.process_names,
            "file_paths": self.file_paths,
            "registry_keys": self.registry_keys,
            "network_indicators": self.network_indicators,
            "api_actions": self.api_actions,
            "target_resources": self.target_resources,
            "observables": [
                {
                    "field": o.field,
                    "values": o.values,
                    "type": o.type,
                    "subtype": o.subtype,
                    "negated": o.negated,
                }
                for o in self.observables
            ],
            "query_complexity": self.query_complexity,
        }


# ---------------------------------------------------------------------------
# Field classification mappings
# ---------------------------------------------------------------------------

# Maps field names (lowercase) to (observable_type, observable_subtype)
FIELD_TYPE_MAP: dict[str, tuple[str, str]] = {
    # ---- PROCESS FIELDS ----
    # Sigma / generic
    "image": ("process", "process_name"),
    "parentimage": ("process", "parent_process_name"),
    "originalfilename": ("process", "process_name"),
    "commandline": ("process", "command_line_pattern"),
    "parentcommandline": ("process", "parent_command_line"),
    # ECS (Elastic)
    "process.name": ("process", "process_name"),
    "process.executable": ("process", "process_path"),
    "process.args": ("process", "command_line_pattern"),
    "process.command_line": ("process", "command_line_pattern"),
    "process.parent.name": ("process", "parent_process_name"),
    "process.parent.executable": ("process", "parent_process_path"),
    "process.parent.args": ("process", "parent_command_line"),
    "process.parent.command_line": ("process", "parent_command_line"),
    "process.pe.original_file_name": ("process", "process_name"),
    "process.hash.sha256": ("process", "process_hash"),
    "process.hash.md5": ("process", "process_hash"),
    # Splunk CIM
    "processes.process_name": ("process", "process_name"),
    "processes.process": ("process", "command_line_pattern"),
    "processes.parent_process_name": ("process", "parent_process_name"),
    "processes.parent_process": ("process", "parent_command_line"),
    "processes.original_file_name": ("process", "process_name"),
    "process_name": ("process", "process_name"),
    "parent_process_name": ("process", "parent_process_name"),
    # Microsoft Defender / Sentinel MDE
    "filename": ("process", "process_name"),
    "initiatingprocessfilename": ("process", "parent_process_name"),
    "processcommandline": ("process", "command_line_pattern"),
    "initiatingprocesscommandline": ("process", "parent_command_line"),
    "foldername": ("process", "process_path"),
    "sha256": ("process", "process_hash"),
    "sha1": ("process", "process_hash"),
    "md5": ("process", "process_hash"),

    # ---- FILE FIELDS ----
    # Sigma
    "targetfilename": ("file", "file_path"),
    "imageloaded": ("file", "file_path"),
    "contents": ("file", "file_content"),
    # ECS
    "file.name": ("file", "file_name"),
    "file.path": ("file", "file_path"),
    "file.extension": ("file", "file_extension"),
    "file.hash.sha256": ("file", "file_hash"),
    "file.hash.md5": ("file", "file_hash"),
    # Splunk
    "filesystem.file_name": ("file", "file_name"),
    "filesystem.file_path": ("file", "file_path"),

    # ---- REGISTRY FIELDS ----
    # Sigma
    "targetobject": ("registry", "registry_key"),
    "details": ("registry", "registry_value"),
    "newvalue": ("registry", "registry_value"),
    # ECS
    "registry.path": ("registry", "registry_key"),
    "registry.key": ("registry", "registry_key"),
    "registry.value": ("registry", "registry_value"),
    "registry.data.strings": ("registry", "registry_value"),
    # Splunk
    "registry.registry_key_name": ("registry", "registry_key"),
    "registry.registry_value_name": ("registry", "registry_value"),
    # Sentinel
    "registrykey": ("registry", "registry_key"),
    "registryvaluename": ("registry", "registry_value"),
    "registryvaluedata": ("registry", "registry_value"),

    # ---- NETWORK FIELDS ----
    # Sigma
    "destinationport": ("network", "port"),
    "destinationhostname": ("network", "domain"),
    "destinationip": ("network", "ip_address"),
    "sourceport": ("network", "port"),
    "sourceip": ("network", "ip_address"),
    "destinationisipv6": ("network", "ip_address"),
    # ECS
    "destination.ip": ("network", "ip_address"),
    "destination.port": ("network", "port"),
    "destination.domain": ("network", "domain"),
    "source.ip": ("network", "ip_address"),
    "source.port": ("network", "port"),
    "url.full": ("network", "url"),
    "url.domain": ("network", "domain"),
    "http.request.method": ("network", "http_method"),
    "http.response.status_code": ("network", "http_status"),
    "network.transport": ("network", "protocol"),
    "network.direction": ("network", "direction"),
    "network.type": ("network", "type"),
    "network.protocol": ("network", "protocol"),
    # Splunk
    "dest_port": ("network", "port"),
    "dest_ip": ("network", "ip_address"),
    "dest": ("network", "ip_address"),
    "src_ip": ("network", "ip_address"),
    "src": ("network", "ip_address"),
    "protocol": ("network", "protocol"),
    "transport": ("network", "protocol"),
    "direction": ("network", "direction"),
    "action": ("network", "action"),
    # Sentinel
    "remoteport": ("network", "port"),
    "remoteip": ("network", "ip_address"),
    "remoteurl": ("network", "url"),
    "localport": ("network", "port"),
    "localip": ("network", "ip_address"),

    # ---- DNS FIELDS ----
    # ECS
    "dns.question.name": ("dns", "query_name"),
    "dns.question.type": ("dns", "query_type"),
    "dns.response_code": ("dns", "response_code"),
    "dns.answers.data": ("dns", "answer"),
    "dns.answers.type": ("dns", "answer_type"),
    # Sigma
    "queryname": ("dns", "query_name"),
    "querytype": ("dns", "query_type"),
    "queryresults": ("dns", "answer"),
    # Sentinel
    "dnsquery": ("dns", "query_name"),
    "querytype_s": ("dns", "query_type"),

    # ---- EVENT ID FIELDS ----
    "eventid": ("event", "event_id"),
    "eventcode": ("event", "event_id"),
    "event.code": ("event", "event_id"),
    "event_id": ("event", "event_id"),
    "message_id": ("event", "event_id"),

    # ---- AUTHENTICATION FIELDS ----
    "user": ("authentication", "user"),
    "logonid": ("authentication", "logon_id"),
    "user.name": ("authentication", "user"),
    "user.id": ("authentication", "user_id"),
    "user.domain": ("authentication", "domain"),
    "user.email": ("authentication", "user_email"),
    "accountname": ("authentication", "user"),
    "accountdomain": ("authentication", "domain"),
    "logontypename": ("authentication", "logon_type"),
    "logontype": ("authentication", "logon_type"),
    "subjectusername": ("authentication", "user"),
    "targetusername": ("authentication", "user"),
    "subjectdomainname": ("authentication", "domain"),
    "targetdomainname": ("authentication", "domain"),

    # ---- CLOUD FIELDS - AWS ----
    "event.action": ("cloud", "api_action"),
    "event.provider": ("cloud", "event_source"),
    "cloud.provider": ("cloud", "cloud_provider"),
    "cloud.region": ("cloud", "region"),
    "cloud.account.id": ("cloud", "account_id"),
    "aws.cloudtrail.event_name": ("cloud", "api_action"),
    "aws.cloudtrail.request_parameters": ("cloud", "request_params"),
    "aws.cloudtrail.response_elements": ("cloud", "response_elements"),
    "aws.cloudtrail.error_code": ("cloud", "error_code"),
    "aws.cloudtrail.error_message": ("cloud", "error_message"),
    "aws.cloudtrail.user_identity.arn": ("cloud", "principal"),
    "aws.cloudtrail.user_identity.type": ("cloud", "principal_type"),
    "aws.cloudtrail.resources.arn": ("cloud", "resource"),
    "eventname": ("cloud", "api_action"),
    "eventsource": ("cloud", "event_source"),
    "useridentity.arn": ("cloud", "principal"),
    "useridentity.type": ("cloud", "principal_type"),
    "resources.arn": ("cloud", "resource"),
    "errorcode": ("cloud", "error_code"),
    "errormessage": ("cloud", "error_message"),
    "awsregion": ("cloud", "region"),
    "sourceipaddress": ("cloud", "source_ip"),
    "useragent": ("cloud", "user_agent"),
    "recipientaccountid": ("cloud", "account_id"),
    "requestparameters": ("cloud", "request_params"),

    # ---- CLOUD FIELDS - Azure ----
    "operationname": ("cloud", "api_action"),
    "operationnamevalue": ("cloud", "api_action"),
    "calleripaddress": ("cloud", "source_ip"),
    "resulttype": ("cloud", "result"),
    "resultsignature": ("cloud", "result"),
    "resourceid": ("cloud", "resource"),
    "resourcegroup": ("cloud", "resource_group"),
    "resourceprovider": ("cloud", "resource_type"),
    "properties.message": ("cloud", "context"),
    "properties.statuscode": ("cloud", "result"),

    # ---- CLOUD FIELDS - GCP ----
    "methodname": ("cloud", "api_action"),
    "gcp.audit.method_name": ("cloud", "api_action"),
    "protopayload.methodname": ("cloud", "api_action"),
    "protopayload.servicename": ("cloud", "event_source"),
    "protopayload.authenticationinfo.principalemail": ("cloud", "principal"),
    "resource.type": ("cloud", "resource_type"),

    # ---- IDENTITY FIELDS - Okta ----
    "eventtype": ("identity", "action"),
    "event_type": ("identity", "action"),
    "outcome.result": ("identity", "outcome"),
    "outcome.reason": ("identity", "outcome_reason"),
    "actor.displayname": ("identity", "actor"),
    "actor.alternateid": ("identity", "actor"),
    "actor.id": ("identity", "actor"),
    "okta.actor.alternate_id": ("identity", "actor"),
    "okta.actor.display_name": ("identity", "actor"),
    "okta.event_type": ("identity", "action"),
    "okta.outcome.result": ("identity", "outcome"),
    "target.displayname": ("identity", "target"),
    "target.type": ("identity", "target_type"),
    "client.device": ("identity", "device"),
    "client.ipaddress": ("identity", "source_ip"),
    "client.useragent.rawuseragent": ("identity", "user_agent"),
    "client.geographicalcontext.country": ("identity", "geo"),
    "authenticationcontext.credentialtype": ("identity", "auth_factor"),
    "debugcontext.debugdata.requesturi": ("identity", "context"),
    "okta.debug_context.debug_data.request_uri": ("identity", "context"),
    "securitycontext.isproxy": ("identity", "context"),

    # ---- IDENTITY FIELDS - Entra ID / AAD ----
    "actiontype": ("identity", "action"),
    "activity": ("identity", "action"),
    "targetresources": ("identity", "target"),
    "initiatedby": ("identity", "actor"),
    "conditionalaccessstatus": ("identity", "context"),
    "appid": ("identity", "target"),
    "appdisplayname": ("identity", "target"),
    "resourcedisplayname": ("identity", "target"),
    "risklevelduringsignin": ("identity", "risk"),
    "riskstate": ("identity", "risk"),

    # ---- ENDPOINT FIELDS - Sentinel MDE ----
    "devicename": ("endpoint", "hostname"),
    "deviceid": ("endpoint", "device_id"),
    "remotedevicename": ("endpoint", "remote_hostname"),

    # ---- EMAIL FIELDS ----
    # Sublime MQL
    "sender.email.domain": ("email", "sender_domain"),
    "sender.email.domain.root_domain": ("email", "sender_domain"),
    "sender.email.domain.domain": ("email", "sender_domain"),
    "sender.email.email": ("email", "sender"),
    "sender.display_name": ("email", "sender_name"),
    "sender.email.domain.tld": ("email", "sender_domain"),
    "from.address": ("email", "sender"),
    "recipients": ("email", "recipient"),
    "recipients.to": ("email", "recipient"),
    "subject.subject": ("email", "subject"),
    "headers.subject": ("email", "subject"),
    "headers.return_path": ("email", "return_path"),
    "headers.reply_to": ("email", "reply_to"),
    "attachments.file_name": ("email", "attachment"),
    "attachments.file_type": ("email", "attachment_type"),
    "attachments.file_extension": ("email", "attachment_type"),
    "attachments.content_type": ("email", "attachment_type"),
    "body.links": ("email", "url"),
    "body.urls": ("email", "url"),
    "body.current_thread.text": ("email", "body_content"),
    "body.html.raw": ("email", "body_content"),
    "headers.auth_summary.spf.pass": ("email", "auth_result"),
    "headers.auth_summary.dmarc.pass": ("email", "auth_result"),
    "headers.auth_summary.dkim.pass": ("email", "auth_result"),
    "ml.nlu_classifier": ("email", "ml_classifier"),
    # ECS / M365
    "email.from.address": ("email", "sender"),
    "email.to.address": ("email", "recipient"),
    "email.subject": ("email", "subject"),
    "email.attachments.file.name": ("email", "attachment"),
}

# Known Microsoft Sentinel/MDE table names
SENTINEL_TABLES = {
    "securityevent", "securityalert", "syslog", "commonsecuritylog",
    "signinlogs", "auditlogs", "aaborevocationeventslog",
    "deviceprocessevents", "devicenetworkevents", "devicefileevents",
    "deviceregistryevents", "devicelogonevent", "deviceimageloadevents",
    "deviceevents", "emailevents", "emailattachmentinfo", "emailurlinfo",
    "identitylogonevents", "identityqueryevents", "identitydirectoryevents",
    "azureactivity", "azurediagnostics", "officeactivity",
    "threatintelligenceindicator", "securityincident",
    "windowsfirewall", "dnsevents", "w3ciislog",
    "aaborevocationeventslog", "aadnoninteractiveusersigninlogs",
    "aadprovisioninglogs", "aadriskyusers", "aadserviceprincipalsigninlogs",
    "aadsigninlogs", "aaduserdataexportlog",
    "alertevidence", "alertinfo",
    "cloudappevents",
    "union",  # not a table but appears as operator
}


def _classify_field(field_name: str) -> tuple[str, str]:
    """Classify a field name into observable type and subtype."""
    key = field_name.lower().strip()
    if key in FIELD_TYPE_MAP:
        return FIELD_TYPE_MAP[key]
    # Heuristic fallback - order matters (more specific first)
    if any(p in key for p in ["process", "image", "commandline", "cmd"]):
        return ("process", "process_field")
    if any(p in key for p in ["registry", "reg", "hklm", "hkcu"]):
        return ("registry", "registry_field")
    if any(p in key for p in ["file", "path", "filename"]):
        return ("file", "file_field")
    if any(p in key for p in ["operationname", "eventname", "methodname", "event.action"]):
        return ("cloud", "api_action")
    if any(p in key for p in ["sender", "recipient", "subject", "attachment"]):
        return ("email", "email_field")
    if any(p in key for p in ["dns", "queryname", "rcode"]):
        return ("dns", "dns_field")
    if any(p in key for p in ["actor", "principal", "identity"]):
        return ("identity", "identity_field")
    if any(p in key for p in ["resource", "arn", "bucket"]):
        return ("cloud", "resource")
    if any(p in key for p in ["ip", "port", "domain", "url", "host"]):
        return ("network", "network_field")
    if any(p in key for p in ["user", "logon", "auth", "account", "signin"]):
        return ("authentication", "auth_field")
    return ("other", "unknown")


def _extract_exe_names(values: list[str]) -> list[str]:
    """Extract .exe filenames from values (handles paths like \\powershell.exe)."""
    names = []
    for v in values:
        matches = re.findall(r'[\\\/]?([a-zA-Z0-9_\-]+\.exe)', str(v), re.IGNORECASE)
        names.extend(matches)
    return list(dict.fromkeys(n.lower() for n in names))  # dedupe, preserve order


def _extract_registry_paths(values: list[str]) -> list[str]:
    """Extract registry key paths from values."""
    paths = []
    for v in values:
        v_str = str(v)
        if re.search(r'(HKLM|HKCU|HKCR|HKU|HKEY_)', v_str, re.IGNORECASE):
            paths.append(v_str)
        elif '\\SOFTWARE\\' in v_str.upper() or '\\SYSTEM\\' in v_str.upper():
            paths.append(v_str)
        elif '\\CurrentVersion\\' in v_str:
            paths.append(v_str)
    return list(dict.fromkeys(paths))


def _is_event_id_field(field_name: str) -> bool:
    """Check if a field name represents an Event ID."""
    return field_name.lower().strip() in (
        "eventid", "eventcode", "event.code", "event_id", "message_id"
    )


def _flatten_values(val: Any) -> list[str]:
    """Flatten a value (scalar, list, or nested) into a list of strings."""
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        result = []
        for v in val:
            result.extend(_flatten_values(v))
        return result
    return [str(val)]


def _route_domain_fields(obs_type: str, obs_subtype: str, values: list[str],
                         negated: bool, result: ExtractedFields):
    """Route extracted values to domain-specific fields based on type classification."""
    # Cloud API actions (the key field for cloud rule comparison)
    if obs_type == "cloud" and obs_subtype == "api_action" and not negated:
        result.api_actions.extend(v for v in values if v)

    # Identity event actions (the key field for identity rule comparison)
    if obs_type == "identity" and obs_subtype == "action" and not negated:
        result.api_actions.extend(v for v in values if v)

    # Cloud resources and identity targets
    if obs_type == "cloud" and obs_subtype in ("resource", "resource_type") and not negated:
        result.target_resources.extend(v for v in values if v)
    if obs_type == "identity" and obs_subtype == "target" and not negated:
        result.target_resources.extend(v for v in values if v)

    # Email and DNS indicators also go to network_indicators for backward compat
    if obs_type in ("email", "dns") and obs_subtype in (
        "sender_domain", "sender", "url", "query_name", "answer"
    ):
        result.network_indicators.extend(v for v in values if v)


def _deduplicate_all(result: ExtractedFields):
    """Deduplicate all extraction lists."""
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))
    result.source_tables = list(dict.fromkeys(result.source_tables))
    result.api_actions = list(dict.fromkeys(result.api_actions))
    result.target_resources = list(dict.fromkeys(result.target_resources))


# ===========================================================================
# SIGMA EXTRACTOR
# ===========================================================================

def extract_sigma_fields(detection: dict, logsource: Optional[dict] = None) -> ExtractedFields:
    """Extract fields from a Sigma rule's detection section.

    Args:
        detection: The detection dict from a parsed Sigma rule (contains selections + condition)
        logsource: Optional logsource dict for additional context

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not detection or not isinstance(detection, dict):
        return result

    condition = detection.get("condition", "")
    selection_count = 0
    has_filter = False

    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue

        is_negated = key.startswith("filter") or (
            isinstance(condition, str) and f"not {key}" in condition.lower()
        )
        if is_negated:
            has_filter = True

        selection_count += 1

        if isinstance(value, dict):
            _process_sigma_selection(value, is_negated, result)
        elif isinstance(value, list):
            # List of dicts (OR of selections)
            for item in value:
                if isinstance(item, dict):
                    _process_sigma_selection(item, is_negated, result)

    # Determine complexity
    if has_filter and selection_count > 2:
        result.query_complexity = "complex"
    elif selection_count > 1 or has_filter:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Add source table info from logsource
    if logsource:
        tables = []
        if logsource.get("product"):
            tables.append(logsource["product"])
        if logsource.get("category"):
            tables.append(logsource["category"])
        if logsource.get("service"):
            tables.append(logsource["service"])
        result.source_tables = tables

    _deduplicate_all(result)
    return result


def _process_sigma_selection(selection: dict, is_negated: bool, result: ExtractedFields):
    """Process a single Sigma selection dict, extracting fields and values."""
    for field_with_modifier, values in selection.items():
        # Strip Sigma modifiers (|contains, |endswith, |startswith, |re, |all, etc.)
        base_field = field_with_modifier.split("|")[0].strip()

        result.fields_used.append(base_field)

        flat_values = _flatten_values(values)
        obs_type, obs_subtype = _classify_field(base_field)

        # Create observable
        observable = ExtractedObservable(
            field=base_field,
            values=flat_values,
            type=obs_type,
            subtype=obs_subtype,
            negated=is_negated,
        )
        result.observables.append(observable)

        # Extract specific artifacts
        if _is_event_id_field(base_field):
            result.event_ids.extend(str(v) for v in flat_values)

        if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
            result.process_names.extend(_extract_exe_names(flat_values))

        if obs_type == "file" and obs_subtype == "file_path":
            result.file_paths.extend(flat_values)

        if obs_type == "registry" and obs_subtype == "registry_key":
            result.registry_keys.extend(_extract_registry_paths(flat_values))

        if obs_type == "network":
            result.network_indicators.extend(flat_values)

        # Route domain-specific fields
        _route_domain_fields(obs_type, obs_subtype, flat_values, is_negated, result)


# ===========================================================================
# ELASTIC EXTRACTOR (EQL / KQL / Lucene / ES|QL)
# ===========================================================================

def extract_elastic_fields(query: str, language: str = "eql") -> ExtractedFields:
    """Extract fields from Elastic detection queries (EQL, KQL, Lucene, or ES|QL).

    Args:
        query: The query string
        language: One of "eql", "kql", "kuery", "lucene", "esql"

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()
    lang = language.lower()

    if lang == "esql":
        return extract_esql_fields(query)
    elif lang == "eql":
        _extract_eql_fields(query, result)
    elif lang in ("kql", "kuery"):
        _extract_elastic_kql_fields(query, result)
    elif lang == "lucene":
        _extract_lucene_fields(query, result)
    else:
        # Try to auto-detect
        if " where " in query.lower() and re.search(r'(process|file|network|registry)\s+where', query, re.IGNORECASE):
            _extract_eql_fields(query, result)
        else:
            _extract_elastic_kql_fields(query, result)

    _deduplicate_all(result)
    return result


def _extract_eql_fields(query: str, result: ExtractedFields):
    """Extract fields from EQL queries."""
    # Check for sequence (complex)
    if re.search(r'\bsequence\b', query, re.IGNORECASE):
        result.query_complexity = "complex"
    elif re.search(r'\b(maxspan|until)\b', query, re.IGNORECASE):
        result.query_complexity = "complex"
    else:
        # Count conditions for moderate
        conditions = len(re.findall(r'\b(and|or)\b', query, re.IGNORECASE))
        result.query_complexity = "moderate" if conditions > 3 else "simple"

    # Extract event type (e.g., "process where", "file where", "network where")
    event_types = re.findall(r'\b(process|file|network|registry|dns|any)\s+where\b', query, re.IGNORECASE)
    for et in event_types:
        result.source_tables.append(et.lower())

    # Extract field == "value" or field == number patterns
    eq_patterns = re.findall(r'([\w.]+)\s*==\s*(?:"([^"]*)"|(\d+))', query)
    for field_name, str_val, num_val in eq_patterns:
        value = str_val if str_val else num_val
        _add_elastic_observable(field_name, [value], False, result)

    # Extract field : "value" patterns (EQL wildcard match)
    colon_patterns = re.findall(r'([\w.]+)\s*:\s*"([^"]*)"', query)
    for field_name, value in colon_patterns:
        _add_elastic_observable(field_name, [value], False, result)

    # Extract field in ("val1", "val2") patterns
    in_patterns = re.findall(r'([\w.]+)\s+in\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in in_patterns:
        values = re.findall(r'"([^"]*)"', values_str)
        _add_elastic_observable(field_name, values, False, result)

    # Extract field != "value" or field != number (negated)
    neq_patterns = re.findall(r'([\w.]+)\s*!=\s*(?:"([^"]*)"|(\d+))', query)
    for field_name, str_val, num_val in neq_patterns:
        value = str_val if str_val else num_val
        _add_elastic_observable(field_name, [value], True, result)

    # Extract field like~ ("pattern") patterns
    like_patterns = re.findall(r'([\w.]+)\s+like~?\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in like_patterns:
        values = re.findall(r'"([^"]*)"', values_str)
        _add_elastic_observable(field_name, values, False, result)

    # Single like pattern
    like_single = re.findall(r'([\w.]+)\s+like~?\s+"([^"]+)"', query, re.IGNORECASE)
    for field_name, value in like_single:
        _add_elastic_observable(field_name, [value], False, result)


def _extract_elastic_kql_fields(query: str, result: ExtractedFields):
    """Extract fields from Elastic KQL (Kuery) queries."""
    conditions = len(re.findall(r'\b(and|or)\b', query, re.IGNORECASE))
    result.query_complexity = "moderate" if conditions > 2 else "simple"

    # Extract field:value patterns (KQL style)
    # Handles: field:"value", field:value, field:(val1 or val2)
    kql_patterns = re.findall(r'([\w.]+)\s*:\s*(?:"([^"]*)"|\(([^)]+)\)|(\S+))', query)
    for field_name, quoted, parens, bare in kql_patterns:
        if quoted:
            _add_elastic_observable(field_name, [quoted], False, result)
        elif parens:
            values = re.findall(r'"([^"]*)"', parens)
            if not values:
                values = [v.strip() for v in re.split(r'\s+or\s+', parens, flags=re.IGNORECASE) if v.strip()]
            _add_elastic_observable(field_name, values, False, result)
        elif bare:
            _add_elastic_observable(field_name, [bare], False, result)


def _extract_lucene_fields(query: str, result: ExtractedFields):
    """Extract fields from Lucene queries."""
    conditions = len(re.findall(r'\b(AND|OR)\b', query))
    result.query_complexity = "moderate" if conditions > 2 else "simple"

    # field:"value" or field:(val1 OR val2)
    lucene_patterns = re.findall(r'([\w.]+)\s*:\s*(?:"([^"]*)"|\(([^)]+)\))', query)
    for field_name, quoted, parens in lucene_patterns:
        if quoted:
            _add_elastic_observable(field_name, [quoted], False, result)
        elif parens:
            values = re.findall(r'"([^"]*)"', parens)
            _add_elastic_observable(field_name, values, False, result)


def _add_elastic_observable(field_name: str, values: list[str], negated: bool, result: ExtractedFields):
    """Add an observable from Elastic field extraction."""
    result.fields_used.append(field_name)
    obs_type, obs_subtype = _classify_field(field_name)

    observable = ExtractedObservable(
        field=field_name,
        values=values,
        type=obs_type,
        subtype=obs_subtype,
        negated=negated,
    )
    result.observables.append(observable)

    if _is_event_id_field(field_name):
        result.event_ids.extend(str(v) for v in values)

    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        result.process_names.extend(_extract_exe_names(values))
        # Also add bare process names (without .exe) for Linux
        for v in values:
            v_clean = v.strip('"').strip("*").strip("\\").strip("/")
            if v_clean and not v_clean.endswith('.exe') and '.' not in v_clean and '\\' not in v_clean and '/' not in v_clean and '*' not in v_clean:
                if v_clean.lower() not in [n.lower() for n in result.process_names]:
                    result.process_names.append(v_clean.lower())

    if obs_type == "file" and "path" in obs_subtype:
        result.file_paths.extend(values)

    if obs_type == "registry":
        result.registry_keys.extend(_extract_registry_paths(values))

    if obs_type == "network":
        result.network_indicators.extend(v for v in values if v)

    # Route domain-specific fields
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


# ===========================================================================
# SPLUNK EXTRACTOR (SPL)
# ===========================================================================
#
# Stage-aware tokenizer (issue #6 rebuild). The previous extractor ran
# flat regexes over the whole search string: `by` clauses were split on
# commas although ESCU writes them space-separated — so entire clauses
# ("dest user process_id FilterName") were stored as single field names,
# 2,066 junk fields_used entries in the 2026-08-26 baseline audit —
# and `| fields` / `| table` / `values(x) as y` aggregations were not
# understood at all. This version splits the pipeline into stages
# (quote-, backtick- and bracket-aware), dispatches per command,
# validates every candidate field name, and tracks derived fields
# (`as` aliases, eval/rename targets) so they don't masquerade as
# telemetry fields.

_SPL_COMMENT_RE = re.compile(r"```.*?```", re.DOTALL)
_SPL_MACRO_RE = re.compile(r"`[^`]*`")
# {} for ESCU multivalue paths (assocs{}.name); no ':' — colons appear
# in values (WinEventLog:Security), not field names.
_SPL_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.{}\-]*$")

# Tokens that are SPL syntax, never telemetry field names.
_SPL_LIST_KEYWORDS = frozenset({
    "as", "by", "over", "where", "output", "outputnew", "and", "or",
    "not", "in", "like", "true", "false", "null", "asc", "desc",
})
# Search-language meta fields: real k=v syntax, not observables.
_SPL_META_FIELDS = frozenset({
    "index", "sourcetype", "source", "datamodel", "count", "span",
    "limit", "earliest", "latest", "nodename", "maxspan", "type",
})
_SPL_STATS_CMDS = frozenset({
    "stats", "tstats", "eventstats", "streamstats", "chart",
    "timechart", "top", "rare", "sistats",
})
# Commands we recognize but deliberately don't extract from.
_SPL_SKIP_CMDS = frozenset({
    "eval", "bin", "bucket", "fillnull", "sort", "dedup", "head",
    "tail", "join", "append", "appendpipe", "appendcols", "lookup",
    "inputlookup", "mvexpand", "rex", "regex", "spath", "xyseries",
    "transaction", "convert", "makemv", "foreach", "map",
    "multisearch", "union", "from", "eventcount", "makeresults",
    "iplocation", "outputlookup", "collect", "format", "return",
})
_SPL_AGG_RE = re.compile(
    r"\b(?:count|dc|distinct_count|estdc|values|list|min|max|sum|avg|"
    r"mean|median|mode|stdev|var|earliest|latest|first|last|range|"
    r"per_second|per_minute|per_hour)\s*\(\s*([^()]*?)\s*\)",
    re.IGNORECASE,
)
_SPL_AS_RE = re.compile(r"\bas\s+([A-Za-z_][A-Za-z0-9_.{}\-]*)", re.IGNORECASE)
_SPL_EXPR_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.{}\-]*)\s*(!?=|<=|>=|<|>)\s*"
    r"(?:\"([^\"]*)\"|'([^']*)'|(\S+))"
)
_SPL_IN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.{}\-]*)\s+IN\s*\(([^)]*)\)", re.IGNORECASE
)
_SPL_FUNC_FIELD_RE = re.compile(
    r"\b(?:match|like|cidrmatch|searchmatch)\s*\(\s*"
    r"([A-Za-z_][A-Za-z0-9_.{}\-]*)",
    re.IGNORECASE,
)
_SPL_EVENT_ID_FIELDS = frozenset({
    "eventcode", "eventid", "event_id", "event.code", "message_id",
    "signature_id",
})
_MAX_SUBSEARCH_DEPTH = 5


def _spl_valid_field(name: str, derived: set[str]) -> bool:
    return (
        bool(_SPL_FIELD_NAME_RE.match(name))
        and name.lower() not in _SPL_LIST_KEYWORDS
        and name.lower() not in _SPL_META_FIELDS
        and name not in derived
    )


def _tokenize_spl(text: str) -> tuple[list[str], list[str]]:
    """Split a search into pipeline stages and top-level [subsearches].

    Splits on `|` only at bracket depth 0 outside quotes; bracket
    contents are returned separately (they are full sub-pipelines) and
    excluded from the enclosing stage. Quote state is tracked so
    brackets/pipes inside string literals (rex character classes, URL
    values) don't confuse the scanner.
    """
    stages: list[str] = []
    subsearches: list[str] = []
    buf: list[str] = []
    quote: Optional[str] = None
    in_macro = False
    depth = 0
    sub_start = -1
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            # Previous char was a backslash inside a quote — this char
            # is literal (rex patterns are full of \" escapes).
            escaped = False
            if depth == 0:
                buf.append(ch)
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif in_macro:
            if ch == "`":
                in_macro = False
        elif ch in "\"'":
            quote = ch
        elif ch == "`":
            in_macro = True
        elif ch == "[":
            depth += 1
            if depth == 1:
                sub_start = i + 1
                continue
        elif ch == "]":
            if depth == 1 and sub_start >= 0:
                subsearches.append(text[sub_start:i])
                sub_start = -1
            depth = max(0, depth - 1)
            continue
        elif ch == "|" and depth == 0:
            stages.append("".join(buf))
            buf = []
            continue
        if depth == 0:
            buf.append(ch)
    stages.append("".join(buf))
    return [s for s in (st.strip() for st in stages) if s], subsearches


def _spl_add_observable(
    field_name: str,
    values: list[str],
    negated: bool,
    result: ExtractedFields,
) -> None:
    """Record one (field, values) hit on every relevant surface."""
    result.fields_used.append(field_name)
    values = [v for v in values if v]
    if not values:
        return
    obs_type, obs_subtype = _classify_field(field_name)
    result.observables.append(
        ExtractedObservable(
            field=field_name,
            values=values,
            type=obs_type,
            subtype=obs_subtype,
            negated=negated,
        )
    )
    if field_name.lower() in _SPL_EVENT_ID_FIELDS:
        # Numeric codes only — "success"/operation names are not IDs.
        result.event_ids.extend(v for v in values if v.isdigit())
    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        result.process_names.extend(_extract_exe_names(values))
    if obs_type == "file" and "path" in obs_subtype:
        # Extensions and bare filenames are not paths.
        result.file_paths.extend(
            v for v in values if ("\\" in v or "/" in v)
        )
    if obs_type == "registry":
        result.registry_keys.extend(_extract_registry_paths(values))
    if obs_type == "network" and obs_subtype not in (
        # Enum-ish network metadata (action=allowed, direction=outbound,
        # protocol=tcp) is not an INDICATOR — only value-bearing
        # subtypes belong on the network_indicators surface.
        "action", "direction", "protocol", "http_method", "http_status",
        "type",
    ):
        result.network_indicators.extend(values)
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


def _spl_clean_bare_value(value: str) -> str:
    """Trim grouping punctuation regexes drag along with bare values:
    `(Processes.process=*-a*)` captures `*-a*)`."""
    return value.strip().strip(",").rstrip(")]").lstrip("([")


def _parse_spl_expression(
    text: str, result: ExtractedFields, derived: set[str]
) -> None:
    """field=value / field IN (...) / match(field, ...) terms."""
    for m in _SPL_IN_RE.finditer(text):
        field_name, values_str = m.group(1), m.group(2)
        if not _spl_valid_field(field_name, derived):
            continue
        if field_name.lower() in _SPL_EVENT_ID_FIELDS:
            result.fields_used.append(field_name)
            result.event_ids.extend(re.findall(r"\d+", values_str))
            continue
        values = re.findall(r'"([^"]*)"', values_str)
        if not values:
            values = [
                v.strip().strip("'\"")
                for v in values_str.split(",")
                if v.strip()
            ]
        if values:
            _spl_add_observable(field_name, values, False, result)

    remainder = _SPL_IN_RE.sub(" ", text)
    for m in _SPL_EXPR_RE.finditer(remainder):
        field_name, op = m.group(1), m.group(2)
        value = m.group(3) or m.group(4) or _spl_clean_bare_value(m.group(5) or "")
        if not _spl_valid_field(field_name, derived):
            continue
        # A "value" that is pure wildcard/punctuation is match-anything
        # noise, not an observable.
        if not value or not re.search(r"[A-Za-z0-9]", value):
            result.fields_used.append(field_name)
            continue
        _spl_add_observable(field_name, [value], op == "!=", result)

    for m in _SPL_FUNC_FIELD_RE.finditer(remainder):
        if _spl_valid_field(m.group(1), derived):
            result.fields_used.append(m.group(1))


def _parse_spl_field_list(
    text: str, result: ExtractedFields, derived: set[str]
) -> None:
    """Space/comma-separated field list (`by` clause, `fields`, `table`)."""
    for token in re.split(r"[,\s]+", text):
        token = token.strip().strip("\"'")
        if token and _spl_valid_field(token, derived):
            result.fields_used.append(token)


def _parse_spl_stats(
    stage: str, result: ExtractedFields, derived: set[str], cmd: str
) -> None:
    """stats/tstats/chart/... — aggregation args + where-expr + by list."""
    parts = re.split(r"\bby\b", stage, flags=re.IGNORECASE)
    head = parts[0]
    if len(parts) > 1:
        _parse_spl_field_list(" ".join(parts[1:]), result, derived)

    # tstats carries its filter inline: ... from datamodel=X where <expr>
    if cmd == "tstats":
        where_split = re.split(r"\bwhere\b", head, flags=re.IGNORECASE, maxsplit=1)
        if len(where_split) > 1:
            _parse_spl_expression(where_split[1], result, derived)
        head = where_split[0]

    for m in _SPL_AGG_RE.finditer(head):
        arg = m.group(1).strip()
        if arg and arg != "*" and _spl_valid_field(arg, derived):
            result.fields_used.append(arg)


def _extract_spl_pipeline(
    text: str, result: ExtractedFields, depth: int = 0
) -> None:
    if depth > _MAX_SUBSEARCH_DEPTH:
        return
    stages, subsearches = _tokenize_spl(text)

    # Pass 1: derived field names (`as` aliases, eval/rename targets)
    # so later stages don't report them as telemetry fields.
    derived: set[str] = set()
    parsed: list[tuple[str, str, str]] = []
    for raw_stage in stages:
        stage = _SPL_MACRO_RE.sub(" ", raw_stage).strip()
        if not stage:
            continue
        first, _, rest = stage.partition(" ")
        cmd = first.lower()
        known = (
            cmd in _SPL_STATS_CMDS
            or cmd in _SPL_SKIP_CMDS
            or cmd in ("search", "where", "fields", "table", "rename")
        )
        if not known:
            # Base search / bare filter stage — the whole stage is an
            # expression ("index=x EventCode=1", "message_id IN (...)").
            cmd, rest = "search", stage
        parsed.append((cmd, rest, stage))
        if cmd in _SPL_STATS_CMDS or cmd == "rename":
            derived.update(_SPL_AS_RE.findall(stage))
        elif cmd == "rex":
            # rex named capture groups define new fields.
            derived.update(
                re.findall(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>", stage)
            )
        elif cmd == "eval":
            # Only top-level assignment targets are derived — strip
            # parenthesized args first so `case(message_id="x", ...)`
            # doesn't mark message_id as derived.
            expr = rest
            for _ in range(10):
                stripped = re.sub(r"\([^()]*\)", " ", expr)
                if stripped == expr:
                    break
                expr = stripped
            derived.update(
                m.group(1)
                for m in re.finditer(
                    r"(?:^|,)\s*([A-Za-z_][A-Za-z0-9_.{}\-]*)\s*=", expr
                )
            )

    # Pass 2: per-command extraction.
    for cmd, rest, stage in parsed:
        if cmd in ("search", "where"):
            _parse_spl_expression(rest, result, derived)
        elif cmd in _SPL_STATS_CMDS:
            _parse_spl_stats(rest, result, derived, cmd)
        elif cmd in ("fields", "table"):
            body = rest.strip()
            if body.startswith("-"):
                continue  # removal list — fields being dropped, not used
            _parse_spl_field_list(body.lstrip("+ "), result, derived)
        elif cmd == "rename":
            for m in re.finditer(
                r"([A-Za-z_][A-Za-z0-9_.{}\-]*)\s+as\s+", rest, re.IGNORECASE
            ):
                if _spl_valid_field(m.group(1), derived):
                    result.fields_used.append(m.group(1))
        # _SPL_SKIP_CMDS: recognized, deliberately no extraction.

    for sub in subsearches:
        _extract_spl_pipeline(sub, result, depth + 1)


def extract_splunk_fields(search: str) -> ExtractedFields:
    """Extract fields from Splunk SPL search queries.

    Args:
        search: The SPL search string

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not search or not isinstance(search, str):
        return result

    search = search.strip()

    # Determine complexity (same heuristic as pre-rebuild).
    if re.search(r'\bjoin\b', search, re.IGNORECASE) or '|' in search and search.count('|') > 5:
        result.query_complexity = "complex"
    elif re.search(r'\b(transaction|append|subsearch)\b', search, re.IGNORECASE):
        result.query_complexity = "complex"
    elif search.count('|') > 2:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # ``` comments ``` are prose, not SPL.
    cleaned = _SPL_COMMENT_RE.sub(" ", search)

    # Source tables: datamodel / index / sourcetype (global — these
    # regexes are precise and subsearches legitimately contribute).
    result.source_tables.extend(
        re.findall(r'datamodel\s*=\s*([\w.]+)', cleaned, re.IGNORECASE)
    )
    result.source_tables.extend(
        re.findall(r'\bindex\s*=\s*([^\s|\])]+)', cleaned, re.IGNORECASE)
    )
    result.source_tables.extend(
        re.findall(r'\bsourcetype\s*=\s*([^\s|\])]+)', cleaned, re.IGNORECASE)
    )

    _extract_spl_pipeline(cleaned, result)

    _deduplicate_all(result)
    return result


# ===========================================================================
# SENTINEL / KQL EXTRACTOR
# ===========================================================================

def extract_sentinel_fields(query: str) -> ExtractedFields:
    """Extract fields from Sentinel KQL queries.

    Args:
        query: The KQL query string

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()

    # Determine complexity
    if re.search(r'\bjoin\b', query, re.IGNORECASE):
        result.query_complexity = "complex"
    elif re.search(r'\bunion\b', query, re.IGNORECASE):
        result.query_complexity = "complex"
    elif re.search(r'\blet\s+\w+\s*=', query, re.IGNORECASE):
        result.query_complexity = "moderate"
    elif query.count('|') > 3:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Extract table references
    # Handle "let x = ...; TableName | ..."
    # Strip let statements first
    clean_query = re.sub(r'let\s+\w+\s*=\s*[^;]+;', '', query, flags=re.IGNORECASE)
    clean_query = clean_query.strip()

    # First token (or after union) is the table name
    table_match = re.match(r'(\w+)\s*(?:\||$)', clean_query)
    if table_match:
        table_name = table_match.group(1)
        if table_name.lower() in SENTINEL_TABLES or table_name[0].isupper():
            result.source_tables.append(table_name)

    # Union tables
    union_match = re.findall(r'\bunion\s+(?:kind\s*=\s*\w+\s+)?([^|]+)', query, re.IGNORECASE)
    for tables_str in union_match:
        tables = [t.strip().strip(',') for t in tables_str.split(',')]
        for t in tables:
            t = t.strip()
            if t and t[0].isupper() and not t.startswith('kind'):
                result.source_tables.append(t)

    # Join table references
    join_match = re.findall(r'\bjoin\s+(?:kind\s*=\s*\w+\s+)?\(?\s*(\w+)', query, re.IGNORECASE)
    for t in join_match:
        if t[0].isupper():
            result.source_tables.append(t)

    # Extract where clause field references
    # Patterns: FieldName == "value", FieldName contains "value", FieldName has "value"
    # FieldName =~ "value", FieldName != value, FieldName in ("v1", "v2")

    # == comparison
    eq_matches = re.findall(r'(\w+)\s*==\s*(?:"([^"]*)"|(\d+))', query)
    for field_name, str_val, num_val in eq_matches:
        value = str_val if str_val else num_val
        _add_sentinel_observable(field_name, [value], False, result)

    # =~ comparison (case insensitive)
    eqi_matches = re.findall(r'(\w+)\s*=~\s*"([^"]*)"', query)
    for field_name, value in eqi_matches:
        _add_sentinel_observable(field_name, [value], False, result)

    # != comparison
    neq_matches = re.findall(r'(\w+)\s*!=\s*(?:"([^"]*)"|(\d+))', query)
    for field_name, str_val, num_val in neq_matches:
        value = str_val if str_val else num_val
        _add_sentinel_observable(field_name, [value], True, result)

    # contains / has / startswith / endswith operators
    str_ops = re.findall(r'(\w+)\s+(?:contains|has|startswith|endswith|has_any|matches\s+regex)\s+"([^"]*)"', query, re.IGNORECASE)
    for field_name, value in str_ops:
        _add_sentinel_observable(field_name, [value], False, result)

    # in operator: FieldName in ("v1", "v2")
    in_matches = re.findall(r'(\w+)\s+in\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in in_matches:
        values = re.findall(r'"([^"]*)"', values_str)
        if not values:
            values = re.findall(r'(\d+)', values_str)
        if values:
            _add_sentinel_observable(field_name, values, False, result)

    # in~ operator (case insensitive)
    ini_matches = re.findall(r'(\w+)\s+in~\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in ini_matches:
        values = re.findall(r'"([^"]*)"', values_str)
        if values:
            _add_sentinel_observable(field_name, values, False, result)

    # Extract project fields
    project_matches = re.findall(r'\|\s*project\s+([^|]+)', query, re.IGNORECASE)
    for proj_str in project_matches:
        proj_fields = [f.strip().strip(',') for f in proj_str.split(',')]
        for f in proj_fields:
            clean = f.strip()
            if clean and clean[0].isupper() and '=' not in clean:
                result.fields_used.append(clean)

    # Extract extend fields (new calculated fields)
    extend_matches = re.findall(r'\|\s*extend\s+(\w+)\s*=', query, re.IGNORECASE)
    for f in extend_matches:
        result.fields_used.append(f)

    # Extract summarize ... by fields
    summarize_by = re.findall(r'\bby\s+([^|]+)', query, re.IGNORECASE)
    for by_clause in summarize_by:
        by_fields = [f.strip().strip(',') for f in by_clause.split(',')]
        for f in by_fields:
            clean = f.strip()
            if clean and not clean.startswith('bin(') and '(' not in clean:
                result.fields_used.append(clean)

    _deduplicate_all(result)
    return result


def _add_sentinel_observable(field_name: str, values: list[str], negated: bool, result: ExtractedFields):
    """Add an observable from Sentinel/KQL field extraction."""
    result.fields_used.append(field_name)
    obs_type, obs_subtype = _classify_field(field_name)

    observable = ExtractedObservable(
        field=field_name,
        values=values,
        type=obs_type,
        subtype=obs_subtype,
        negated=negated,
    )
    result.observables.append(observable)

    if _is_event_id_field(field_name):
        result.event_ids.extend(str(v) for v in values)

    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        result.process_names.extend(_extract_exe_names(values))
        # Handle bare names (MDE FileName field)
        for v in values:
            v_clean = v.strip().lower()
            if v_clean.endswith('.exe') and v_clean not in result.process_names:
                result.process_names.append(v_clean)

    if obs_type == "file" and "path" in obs_subtype:
        result.file_paths.extend(values)

    if obs_type == "registry":
        result.registry_keys.extend(_extract_registry_paths(values))

    if obs_type == "network":
        result.network_indicators.extend(v for v in values if v)

    # Route domain-specific fields
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


# ===========================================================================
# ES|QL EXTRACTOR
# ===========================================================================

def extract_esql_fields(query: str) -> ExtractedFields:
    """Extract fields from Elastic ES|QL queries.

    Args:
        query: The ES|QL query string

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()

    # Strip comments FIRST so a `// WHERE field == "x"` line doesn't
    # leak into observable extraction below. Order matters: block
    # comments first (they can span lines), then line comments.
    query = re.sub(r'/\*.*?\*/', ' ', query, flags=re.DOTALL)
    query = re.sub(r'//[^\n]*', ' ', query)

    # Determine complexity (after comment strip — commented-out pipes
    # shouldn't count toward complexity).
    pipe_count = query.count('|')
    if pipe_count > 5 or re.search(r'\bENRICH\b', query, re.IGNORECASE):
        result.query_complexity = "complex"
    elif pipe_count > 2:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Extract FROM tables. ES|QL supports comma-separated multi-table
    # FROM (`FROM logs-a-*, logs-b-*`); capture the whole clause up
    # to the next pipe / newline, then split.
    from_clauses = re.findall(
        r'\bFROM\s+([^|\n]+)', query, re.IGNORECASE,
    )
    for clause in from_clauses:
        for table in clause.split(','):
            table = table.strip().rstrip(',')
            # Accept only patterns that look like real ES|QL index
            # names — reject anything with a space (would be a
            # keyword continuation, not a table).
            if table and re.fullmatch(r'[\w.*\-]+', table):
                result.source_tables.append(table)

    # KEEP + DROP list the fields the rule projects / suppresses;
    # both signal "this rule cares about these fields". Same
    # comma-separated shape as FROM.
    for kw in ("KEEP", "DROP"):
        for clause in re.findall(rf'\b{kw}\s+([^|\n]+)', query, re.IGNORECASE):
            for f in clause.split(','):
                clean = f.strip().rstrip(',')
                if clean and re.fullmatch(r'[\w.@]+', clean):
                    if clean not in result.fields_used:
                        result.fields_used.append(clean)

    # Extract WHERE field == "value"
    eq_patterns = re.findall(r'([\w.@]+)\s*==\s*"([^"]*)"', query)
    for field_name, value in eq_patterns:
        _add_elastic_observable(field_name, [value], False, result)

    # Extract WHERE field == number
    eq_num_patterns = re.findall(r'([\w.@]+)\s*==\s*(\d+)(?!\w)', query)
    for field_name, value in eq_num_patterns:
        _add_elastic_observable(field_name, [value], False, result)

    # Extract WHERE field != "value"
    neq_patterns = re.findall(r'([\w.@]+)\s*!=\s*"([^"]*)"', query)
    for field_name, value in neq_patterns:
        _add_elastic_observable(field_name, [value], True, result)

    # Extract field LIKE "pattern" or field RLIKE "pattern"
    like_patterns = re.findall(r'([\w.@]+)\s+(?:LIKE|RLIKE)\s+"([^"]*)"', query, re.IGNORECASE)
    for field_name, value in like_patterns:
        _add_elastic_observable(field_name, [value], False, result)

    # Extract field IN ("v1", "v2")
    in_patterns = re.findall(r'([\w.@]+)\s+IN\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in in_patterns:
        values = re.findall(r'"([^"]*)"', values_str)
        if values:
            _add_elastic_observable(field_name, values, False, result)

    # Extract STATS ... BY field patterns
    stats_by = re.findall(r'\bBY\s+([^|]+)', query, re.IGNORECASE)
    for by_clause in stats_by:
        by_fields = [f.strip().strip(',') for f in by_clause.split(',')]
        for f in by_fields:
            clean = f.strip()
            if clean and clean not in result.fields_used:
                result.fields_used.append(clean)

    # Extract DISSECT field "%{pattern}" patterns for field tracking
    dissect_matches = re.findall(r'\bDISSECT\s+([\w.@]+)', query, re.IGNORECASE)
    for f in dissect_matches:
        if f not in result.fields_used:
            result.fields_used.append(f)

    _deduplicate_all(result)
    return result


# ===========================================================================
# SUBLIME MQL EXTRACTOR
# ===========================================================================

def extract_sublime_fields(query: str) -> ExtractedFields:
    """Extract fields from Sublime Security MQL (Message Query Language) queries.

    Parses email detection rules for sender domains, recipients, subjects,
    attachments, URLs, and other email-specific indicators.

    Args:
        query: The MQL query string

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()

    # Strip `//` line comments before anything else — otherwise
    # commented-out clauses leak into observables.
    query = re.sub(r'//[^\n]*', ' ', query)

    # Determine complexity
    and_count = len(re.findall(r'\band\b', query, re.IGNORECASE))
    or_count = len(re.findall(r'\bor\b', query, re.IGNORECASE))
    if and_count + or_count > 8:
        result.query_complexity = "complex"
    elif and_count + or_count > 3:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Extract source table from type.inbound / type.outbound
    type_matches = re.findall(r'\btype\.(inbound|outbound)\b', query, re.IGNORECASE)
    for t in type_matches:
        result.source_tables.append(f"type.{t.lower()}")

    # Pattern: field == "value"
    eq_patterns = re.findall(r'([\w.]+)\s*==\s*"([^"]*)"', query)
    for field_name, value in eq_patterns:
        _add_sublime_observable(field_name, [value], False, result)

    # Pattern: field != "value"
    neq_patterns = re.findall(r'([\w.]+)\s*!=\s*"([^"]*)"', query)
    for field_name, value in neq_patterns:
        _add_sublime_observable(field_name, [value], True, result)

    # Pattern: field = "value" (single equals, common in MQL)
    single_eq = re.findall(r'([\w.]+)\s*(?<!=)=\s*(?!=)"([^"]*)"', query)
    for field_name, value in single_eq:
        # Skip if already captured by == pattern
        if (field_name, value) not in eq_patterns:
            _add_sublime_observable(field_name, [value], False, result)

    # Pattern: field in ("v1", "v2")
    in_patterns = re.findall(r'([\w.]+)\s+in\s*\(([^)]+)\)', query, re.IGNORECASE)
    for field_name, values_str in in_patterns:
        values = re.findall(r'"([^"]*)"', values_str)
        if values:
            _add_sublime_observable(field_name, values, False, result)

    # Pattern: regex.icontains(field, "pattern") or regex.contains(field, "pattern")
    regex_patterns = re.findall(
        r'regex\.(?:i?contains|i?match)\s*\(\s*([\w.]+(?:\([^)]*\))?)\s*,\s*[\'"]([^\'"]*)[\'"]',
        query, re.IGNORECASE
    )
    for field_name, pattern in regex_patterns:
        _add_sublime_observable(field_name, [pattern], False, result)

    # Pattern: strings.icontains(field, "value") or strings.contains(field, "value")
    str_patterns = re.findall(
        r'strings\.(?:i?contains|i?like|starts_with|ends_with)\s*\(\s*([\w.]+(?:\([^)]*\))?)\s*,\s*[\'"]([^\'"]*)[\'"]',
        query, re.IGNORECASE
    )
    for field_name, value in str_patterns:
        _add_sublime_observable(field_name, [value], False, result)

    # Pattern: any(field, .attr == "value")
    any_eq_patterns = re.findall(
        r'any\s*\(\s*([\w.]+)\s*,\s*\.([\w.]+)\s*==\s*"([^"]*)"',
        query, re.IGNORECASE
    )
    for container, attr, value in any_eq_patterns:
        field_name = f"{container}.{attr}"
        _add_sublime_observable(field_name, [value], False, result)

    # Pattern: any(field, .attr in ("v1", "v2"))
    any_in_patterns = re.findall(
        r'any\s*\(\s*([\w.]+)\s*,\s*\.([\w.]+)\s+in\s*\(([^)]+)\)',
        query, re.IGNORECASE
    )
    for container, attr, values_str in any_in_patterns:
        values = re.findall(r'"([^"]*)"', values_str)
        field_name = f"{container}.{attr}"
        if values:
            _add_sublime_observable(field_name, values, False, result)

    # Pattern: .field == "value" (within any() context, dot-prefixed)
    dot_eq_patterns = re.findall(r'\.([\w.]+)\s*==\s*"([^"]*)"', query)
    for field_name, value in dot_eq_patterns:
        # Only add if not already captured
        if field_name not in result.fields_used:
            _add_sublime_observable(field_name, [value], False, result)

    _deduplicate_all(result)
    return result


def _add_sublime_observable(field_name: str, values: list[str], negated: bool, result: ExtractedFields):
    """Add an observable from Sublime MQL field extraction."""
    result.fields_used.append(field_name)
    obs_type, obs_subtype = _classify_field(field_name)

    observable = ExtractedObservable(
        field=field_name,
        values=values,
        type=obs_type,
        subtype=obs_subtype,
        negated=negated,
    )
    result.observables.append(observable)

    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        result.process_names.extend(_extract_exe_names(values))

    if obs_type == "file" and "path" in obs_subtype:
        result.file_paths.extend(values)

    if obs_type == "network":
        result.network_indicators.extend(v for v in values if v)

    # Route domain-specific fields
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)
