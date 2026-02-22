"""Field extraction service for parsing detection logic across formats.

Extracts observable artifacts (process names, file paths, registry keys, Event IDs,
network indicators) from detection query logic. Supports Sigma, Elastic (EQL/KQL/Lucene),
Splunk (SPL), and Sentinel (KQL) formats.

Inspired by security-detections-mcp field extraction approach and
UC-16 Observable/Artifact Extraction methodology.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ExtractedObservable:
    """A single observable artifact extracted from detection logic."""
    field: str              # Original field name (e.g., "process.name", "CommandLine")
    values: list[str]       # Values/patterns matched
    type: str               # Observable type: process, file, registry, network, authentication, cloud
    subtype: str            # e.g., process_name, command_line_pattern, file_path, registry_key
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
    # Process fields - Sigma / generic
    "image": ("process", "process_name"),
    "parentimage": ("process", "parent_process_name"),
    "originalfilename": ("process", "process_name"),
    "commandline": ("process", "command_line_pattern"),
    "parentcommandline": ("process", "parent_command_line"),
    "user": ("authentication", "user"),
    "logonid": ("authentication", "logon_id"),
    # Process fields - ECS (Elastic)
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
    # Process fields - Splunk CIM
    "processes.process_name": ("process", "process_name"),
    "processes.process": ("process", "command_line_pattern"),
    "processes.parent_process_name": ("process", "parent_process_name"),
    "processes.parent_process": ("process", "parent_command_line"),
    "processes.original_file_name": ("process", "process_name"),
    "process_name": ("process", "process_name"),
    "parent_process_name": ("process", "parent_process_name"),
    # Process fields - Microsoft Defender / Sentinel
    "filename": ("process", "process_name"),
    "initiatingprocessfilename": ("process", "parent_process_name"),
    "processcommandline": ("process", "command_line_pattern"),
    "initiatingprocesscommandline": ("process", "parent_command_line"),
    "foldername": ("process", "process_path"),
    # File fields - Sigma
    "targetfilename": ("file", "file_path"),
    "imageloaded": ("file", "file_path"),
    "contents": ("file", "file_content"),
    # File fields - ECS
    "file.name": ("file", "file_name"),
    "file.path": ("file", "file_path"),
    "file.extension": ("file", "file_extension"),
    "file.hash.sha256": ("file", "file_hash"),
    # File fields - Splunk
    "filesystem.file_name": ("file", "file_name"),
    "filesystem.file_path": ("file", "file_path"),
    # Registry fields - Sigma
    "targetobject": ("registry", "registry_key"),
    "details": ("registry", "registry_value"),
    "newvalue": ("registry", "registry_value"),
    # Registry fields - ECS
    "registry.path": ("registry", "registry_key"),
    "registry.key": ("registry", "registry_key"),
    "registry.value": ("registry", "registry_value"),
    "registry.data.strings": ("registry", "registry_value"),
    # Registry fields - Splunk
    "registry.registry_key_name": ("registry", "registry_key"),
    "registry.registry_value_name": ("registry", "registry_value"),
    # Registry fields - Sentinel
    "registrykey": ("registry", "registry_key"),
    "registryvaluename": ("registry", "registry_value"),
    # Network fields - Sigma
    "destinationport": ("network", "port"),
    "destinationhostname": ("network", "domain"),
    "destinationip": ("network", "ip_address"),
    "sourceport": ("network", "port"),
    "sourceip": ("network", "ip_address"),
    "destinationisipv6": ("network", "ip_address"),
    # Network fields - ECS
    "destination.ip": ("network", "ip_address"),
    "destination.port": ("network", "port"),
    "destination.domain": ("network", "domain"),
    "source.ip": ("network", "ip_address"),
    "source.port": ("network", "port"),
    "dns.question.name": ("network", "domain"),
    "url.full": ("network", "url"),
    "url.domain": ("network", "domain"),
    "http.request.method": ("network", "http_method"),
    "http.response.status_code": ("network", "http_status"),
    # Network fields - Splunk
    "dest_port": ("network", "port"),
    "dest_ip": ("network", "ip_address"),
    "dest": ("network", "ip_address"),
    "src_ip": ("network", "ip_address"),
    "src": ("network", "ip_address"),
    # Network fields - Sentinel
    "remoteport": ("network", "port"),
    "remoteip": ("network", "ip_address"),
    "remoteurl": ("network", "url"),
    # Event ID fields
    "eventid": ("event", "event_id"),
    "eventcode": ("event", "event_id"),
    "event.code": ("event", "event_id"),
    "event_id": ("event", "event_id"),
    "message_id": ("event", "event_id"),
    # Cloud fields
    "event.action": ("cloud", "api_call"),
    "cloud.provider": ("cloud", "cloud_provider"),
    "aws.cloudtrail.event_name": ("cloud", "api_call"),
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
    # Heuristic fallback
    if any(p in key for p in ["process", "image", "commandline", "cmd"]):
        return ("process", "process_field")
    if any(p in key for p in ["file", "path", "filename"]):
        return ("file", "file_field")
    if any(p in key for p in ["registry", "reg", "hklm", "hkcu"]):
        return ("registry", "registry_field")
    if any(p in key for p in ["ip", "port", "domain", "dns", "url", "host"]):
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

    # Deduplicate
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))

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


# ===========================================================================
# ELASTIC EXTRACTOR (EQL / KQL / Lucene)
# ===========================================================================

def extract_elastic_fields(query: str, language: str = "eql") -> ExtractedFields:
    """Extract fields from Elastic detection queries (EQL, KQL, or Lucene).

    Args:
        query: The query string
        language: One of "eql", "kql", "kuery", "lucene"

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()
    lang = language.lower()

    if lang == "eql":
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

    # Deduplicate
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))

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


# ===========================================================================
# SPLUNK EXTRACTOR (SPL)
# ===========================================================================

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

    # Determine complexity
    if re.search(r'\bjoin\b', search, re.IGNORECASE) or '|' in search and search.count('|') > 5:
        result.query_complexity = "complex"
    elif re.search(r'\b(transaction|append|subsearch)\b', search, re.IGNORECASE):
        result.query_complexity = "complex"
    elif search.count('|') > 2:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Extract datamodel references
    dm_matches = re.findall(r'datamodel\s*=\s*([\w.]+)', search, re.IGNORECASE)
    result.source_tables.extend(dm_matches)

    # Extract index references
    idx_matches = re.findall(r'\bindex\s*=\s*(\S+)', search, re.IGNORECASE)
    result.source_tables.extend(idx_matches)

    # Extract sourcetype
    st_matches = re.findall(r'\bsourcetype\s*=\s*(\S+)', search, re.IGNORECASE)
    result.source_tables.extend(st_matches)

    # Extract EventCode / EventID
    ec_matches = re.findall(r'\b(?:EventCode|EventID)\s*(?:=|IN)\s*(?:(\d+)|\(([^)]+)\))', search, re.IGNORECASE)
    for single, multi in ec_matches:
        if single:
            result.event_ids.append(single)
        if multi:
            result.event_ids.extend(re.findall(r'(\d+)', multi))

    # Extract field=value from tstats where clause and search terms
    field_eq = re.findall(r'([\w.]+)\s*=\s*(?:"([^"]*)"|(\S+))', search)
    for field_name, quoted, bare in field_eq:
        value = quoted if quoted else bare
        # Skip meta-fields
        if field_name.lower() in ('index', 'sourcetype', 'source', 'datamodel', 'count', 'span'):
            continue
        result.fields_used.append(field_name)
        obs_type, obs_subtype = _classify_field(field_name)
        observable = ExtractedObservable(
            field=field_name,
            values=[value],
            type=obs_type,
            subtype=obs_subtype,
        )
        result.observables.append(observable)

        if _is_event_id_field(field_name):
            result.event_ids.append(value)
        if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
            result.process_names.extend(_extract_exe_names([value]))
        if obs_type == "file" and "path" in obs_subtype:
            result.file_paths.append(value)
        if obs_type == "registry":
            result.registry_keys.extend(_extract_registry_paths([value]))
        if obs_type == "network":
            result.network_indicators.append(value)

    # Extract fields from IN() operator
    in_matches = re.findall(r'([\w.]+)\s+IN\s*\(([^)]+)\)', search, re.IGNORECASE)
    for field_name, values_str in in_matches:
        if field_name.lower() in ('eventcode', 'eventid', 'message_id'):
            ids = re.findall(r'(\d+)', values_str)
            result.event_ids.extend(ids)
            result.fields_used.append(field_name)
            continue
        values = re.findall(r'"([^"]*)"', values_str)
        if not values:
            values = [v.strip().strip("'\"") for v in values_str.split(",") if v.strip()]
        if values:
            result.fields_used.append(field_name)
            obs_type, obs_subtype = _classify_field(field_name)
            observable = ExtractedObservable(
                field=field_name,
                values=values,
                type=obs_type,
                subtype=obs_subtype,
            )
            result.observables.append(observable)
            if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
                result.process_names.extend(_extract_exe_names(values))

    # Extract fields from "by" clause (stats ... by field1, field2)
    by_matches = re.findall(r'\bby\s+([^|]+?)(?:\||$)', search, re.IGNORECASE)
    for by_clause in by_matches:
        by_fields = [f.strip() for f in by_clause.split(',') if f.strip()]
        for f in by_fields:
            # Clean field name (remove quotes, spaces)
            clean = f.strip().strip('"').strip("'")
            if clean and not clean.startswith('`') and clean not in result.fields_used:
                result.fields_used.append(clean)

    # Extract where clause field references
    where_matches = re.findall(r'\bwhere\s+(.+?)(?:\||$)', search, re.IGNORECASE)
    for where_clause in where_matches:
        # Extract field IN ("val1", "val2") from where
        where_in = re.findall(r'([\w.]+)\s+IN\s*\(([^)]+)\)', where_clause, re.IGNORECASE)
        for field_name, values_str in where_in:
            values = re.findall(r'"([^"]*)"', values_str)
            if values:
                result.fields_used.append(field_name)
                obs_type, obs_subtype = _classify_field(field_name)
                observable = ExtractedObservable(
                    field=field_name,
                    values=values,
                    type=obs_type,
                    subtype=obs_subtype,
                )
                result.observables.append(observable)
                if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
                    result.process_names.extend(_extract_exe_names(values))

    # Deduplicate
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.source_tables = list(dict.fromkeys(result.source_tables))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))

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

    # Deduplicate
    result.source_tables = list(dict.fromkeys(result.source_tables))
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))

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
