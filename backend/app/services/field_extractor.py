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

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


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
    # 2026-08-30 review batch (Splunk / Sentinel / Elastic / Panther)
    "sourceuser": ("authentication", "user"),
    "source": ("event", "event_source"),
    "taskcontent": ("process", "command_line_pattern"),
    "object_file_path": ("file", "file_path"),
    "web.http_user_agent": ("network", "user_agent"),
    "http_user_agent": ("network", "user_agent"),
    "eventmessage": ("event", "message"),
    "fixstatus": ("event", "event_outcome"),
    "cip": ("network", "ip_address"),
    "sip": ("network", "ip_address"),
    "csuseragent": ("network", "user_agent"),
    "csusername": ("authentication", "user"),
    "csmethod": ("network", "http_method"),
    "csuristem": ("network", "url"),
    "csuriquery": ("network", "url"),
    "scstatus": ("network", "http_status"),
    "dns.question.registered_domain": ("dns", "query_name"),
    "dll.code_signature.subject_name": ("file", "code_signature"),
    "dll.code_signature.status": ("file", "code_signature"),
    "winlog.event_data.subjectusersid": ("authentication", "user_id"),
    "winlog.event_data.processname": ("process", "process_path"),
    "winlog.event_data.enabledprivilegelist": ("authentication", "auth_field"),
    "winlog.event_data.servicefilename": ("process", "process_path"),
    "winlog.event_data.imagepath": ("process", "process_path"),
    "azure.auditlogs.operation_name": ("identity", "action"),
    "audittype.action": ("cloud", "api_action"),
    "audittype.category": ("cloud", "event_source"),
    "process.pe.imphash": ("process", "process_hash"),
    "process.ext.api.metadata.target_address_path": ("process", "api_call"),
    "dll.ext.device.product_id": ("file", "file_field"),
    "azure.signinlogs.properties.client_app_used": ("identity", "device"),
    "azure.signinlogs.properties.user_type": ("identity", "actor"),
    "entry.protection_provenance": ("process", "call_stack"),
    "whitelistentry": ("network", "ip_address"),
    "generatorid": ("cloud", "event_source"),
    "action.awsapicallaction.api": ("cloud", "api_action"),
    "operation_type": ("cloud", "api_action"),
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
    # ECS-generic: an endpoint verb ("start", "exec") on host streams,
    # an API operation ("CreateUser") on cloud/identity audit streams.
    # Neutral here; the Elastic post-pass (resolve_event_action_domain)
    # promotes it to cloud/api_action or identity/action from context.
    "event.action": ("event", "event_action"),
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
    # eventType / event_type / ActionType / Activity are AMBIGUOUS: Okta
    # and Snowflake put the audit action there ("user.session.start"),
    # Cisco / CommonSecurityLog put the record class ("proxylogs",
    # "IntrusionEvent"), MDE the endpoint verb ("RegistryValueSet").
    # Classified neutrally; _promote_namespaced_event_actions() lifts the
    # values that look like audit operations onto the api_actions surface.
    "eventtype": ("event", "event_action"),
    "event_type": ("event", "event_action"),
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
    "actiontype": ("event", "event_action"),  # ambiguous, see Okta block
    "activity": ("event", "event_action"),
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
    # Container-resolved Sublime paths (issue #6 rebuild): the MQL
    # scope resolver now emits full paths like body.links.display_text
    # for `any(body.links, .display_text == ...)` — map the common ones.
    "body.links.display_text": ("email", "url"),
    "body.links.display_url.url": ("email", "url"),
    "body.links.href_url.url": ("email", "url"),
    "body.links.href_url.path": ("email", "url"),
    "body.links.href_url.query_params": ("email", "url"),
    "body.links.href_url.domain.domain": ("email", "url"),
    "body.links.href_url.domain.root_domain": ("email", "url"),
    "body.links.href_url.domain.tld": ("email", "url"),
    "recipients.to.email.email": ("email", "recipient"),
    "recipients.to.email.domain.domain": ("email", "recipient"),
    "recipients.to.display_name": ("email", "recipient"),
    "attachments.file_name.file_extension": ("email", "attachment_type"),
    "attachments.sha256": ("email", "attachment"),
    "attachments.md5": ("email", "attachment"),
    "ml.nlu_classifier.intents.name": ("email", "ml_classifier"),
    "ml.nlu_classifier.intents.confidence": ("email", "ml_classifier"),
    "ml.nlu_classifier.entities.name": ("email", "ml_classifier"),
    "ml.nlu_classifier.entities.text": ("email", "ml_classifier"),
    # ECS / M365
    "email.from.address": ("email", "sender"),
    "email.to.address": ("email", "recipient"),
    "email.subject": ("email", "subject"),
    "email.attachments.file.name": ("email", "attachment"),

    # ---- VOCABULARY PASS (issue #6) ----
    # High-frequency fields the 2026-08-27 fallback tally surfaced,
    # mapped by corpus frequency. Sources: local re-extraction tally
    # (scratch tally in docs/audit.md history).

    # ECS event-stream metadata
    "event.type": ("event", "event_category"),
    "event.category": ("event", "event_category"),
    "event.kind": ("event", "event_category"),
    "endgame.event_subtype_full": ("event", "event_category"),
    "event.dataset": ("event", "event_source"),
    "event.module": ("event", "event_source"),
    "data_stream.dataset": ("event", "event_source"),
    "event.outcome": ("event", "event_outcome"),
    "host.os.type": ("endpoint", "os"),
    "host.os.family": ("endpoint", "os"),
    "host.os.platform": ("endpoint", "os"),
    "host.os.name": ("endpoint", "os"),
    "user_agent.original": ("network", "user_agent"),
    "container.id": ("cloud", "resource"),
    "kubernetes.audit.verb": ("cloud", "api_action"),
    "azure.activitylogs.operation_name": ("cloud", "api_action"),
    "dll.path": ("file", "file_path"),
    "dll.name": ("file", "file_name"),
    "f.path": ("file", "file_path"),  # osquery hunting joins
    "file.ext.header_bytes": ("file", "file_content"),
    "file.ext.original.extension": ("file", "file_extension"),
    "process.working_directory": ("process", "process_path"),
    "process.ext.effective_parent.executable": ("process", "parent_process_path"),
    "powershell.file.script_block_text": ("process", "command_line_pattern"),
    # Elastic Defend behavioral internals
    "process.code_signature.subject_name": ("process", "code_signature"),
    "process.code_signature.status": ("process", "code_signature"),
    "process.code_signature.trusted": ("process", "code_signature"),
    "file.code_signature.status": ("file", "code_signature"),
    "file.code_signature.subject_name": ("file", "code_signature"),
    "process.thread.ext.call_stack_summary": ("process", "call_stack"),
    "process.parent.thread.ext.call_stack_summary": ("process", "call_stack"),
    "process.thread.ext.call_stack_final_user_module.name": ("process", "call_stack"),
    "process.thread.ext.call_stack_final_user_module.path": ("process", "call_stack"),
    "process.thread.ext.call_stack_final_user_module.hash.sha256": ("process", "call_stack"),
    "process.thread.ext.call_stack_final_user_module.protection_provenance": ("process", "call_stack"),
    "entry.symbol_info": ("process", "call_stack"),
    "entry.callsite_trailing_bytes": ("process", "call_stack"),
    "entry.subject_name": ("process", "code_signature"),
    "process.ext.api.name": ("process", "api_call"),
    "process.ext.api.behaviors": ("process", "api_call"),
    "process.ext.api.summary": ("process", "api_call"),
    "process.ext.api.metadata.target_address_name": ("process", "api_call"),
    "process.ext.token.integrity_level_name": ("process", "integrity_level"),

    # Sigma / Windows event fields
    "scriptblocktext": ("process", "command_line_pattern"),
    "sourceimage": ("process", "process_path"),
    "targetimage": ("process", "process_path"),
    "imagepath": ("process", "process_path"),
    "processname": ("process", "process_name"),
    "servicefilename": ("process", "process_path"),
    "servicename": ("process", "service_name"),
    "hashes": ("file", "file_hash"),
    "provider_name": ("event", "event_source"),
    "cs-uri-query": ("network", "url"),
    "c-uri": ("network", "url"),
    "cs-method": ("network", "http_method"),
    "a0": ("process", "command_line_pattern"),  # auditd execve args
    "a1": ("process", "command_line_pattern"),

    # Splunk CIM
    "registry.registry_path": ("registry", "registry_key"),
    "registry.registry_value_data": ("registry", "registry_value"),
    "processes.process_path": ("process", "process_path"),
    "web.url": ("network", "url"),
    "web.uri_path": ("network", "url"),
    "web.uri_query": ("network", "url"),
    "web.http_method": ("network", "http_method"),
    "web.status": ("network", "http_status"),
    "all_traffic.dest_port": ("network", "port"),
    "all_traffic.src_port": ("network", "port"),
    "all_changes.command": ("process", "command_line_pattern"),
    "execve_command": ("process", "command_line_pattern"),
    "proctitle": ("process", "command_line_pattern"),
    "api.operation": ("cloud", "api_action"),
    "operation": ("cloud", "api_action"),   # O365 Operation
    "workload": ("cloud", "event_source"),  # O365 Workload
    "subject_title": ("email", "subject"),

    # Sentinel custom logs / CEF
    "status_s": ("event", "event_outcome"),
    "severity_s": ("event", "severity"),
    "severity": ("event", "severity"),
    "priority_s": ("event", "severity"),
    "type_s": ("event", "event_category"),
    "category": ("event", "event_category"),
    "deviceeventclassid": ("event", "event_id"),
    "devicevendor": ("event", "event_source"),
    "deviceproduct": ("event", "event_source"),
    "dvcaction": ("network", "action"),
    "urloriginal": ("network", "url"),
    "requesturl": ("network", "url"),
    "instanceid": ("cloud", "resource"),

    # Sublime resolved paths (post scope-resolution)
    "file.explode.scan.ocr.raw": ("email", "attachment_content"),
    "file.explode.scan.strings.strings": ("email", "attachment_content"),
    "file.explode.scan.strings.raw": ("email", "attachment_content"),
    "file.explode.scan.exiftool.fields.key": ("email", "attachment_content"),
    "file.explode.scan.exiftool.fields.value": ("email", "attachment_content"),
    "file.explode.scan.qr.url.path": ("email", "url"),
    "body.html.inner_text": ("email", "body_content"),
    "body.html.display_text": ("email", "body_content"),
    "body.plain.raw": ("email", "body_content"),
    "ml.logo_detect.brands.name": ("email", "ml_classifier"),
    "ml.logo_detect.brands.confidence": ("email", "ml_classifier"),
    "ml.nlu_classifier.topics.name": ("email", "ml_classifier"),
    "ml.nlu_classifier.topics.confidence": ("email", "ml_classifier"),
    "beta.ml_topic.topics.name": ("email", "ml_classifier"),
    "prevalence": ("email", "ml_classifier"),
    "credphish.disposition": ("email", "ml_classifier"),
    "headers.hops.fields.name": ("email", "header"),
    "headers.hops.fields.value": ("email", "header"),
    "headers.message_id": ("email", "header"),
    "headers.domains.root_domain": ("email", "sender_domain"),
    "sender.email.local_part": ("email", "sender"),
    "subject.base": ("email", "subject"),

    # ---- Chronicle UDM (YARA-L; issue #6 tail) ----
    # principal.process = initiating process, target.process = launched.
    "target.process.command_line": ("process", "command_line_pattern"),
    "src.process.command_line": ("process", "command_line_pattern"),
    "principal.process.command_line": ("process", "parent_command_line"),
    "target.process.file.full_path": ("process", "process_path"),
    "src.process.file.full_path": ("process", "process_path"),
    "principal.process.file.full_path": ("process", "parent_process_path"),
    "target.process.file.sha256": ("process", "process_hash"),
    "target.process.file.md5": ("process", "process_hash"),
    "target.process.file.sha": ("process", "process_hash"),
    "target.registry.registry_key": ("registry", "registry_key"),
    "target.registry.registry_value_name": ("registry", "registry_value"),
    "target.registry.registry_value_data": ("registry", "registry_value"),
    "target.file.full_path": ("file", "file_path"),
    "principal.file.full_path": ("file", "file_path"),
    "target.file.sha256": ("file", "file_hash"),
    "target.file.md5": ("file", "file_hash"),
    "target.file.sha": ("file", "file_hash"),
    "graph.entity.file.sha": ("file", "file_hash"),
    "graph.entity.file.sha256": ("file", "file_hash"),
    "principal.ip": ("network", "ip_address"),
    "target.ip": ("network", "ip_address"),
    "src.ip": ("network", "ip_address"),
    "graph.entity.artifact.ip": ("network", "ip_address"),
    "principal.hostname": ("endpoint", "hostname"),
    "target.hostname": ("endpoint", "hostname"),
    "src.hostname": ("endpoint", "hostname"),
    "network.http.user_agent": ("network", "user_agent"),
    "network.http.method": ("network", "http_method"),
    "network.http.response_code": ("network", "http_status"),
    "target.url": ("network", "url"),
    "target.port": ("network", "port"),
    "principal.port": ("network", "port"),
    "network.dns.questions.name": ("dns", "query_name"),
    "network.dns.answers.data": ("dns", "answer"),
    "principal.user.userid": ("authentication", "user"),
    "target.user.userid": ("authentication", "user"),
    "principal.user.user_display_name": ("authentication", "user"),
    "principal.user.email_addresses": ("authentication", "user_email"),
    "target.user.email_addresses": ("authentication", "user_email"),
    "metadata.event_type": ("event", "event_category"),
    "metadata.product_event_type": ("event", "event_category"),
    "metadata.product_name": ("event", "event_source"),
    "metadata.vendor_name": ("event", "event_source"),
    "metadata.log_type": ("event", "event_source"),
    "graph.metadata.product_name": ("event", "event_source"),
    "graph.metadata.vendor_name": ("event", "event_source"),
    "graph.metadata.entity_type": ("event", "event_category"),
    "graph.metadata.source_type": ("event", "event_source"),
    "security_result.action": ("event", "event_outcome"),
    "security_result.category_details": ("event", "event_category"),
    "security_result.severity": ("event", "severity"),
    "target.application": ("cloud", "event_source"),
    "target.resource.name": ("cloud", "resource"),
    "target.resource.product_object_id": ("cloud", "resource"),
    "target.resource.resource_type": ("cloud", "resource_type"),
    "target.cloud.project.name": ("cloud", "account_id"),
    "principal.cloud.project.name": ("cloud", "account_id"),

    # ---- Okta System Log (OIE filter expressions; issue #6 tail) ----
    "eventtype": ("event", "event_action"),  # ambiguous, see Okta block
    "outcome.result": ("identity", "outcome"),
    "outcome.reason": ("identity", "outcome_reason"),
    "result": ("identity", "outcome"),
    "actor.alternateid": ("identity", "actor"),
    "actor.displayname": ("identity", "actor"),
    "actor.type": ("identity", "actor"),
    "target.displayname": ("identity", "target"),
    "target.alternateid": ("identity", "target"),
    "target.type": ("identity", "target_type"),
    "target.0.displayname": ("identity", "target"),
    "target.detailentry.methodtypeused": ("identity", "auth_factor"),
    "target.detailentry.methodusedverifiedproperties": ("identity", "auth_factor"),
    "client.ipaddress": ("identity", "source_ip"),
    "client.useragent.rawuseragent": ("identity", "user_agent"),
    "client.useragent.browser": ("identity", "user_agent"),
    "client.useragent.os": ("identity", "device"),
    "client.device": ("identity", "device"),
    "client.geographicalcontext.country": ("identity", "geo"),
    "client.geographicalcontext.city": ("identity", "geo"),
    "securitycontext.isproxy": ("identity", "context"),
    "securitycontext.asorg": ("identity", "context"),
    "debugcontext.debugdata.risk": ("identity", "risk"),
    "debugcontext.debugdata.risklevel": ("identity", "risk"),
    "debugcontext.debugdata.behaviors": ("identity", "risk"),
    "debugcontext.debugdata.factor": ("identity", "auth_factor"),
    "debugcontext.debugdata.networkconnection": ("identity", "context"),
    "debugcontext.debugdata.privilegegranted": ("identity", "context"),
    "debugcontext.debugdata.privilegerevoked": ("identity", "context"),
    "debugcontext.debugdata.logonlysecuritydata": ("identity", "risk"),
    "authenticationcontext.authenticatorcontext.binaryidentifier": ("identity", "auth_factor"),
    "authenticationcontext.authenticatorcontext.bindingmethod": ("identity", "auth_factor"),
    "authenticationcontext.authenticatorcontext.validationstatus": ("identity", "auth_factor"),
    "authenticationcontext.credentialtype": ("identity", "auth_factor"),
    "authenticationcontext.externalsessionid": ("identity", "context"),

    # ---- 2026-08-29 precision pass (issue #6 production audit) ----
    # Driven by the per-source `other/unknown` + `*_field` tallies of a
    # 13-source live sample re-run through master. Free-text
    # description / message fields get the `event/message` subtype so
    # they stop reading as extraction gaps.
    # Free-text messages / descriptions
    "message": ("event", "message"),
    "description": ("event", "message"),
    "resultdescription": ("event", "message"),
    "data.description": ("event", "message"),
    "data.details.request.body.description": ("event", "message"),
    "additional.fields.msg_1": ("event", "message"),
    "security_result.summary": ("event", "message"),
    "security_result.description": ("event", "message"),
    "security_result.action_details": ("event", "message"),
    "metadata.description": ("event", "message"),
    "possiblecause": ("event", "message"),
    "gen_ai.completion": ("event", "message"),
    # Auth0 (Sigma-format rules over Auth0 tenant logs)
    "data.type": ("event", "event_category"),  # Auth0 log-type codes (sapi, fapi, slo...), not actions
    "data.tenant_name": ("identity", "context"),
    "data.client_id": ("identity", "target"),
    "data.client_name": ("identity", "target"),
    "data.user_name": ("identity", "actor"),
    "data.user_id": ("identity", "actor"),
    "data.hostname": ("network", "domain"),
    "data.ip": ("identity", "source_ip"),
    "data.user_agent": ("identity", "user_agent"),
    "data.details.response.statuscode": ("identity", "outcome"),
    "data.details.request.channel": ("identity", "context"),
    "data.details.requiresverification": ("identity", "context"),
    "data.details.request.path": ("network", "url"),
    "data.details.response.body.client_id": ("identity", "target"),
    "data.details.response.body.audience": ("identity", "target"),
    "data.details.request.body.scope{}": ("identity", "context"),
    "data.details.request.auth.credentials.scopes{}": ("identity", "context"),
    "data.details.accessedsecrets{}": ("identity", "target"),
    "data.details.response.body.afterauthentication": ("identity", "context"),
    "data.details.response.body.cross_origin_authentication": ("identity", "context"),
    "allowed_grants": ("identity", "context"),
    # Sigma: Windows / RPC firewall / misc
    "endpoint": ("network", "protocol"),           # rpc_firewall RPC interface (svcctl, atsvc)
    "clientaddress": ("network", "ip_address"),
    "cs-host": ("network", "domain"),
    "cs-uri": ("network", "url"),
    "cs-uri-stem": ("network", "url"),
    "cs-uri-query": ("network", "url"),
    "logtype": ("event", "event_source"),
    "provider": ("event", "event_source"),
    "product": ("event", "event_source"),
    "type": ("event", "event_category"),
    "status": ("event", "event_outcome"),
    "grantedaccess": ("process", "api_call"),      # Sysmon 10 access mask
    "calltrace": ("process", "call_stack"),
    "device": ("endpoint", "device_id"),
    "sharename": ("file", "file_path"),
    "relativetargetname": ("file", "file_path"),
    "binary": ("file", "file_path"),
    "query": ("dns", "query_name"),
    "unit": ("process", "service_name"),           # systemd unit
    "signingused": ("process", "code_signature"),
    "logonprocessname": ("authentication", "logon_type"),
    "encyptionused": ("authentication", "auth_field"),
    # Sentinel (KQL) generic columns
    "datasource": ("event", "event_source"),
    "sourcesystem": ("event", "event_source"),
    "loggedbyservice": ("event", "event_source"),
    "tablename": ("event", "event_source"),
    "service": ("event", "event_source"),
    "sourceseverity": ("event", "severity"),
    "finding": ("event", "event_category"),
    "policyviolatedcontrolfeature": ("event", "event_category"),
    "compliancestandard": ("event", "event_category"),
    "eventresult": ("cloud", "result"),
    "action_s": ("cloud", "api_action"),
    "activitydisplayname": ("cloud", "api_action"),
    "roles": ("identity", "target"),
    "ioctype": ("network", "type"),
    "identity": ("identity", "actor"),
    "process": ("process", "process_name"),
    "ipaddress": ("network", "ip_address"),
    "url": ("network", "url"),
    # Splunk CIM / Windows / Linux
    "attributeldapdisplayname": ("identity", "target"),
    "objectcategory": ("identity", "target_type"),
    "admoneventtype": ("event", "event_category"),
    "operationtype": ("cloud", "api_action"),
    "syscall": ("process", "api_call"),
    "comm": ("process", "process_name"),
    "exe": ("process", "process_path"),
    "uid": ("authentication", "user_id"),
    "result.status": ("cloud", "result"),
    "success": ("cloud", "result"),
    "web.dest": ("network", "domain"),
    "web.url": ("network", "url"),
    "logon_type": ("authentication", "logon_type"),
    "user_type": ("authentication", "user"),
    "serviceprincipalnames": ("identity", "target"),
    "processes.os": ("endpoint", "os"),
    "dns.query": ("dns", "query_name"),
    "processes.parent_process_path": ("process", "parent_process_path"),
    "columns.cmdline": ("process", "command_line_pattern"),
    "all_traffic.src_ip": ("network", "ip_address"),
    "all_traffic.dest_ip": ("network", "ip_address"),
    "properties.status.errorcode": ("cloud", "error_code"),
    "properties.authenticationdetails{}.succeeded": ("identity", "outcome"),
    # Elastic ECS + integrations
    "http.request.body.content": ("network", "http_body"),
    "http.request.method": ("network", "http_method"),
    "service.name": ("event", "event_source"),
    "source.as.number": ("network", "type"),
    "source.as.organization.name": ("network", "type"),
    "endgame.metadata.type": ("event", "event_category"),
    "volume.removable": ("file", "file_field"),
    "network_traffic.redis.query": ("network", "http_body"),
    "kubernetes.audit.objectref.namespace": ("cloud", "resource"),
    "kubernetes.audit.objectref.name": ("cloud", "resource"),
    "kubernetes.audit.objectref.resource": ("cloud", "resource_type"),
    "kubernetes.audit.stage": ("cloud", "context"),
    "kubernetes.audit.requesturi": ("cloud", "request_params"),
    "kubernetes.audit.user.username": ("cloud", "principal"),
    "kubernetes.audit.requestobject.spec.serviceaccountname": ("cloud", "principal"),
    "kubernetes.audit.requestobject.spec.containers.image": ("cloud", "resource"),
    "azure.auditlogs.properties.category": ("cloud", "event_source"),
    "azure.platformlogs.category": ("cloud", "event_source"),
    "azure.platformlogs.properties.log.stage": ("cloud", "context"),
    "azure.platformlogs.properties.log.user.username": ("cloud", "principal"),
    "azure.signinlogs.properties.app_id": ("identity", "target"),
    "azure.signinlogs.properties.app_display_name": ("identity", "target"),
    "azure.signinlogs.properties.risk_level_aggregated": ("identity", "risk"),
    "azure.signinlogs.properties.risk_level_during_signin": ("identity", "risk"),
    "azure.signinlogs.properties.risk_state": ("identity", "risk"),
    "azure.signinlogs.properties.authentication_requirement": ("identity", "auth_factor"),
    "google_workspace.token.client.id": ("identity", "target"),
    "google_workspace.device.account_state": ("identity", "context"),
    "google_workspace.drive.copy_type": ("cloud", "api_action"),
    "aws.cloudtrail.event_type": ("cloud", "event_source"),
    "okta.actor.type": ("identity", "actor"),
    "okta.authentication_context.authentication_step": ("identity", "auth_factor"),
    "okta.client.user_agent.raw_user_agent": ("identity", "user_agent"),
    "winlog.event_data.targetimage": ("process", "process_path"),
    "winlog.event_data.servicetype": ("process", "service_name"),
    "target.process.name": ("process", "process_name"),
    "target.process.ext.token.integrity_level_name": ("process", "integrity_level"),
    "effective_process.executable": ("process", "process_path"),
    "process.ext.session_info.logon_type": ("authentication", "logon_type"),
    "process.ext.api.parameters.protection": ("process", "api_call"),
    "process.ext.api.parameters.buffer": ("process", "api_call"),
    "process.ext.api.parameters.size": ("process", "api_call"),
    "process.ext.api.parameters.hook_type": ("process", "api_call"),
    "process.code_signature.signing_id": ("process", "code_signature"),
    "process.parent.code_signature.team_id": ("process", "code_signature"),
    "process.parent.user.name": ("authentication", "user"),
    "process.parent.group.name": ("authentication", "user"),
    "process.user.id": ("authentication", "user_id"),
    "process.group.id": ("authentication", "user_id"),
    "user.effective.id": ("authentication", "user_id"),
    "client.user.email": ("authentication", "user_email"),
    "process.entry_leader.executable": ("process", "process_path"),
    "process.session_leader.name": ("process", "process_name"),
    "process.group_leader.name": ("process", "process_name"),
    "process.name.caseless": ("process", "process_name"),
    "dll.pe.original_file_name": ("file", "file_name"),
    "dll.pe.imphash": ("file", "file_hash"),
    "dll.hash.sha256": ("file", "file_hash"),
    "dll.code_signature.status": ("file", "code_signature"),
    "dll.ext.defense_evasions": ("process", "call_stack"),
    "file.ext.windows.zone_identifier": ("file", "file_field"),
    "auditd.data.syscall": ("process", "api_call"),
    "tls.server.x509.serial_number": ("network", "type"),
    "entry.status": ("event", "event_outcome"),
    # Panther / pypanther (AWS, GCP, Okta, GitHub, CrowdStrike, Slack...)
    "verb": ("cloud", "api_action"),
    "p_log_type": ("cloud", "event_source"),
    "actionname": ("cloud", "api_action"),
    "audit_log_event": ("cloud", "api_action"),
    "eventtypename": ("identity", "action"),
    "event_simplename": ("event", "event_category"),
    "fdr_event_type": ("event", "event_category"),
    "event_platform": ("endpoint", "os"),
    "alerttype": ("event", "event_category"),
    "auditlevel": ("cloud", "context"),
    "response.statuscode": ("cloud", "result"),
    "state.status": ("cloud", "result"),
    "jsonpayload.statusdetails": ("cloud", "result"),
    "execution_status": ("cloud", "result"),
    "query_type": ("cloud", "request_params"),
    "parameters.setting_name": ("cloud", "request_params"),
    "details.new_value": ("cloud", "request_params"),
    "responseelements.snapshottype": ("cloud", "response_elements"),
    "responseelements.consolelogin": ("cloud", "response_elements"),
    "additionaleventdata.mfaused": ("identity", "auth_factor"),
    "userIdentity.invokedby".lower(): ("cloud", "principal"),
    "userIdentity.sessioncontext.attributes.mfaauthenticated".lower(): ("identity", "auth_factor"),
    "user.groups": ("identity", "target"),
    "requestparameters.cidrip": ("network", "ip_address"),
    "protopayload.requestmetadata.callersupplieduseragent": ("cloud", "user_agent"),
    "protopayload.metadata.jobchange.job.jobconfig.type": ("cloud", "request_params"),
    "protopayload.metadata.jobchange.job.jobconfig.queryconfig.statementtype": ("cloud", "request_params"),
    "id.applicationname": ("cloud", "event_source"),
    "event.imagefilename": ("process", "process_path"),
    "event.commandline": ("process", "command_line_pattern"),
    "event.postaction.authfrequency": ("identity", "auth_factor"),
    "destination_port": ("network", "port"),
    "quarantinerule": ("email", "email_field"),
    "quarantinefolder": ("email", "email_field"),
    "program": ("process", "process_name"),
    "login": ("identity", "actor"),
    # Sublime resolved paths
    "beta.scan_qr.items.url.path": ("email", "url"),
    "scan.qr.url.domain.root_domain": ("email", "url"),
    "scan.qr.data": ("email", "attachment_content"),
    "file.explode.scan.qr.data": ("email", "attachment_content"),
    "file.explode.scan.javascript.strings": ("email", "attachment_content"),
    "file.explode.scan.yara.matches.name": ("email", "attachment_content"),
    "file.explode.scan.pdf.urls.query_params": ("email", "url"),
    "file.explode.scan.strings.raw": ("email", "attachment_content"),
    "file.explode.scan.ocr.raw": ("email", "attachment_content"),
    "file.explode.file_extension": ("email", "attachment_type"),
    "file.explode.file_name": ("email", "attachment"),
    "file_type": ("email", "attachment_type"),
    "file.parse_eml.attachments.content_type": ("email", "attachment_type"),
    "body.current_thread.links.href_url.scheme": ("email", "url"),
    "body.current_thread.links.href_url.path": ("email", "url"),
    "body.current_thread.links.href_url.domain.root_domain": ("email", "url"),
    "body.links.href_url.domain.subdomain": ("email", "url"),
    "body.links.href_url.fragment": ("email", "url"),
    "body.previous_threads.recipients.to.email.email": ("email", "recipient"),
    "body.previous_threads.preamble": ("email", "body_content"),
    "recipients.to.email.domain.root_domain": ("email", "recipient"),
    "headers.return_path.domain.domain": ("email", "return_path"),
    "headers.domains.tld": ("email", "header"),
    "headers.hops.received.server.raw": ("email", "header"),
    "headers.hops.received.source.raw": ("email", "header"),
    "headers.hops.authentication_results.dmarc": ("email", "auth_result"),
    "beta.ml_topic.topics.confidence": ("email", "ml_classifier"),
    "ml.nlu_classifier.tags.name": ("email", "ml_classifier"),
    "html.xpath.nodes.inner_text": ("email", "body_content"),
    "html.xpath.nodes.attributes.style": ("email", "body_content"),
    "html.xpath.nodes.attributes.bgcolor": ("email", "body_content"),
    "html.xpath.nodes.attributes.height": ("email", "body_content"),
    "html.xpath.nodes.attributes.class": ("email", "body_content"),
    "html.xpath.nodes.attributes.alt": ("email", "body_content"),
    "html.xpath.nodes.attributes.href": ("email", "url"),
    "html.xpath.nodes.attributes.src": ("email", "url"),
    "display_url.domain.root_domain": ("email", "url"),
    "href_url.url": ("email", "url"),
    "href_url.path": ("email", "url"),
    "root_domain": ("email", "sender_domain"),
    "ec_url": ("email", "url"),
    "body.current_thread.links.display_text": ("email", "url"),
    "final_dom.display_text": ("email", "url"),
    "beta.scan_qr.items.data": ("email", "attachment_content"),
    "beta.scan_base64": ("email", "attachment_content"),
    "format": ("email", "attachment_type"),
    "language": ("email", "body_content"),
    # Residual long tail from the 2026-08-29 live-sample re-run
    "integritylevel": ("process", "integrity_level"),
    "activitytype": ("event", "event_category"),
    "auditpolicychanges": ("event", "event_category"),
    "subcategoryguid": ("event", "event_category"),
    "data": ("event", "message"),
    "param1": ("event", "message"),
    "eventdata_xml": ("event", "message"),
    "syslogmessage": ("event", "message"),
    "alertmessage": ("event", "message"),
    "reason": ("event", "message"),
    "objecttype": ("identity", "target_type"),
    "email": ("authentication", "user_email"),
    "emaildirection": ("email", "email_field"),
    "entityname": ("identity", "target"),
    "vulnerabilitytype": ("event", "event_category"),
    "permission": ("identity", "context"),
    "deviceproduct_s": ("event", "event_source"),
    "davisrisklevel": ("identity", "risk"),
    "decision": ("cloud", "result"),
    "source_type": ("cloud", "event_source"),
    "entity.app.scopes": ("identity", "context"),
    "details.new_scopes": ("identity", "context"),
    "details.bot_scopes": ("identity", "context"),
    "workflow.changed_by": ("identity", "actor"),
    "created_by.id": ("identity", "actor"),
    "data.details.request.body": ("cloud", "request_params"),
    "data.details.request.body.name": ("cloud", "request_params"),
    "parameters.message_info.message_set.type": ("cloud", "request_params"),
    "event_type._tag": ("event", "event_category"),
    "azure.platformlogs.properties.log.objectref.namespace": ("cloud", "resource"),
    "azure.platformlogs.properties.log.objectref.name": ("cloud", "resource"),
    "azure.platformlogs.properties.log.verb": ("cloud", "api_action"),
    "aws.cloudtrail.flattened.request_parameters.x-amz-acl": ("cloud", "request_params"),
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
    # Heuristic fallback - order matters (more specific first).
    # Long distinctive stems may match as substrings; short stems must
    # be whole tokens of the field name (`relationship` is not `ip`,
    # `registered_domain` is not `reg`, `code_signature.subject_name`
    # is not an email subject -- 2026-08-30 review).
    tokens = _field_tokens(field_name)
    if any(p in key for p in ["process", "image", "commandline"]) or "cmd" in tokens:
        return ("process", "process_field")
    if "dns" in tokens or any(p in key for p in ["queryname", "rcode"]):
        return ("dns", "dns_field")
    if "registry" in key or tokens & {"reg", "hklm", "hkcu"}:
        return ("registry", "registry_field")
    if any(p in key for p in ["file", "path", "filename"]):
        return ("file", "file_field")
    if any(p in key for p in ["operationname", "eventname", "methodname"]):
        return ("cloud", "api_action")
    if any(p in key for p in ["sender", "recipient", "attachment"]) or "subject" in tokens:
        return ("email", "email_field")
    if any(p in key for p in ["actor", "principal", "identity"]):
        return ("identity", "identity_field")
    if any(p in key for p in ["resource", "bucket"]) or "arn" in tokens:
        return ("cloud", "resource")
    if tokens & {"ip", "port", "domain", "url", "host", "hostname", "ipaddress", "srcip", "dstip"} or any(p in key for p in ["domain", "url"]):
        return ("network", "network_field")
    if any(p in key for p in ["user", "logon", "auth", "account", "signin"]):
        return ("authentication", "auth_field")
    return ("other", "unknown")


def _field_tokens(key: str) -> set[str]:
    """Tokens of a field name: split on . _ - and camelCase humps."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return {t.lower() for t in re.split(r"[._\-\s\[\]\"']+", spaced) if t}


def _extract_exe_names(values: list[str]) -> list[str]:
    """Extract .exe basenames from values (handles paths like \\powershell.exe).

    The basename is the last path segment, dots included:
    `Syncro.Installer.exe` used to come out as `installer.exe` and
    `Microsoft.Workflow.Compiler.exe` as `compiler.exe` (2026-08-30
    review), colliding across unrelated tools. Wildcard stems
    (`PAExec-*.exe`) are kept as written."""
    names = []
    for v in values:
        for m in re.finditer(r'([^\\/\s"\']+?\.exe)(?![\w.])', str(v), re.IGNORECASE):
            name = m.group(1).lstrip("*")
            if name.lower() != ".exe" and name:
                names.append(name)
    return list(dict.fromkeys(n.lower() for n in names))  # dedupe, preserve order


_UNIX_NAME_RE = re.compile(r"^[*]?/?([A-Za-z0-9_.+-]{2,})$")
_IPV4_VALUE_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")


def _bare_unix_names(values: list[str]) -> list[str]:
    """`/uname`, `*/openssl`, `dd` -> the binary name, for process-name
    fields whose values carry no `.exe` (Linux / macOS Sigma rules)."""
    names = []
    for v in values:
        sv = str(v).strip()
        if sv.lower().endswith(".exe") or "\\" in sv or "*" in sv.lstrip("*"):
            continue
        m = _UNIX_NAME_RE.match(sv)
        if m and "/" not in m.group(1):
            names.append(m.group(1).lower())
    return list(dict.fromkeys(names))


def _retype_by_value_shape(obs_type: str, obs_subtype: str, values: list[str]) -> tuple[str, str]:
    """Second opinion from the values themselves.

    `Image|contains: \\AppData\\Local\\Temp\\` is a directory fragment,
    not a process name; `DestinationHostname: 136.243.104.235` is an IP
    under a hostname field (LOLRMM). The field name says one thing, the
    value another -- the value wins for the surface routing.
    """
    vals = [str(v) for v in values if str(v).strip()]
    if not vals:
        return obs_type, obs_subtype
    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        if all(v.rstrip("*").endswith(("\\", "/")) and not v.lower().endswith(".exe") for v in vals):
            return "process", "process_path"
    if obs_type == "network" and obs_subtype in ("domain", "hostname"):
        if all(_IPV4_VALUE_RE.match(v.strip("*")) for v in vals):
            return "network", "ip_address"
    return obs_type, obs_subtype


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

    # Cloud resources and identity targets (`instanceId == 24050` is an
    # id, not a resource anyone searches for)
    if obs_type == "cloud" and obs_subtype in ("resource", "resource_type") and not negated:
        result.target_resources.extend(v for v in values if v and not str(v).isdigit())
    if obs_type == "identity" and obs_subtype == "target" and not negated:
        result.target_resources.extend(v for v in values if v)

    # Email and DNS indicators also go to network_indicators for backward
    # compat. Whitespace-bearing values are match PATTERNS (regex bodies,
    # link display text), not indicators — keep them on the observable
    # but off the indicator surface.
    if obs_type in ("email", "dns") and obs_subtype in (
        "sender_domain", "sender", "url", "query_name", "answer"
    ):
        result.network_indicators.extend(
            v for v in values if v and not re.search(r"\s", v)
        )


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*(?:/\d{1,3})?$")
_INDICATOR_CHARS_RE = re.compile(r"^[A-Za-z0-9*?._:\-\[\]@%/=&+~#]+$")
_DOMAIN_LIKE_RE = re.compile(r"(?:^|[*.])[A-Za-z0-9\-*?]+\.[A-Za-z0-9\-*?]*[A-Za-z][A-Za-z0-9\-*?]*")


def _is_network_indicator(value: str) -> bool:
    """Surface contract for `network_indicators`: an IP / CIDR, a
    domain (incl. `*.suffix` / `.suffix` patterns), or a URL / URL
    path. Everything else the `network/*` subtypes carry -- HTTP
    methods (`GET`), status codes (`403`), protocol / RPC interface
    names (`svcctl`), AS numbers, regex fragments (`.{150}`) -- stays
    on the typed observable but off the indicator surface.
    """
    v = value.strip()
    if not v or len(v) > 512 or re.search(r"\s", v) or not _INDICATOR_CHARS_RE.match(v):
        return False
    if _IPV4_RE.match(v) or (":" in v and _IPV6_RE.match(v)):
        return True
    if "/" in v:
        return True  # URL or path
    if ".{" in v or v.startswith("."):
        return _DOMAIN_LIKE_RE.search(v) is not None and ".{" not in v
    return _DOMAIN_LIKE_RE.search(v) is not None


# Fields whose values are an audit action on some products and a record
# class or endpoint verb on others (see FIELD_TYPE_MAP, Okta block).
_AMBIGUOUS_ACTION_FIELDS = frozenset({"eventtype", "event_type", "actiontype", "activity", "event"})
# An audit operation is namespaced: "user.session.start", "iam:PassRole",
# "Microsoft.Compute/virtualMachines/write", "New-InboxRule". Single
# tokens ("proxylogs", "Login", "IntrusionEvent", "RegistryValueSet")
# are record classes or endpoint verbs and stay off the surface.
_NAMESPACED_ACTION_RE = re.compile(r"^[A-Za-z0-9_]+(?:[.:/][A-Za-z0-9_.:/-]+|-[A-Za-z][A-Za-z0-9]+)$")


def _promote_namespaced_event_actions(result: ExtractedFields) -> None:
    """Lift (event, event_action) values from ambiguous fields onto the
    api_actions surface when they look like audit operations."""
    for obs in result.observables:
        if obs.type != "event" or obs.subtype != "event_action":
            continue
        if _LA_SUFFIX_RE.sub("", obs.field.lower()) not in _AMBIGUOUS_ACTION_FIELDS:
            continue
        promoted = [v for v in obs.values if isinstance(v, str) and _NAMESPACED_ACTION_RE.match(v.strip())]
        if not promoted:
            continue
        obs.type, obs.subtype = "identity", "action"
        if not obs.negated:
            result.api_actions.extend(promoted)


_PLACEHOLDER_VALUE_RE = re.compile(r"^(?:<[^>]+>|\{[^}]+\})$")


def _drop_placeholder_values(result: ExtractedFields) -> None:
    """`data.tenant_name="{your-tenant-name}"` (every Auth0 rule) and
    `"<UNKNOWN REASON>"` getter defaults are templates, not values.
    The field stays in fields_used; the observable goes."""
    kept = []
    for obs in result.observables:
        obs.values = [v for v in obs.values if not _PLACEHOLDER_VALUE_RE.match(str(v).strip())]
        if obs.values:
            kept.append(obs)
    result.observables = kept
    for name in ("api_actions", "target_resources", "network_indicators", "process_names", "file_paths"):
        setattr(result, name, [v for v in getattr(result, name) if not _PLACEHOLDER_VALUE_RE.match(str(v).strip())])


_AUTH0_OPERATION_TYPES = frozenset({"sapi", "fapi", "mgmt_api_read"})


def _promote_auth0_operations(result: ExtractedFields) -> None:
    """Auth0: when `data.type` is a management-API log type, the
    `data.description` ("Update a client", "Get client by ID") IS the
    audited operation -- the only thing those rules key on."""
    if not any(
        o.field.lower() == "data.type" and not o.negated
        and any(str(v).lower() in _AUTH0_OPERATION_TYPES for v in o.values)
        for o in result.observables
    ):
        return
    for obs in result.observables:
        if obs.field.lower() == "data.description" and not obs.negated:
            obs.type, obs.subtype = "cloud", "api_action"
            result.api_actions.extend(v for v in obs.values if v)


def _deduplicate_all(result: ExtractedFields):
    """Deduplicate all extraction lists and drop empty values.

    An observable whose only value is "" (e.g. `sender.email.domain.domain
    == ""`) is a field reference, not an observable: keep the field in
    fields_used, drop the observable. Also applies the
    `network_indicators` surface contract (see _is_network_indicator).
    """
    kept: list[ExtractedObservable] = []
    for obs in result.observables:
        values = [v for v in (obs.values or []) if isinstance(v, str) and v.strip()]
        if not values:
            continue
        obs.values = list(dict.fromkeys(values))
        kept.append(obs)
    result.observables = kept
    # Ports are indicators too, but only when a port observable says so
    # (AS numbers / status codes are numeric and must not pass).
    port_values = {
        v for obs in kept if obs.type == "network" and obs.subtype == "port"
        for v in obs.values
    }
    # Values that only ever appeared under a non-indicator network
    # subtype (payload bodies, user agents, protocol names...) are
    # patterns, not indicators, even when they look domain-like
    # (`*process.mainModule*` from an HTTP body match).
    indicator_subtypes = {"ip_address", "domain", "url", "port"}
    non_indicator_values = {
        v for obs in kept
        if obs.type == "network" and obs.subtype not in indicator_subtypes and obs.subtype != "network_field"
        for v in obs.values
    } - {
        v for obs in kept
        if obs.type in ("network", "email", "dns") and (obs.type != "network" or obs.subtype in indicator_subtypes)
        for v in obs.values
    }
    result.network_indicators = [
        v for v in result.network_indicators
        if isinstance(v, str) and v not in non_indicator_values
        and (v in port_values or _is_network_indicator(v))
    ]
    # Identical observables from a let body and the main pipeline
    # (or two regex passes) collapse to one.
    unique: dict[tuple, ExtractedObservable] = {}
    for obs in result.observables:
        key = (obs.field, tuple(obs.values), obs.negated, obs.type, obs.subtype)
        unique.setdefault(key, obs)
    result.observables = list(unique.values())
    result.fields_used = list(dict.fromkeys(result.fields_used))
    result.event_ids = list(dict.fromkeys(result.event_ids))
    result.process_names = list(dict.fromkeys(result.process_names))
    result.file_paths = list(dict.fromkeys(result.file_paths))
    result.registry_keys = list(dict.fromkeys(result.registry_keys))
    result.network_indicators = list(dict.fromkeys(result.network_indicators))
    result.source_tables = list(dict.fromkeys(result.source_tables))
    _promote_namespaced_event_actions(result)
    _drop_placeholder_values(result)
    _promote_auth0_operations(result)
    # A wildcard pattern ("user.authentication.*") is a match expression,
    # not an action anyone can look up.
    result.api_actions = [a for a in dict.fromkeys(result.api_actions) if "*" not in a and "?" not in a]
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
        obs_type, obs_subtype = _retype_by_value_shape(obs_type, obs_subtype, flat_values)

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
            result.event_ids.extend(
                str(v) for v in flat_values if str(v).isdigit()
            )

        # Exclusions (`filter` selections) describe what the rule ignores;
        # they stay off the flat surfaces.
        if is_negated:
            _route_domain_fields(obs_type, obs_subtype, flat_values, is_negated, result)
            continue

        if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name", "process_path"):
            result.process_names.extend(_extract_exe_names(flat_values))
            if obs_subtype != "process_path":
                # `Image|endswith: /uname` -- Unix binaries have no .exe.
                result.process_names.extend(_bare_unix_names(flat_values))

        if obs_type == "file" and obs_subtype == "file_path":
            # `TargetFilename|endswith: '.bat'` values are EXTENSIONS,
            # not paths — 22.8% of sigma file_paths in the 2026-08-26
            # baseline. Keep them as a file_extension observable.
            paths = [v for v in flat_values if ("\\" in v or "/" in v)]
            exts = [
                v for v in flat_values
                if re.match(r"^\.[A-Za-z0-9]{1,10}$", v.strip())
            ]
            result.file_paths.extend(paths)
            if exts:
                result.observables.append(
                    ExtractedObservable(
                        field=base_field,
                        values=exts,
                        type="file",
                        subtype="file_extension",
                        negated=is_negated,
                    )
                )

        if obs_type == "registry" and obs_subtype == "registry_key":
            # A value-name suffix (`TargetObject|endswith: \\IsCredGuardEnabled`)
            # is the dominant SigmaHQ registry idiom: any backslash-bearing
            # value on a registry_key field is a key fragment.
            result.registry_keys.extend(
                v for v in flat_values if "\\" in str(v) and str(v).strip("*\\")
            )

        if obs_type == "network":
            result.network_indicators.extend(
                v for v in flat_values if v and not re.search(r"\s", str(v))
            )

        # Route domain-specific fields
        _route_domain_fields(obs_type, obs_subtype, flat_values, is_negated, result)


# ===========================================================================
# ECS `event.action` DOMAIN RESOLUTION (Elastic family)
# ===========================================================================
#
# `event.action` is ECS-generic. On endpoint streams it is the telemetry
# verb ("start", "exec", "creation", "connection_attempted"); on cloud
# and identity audit streams it is the API / audit operation
# ("CreateUser", "user.session.start",
# "Microsoft.Authorization/roleAssignments/write"). Only the latter is an
# api_action. The 2026-08-28 corpus census found 2,214 event.action
# observables, ~85% of them endpoint verbs, every one labelled
# cloud/api_action -- so a Linux file-access rule rendered a CLOUD group
# and "exec" / "start" led the api_actions facet.
#
# FIELD_TYPE_MAP therefore classifies event.action neutrally as
# (event, event_action), and the Elastic extractors run this post-pass
# once the whole query has been read. Signals, in descending precision;
# the first decisive one wins:
#
#   1. index patterns -- the rule `index` list (passed by the
#      normalizer) and ES|QL FROM targets -- then `metadata.integration`
#   2. the EQL category head (`process where`, `file where`)
#   3. companion terms in the same query: event.dataset / event.module /
#      data_stream.dataset values, event.provider, the field namespaces
#      in use (okta.*, aws.*, process.*, host.os.*), event.category
#   4. the caller default (elastic_protections is endpoint by definition)
#
# Undecided stays (event, event_action) and off the api_actions surface:
# a missing api_action on a context-free cloud rule is a smaller error
# than "exec" showing up as a cloud API call.

# Integration names as they appear in `logs-<integration>.<dataset>-*`
# index patterns, `event.dataset` / `event.module` values and
# `metadata.integration`. Vocabulary mirrors taxonomy/mappings/elastic.yaml.
_ENDPOINT_INTEGRATIONS = frozenset({
    "endpoint", "endgame", "winlogbeat", "windows", "system", "security",
    "sysmon", "sysmon_linux", "auditd", "auditd_manager", "auditbeat",
    "crowdstrike", "sentinel_one", "sentinel_one_cloud_funnel",
    "microsoft_defender_endpoint", "m365_defender", "jamf_protect",
    "cloud_defend", "fim", "pad", "ded", "lmd", "dga", "beaconing",
    "ml_beaconing", "problemchild",
})
_CLOUD_INTEGRATIONS = frozenset({
    "aws", "aws_bedrock", "azure", "azure_openai", "gcp",
    "google_workspace", "o365", "github", "kubernetes", "cyberarkpas",
    "zoom",  # SaaS webhook audit: meeting.created is an API-side action
})
_IDENTITY_INTEGRATIONS = frozenset({"okta", "auth0", "duo"})
# Streams whose event.action is neither an endpoint verb nor an API
# operation (firewall verdicts, web-server methods, SIEM alert wrappers):
# decisive, but generic -- stays (event, event_action).
_GENERIC_INTEGRATIONS = frozenset({
    "network_traffic", "packetbeat", "panw", "fortinet_fortigate",
    "cisco_ftd", "sonicwall_firewall", "suricata", "zeek", "nginx",
    "apache", "apache_tomcat", "iis", "apm", "elastic_security",
    "google_secops", "microsoft_sentinel", "splunk", "ibm_qradar", "wiz",
    "checkpoint_email",
})
# Azure datasets that are Entra ID (identity) rather than the control plane.
_AZURE_IDENTITY_DATASETS = frozenset({"signinlogs", "auditlogs", "identity_protection"})
# `logs-aws.cloudtrail-*`, `.ds-logs-okta.system-*`, `endgame-*`,
# `winlogbeat-*`, and bare dataset values like `aws.cloudtrail`.
_INDEX_RE = re.compile(r"^(?:\.ds-)?(?:logs-)?([a-z0-9_]+)(?:\.([a-z0-9_]+))?")
_ENDPOINT_EVENT_CATEGORIES = frozenset({
    "process", "file", "network", "registry", "dns", "library", "driver",
    "api", "session",
})
_DATASET_FIELDS = frozenset({"event.dataset", "event.module", "data_stream.dataset"})
_IDENTITY_NAMESPACES = (
    "okta.", "auth0.", "duo.",
    "azure.signinlogs.", "azure.auditlogs.", "azure.identity_protection.",
)
_CLOUD_NAMESPACES = (
    "aws.", "azure.", "gcp.", "google_workspace.", "o365.", "github.",
    "kubernetes.", "cloud.",
)
_ENDPOINT_NAMESPACES = (
    "process.", "file.", "registry.", "dll.", "library.", "driver.",
    "host.os.", "winlog.", "powershell.", "auditd.", "endgame.",
    "crowdstrike.", "sentinel_one.",
)


def _integration_domain(integration: str, dataset: str = "") -> Optional[str]:
    """Domain of an integration name; None when unknown."""
    if integration == "azure":
        return "identity" if dataset in _AZURE_IDENTITY_DATASETS else "cloud"
    if integration in _IDENTITY_INTEGRATIONS:
        return "identity"
    if integration in _CLOUD_INTEGRATIONS:
        return "cloud"
    if integration in _ENDPOINT_INTEGRATIONS:
        return "endpoint"
    if integration in _GENERIC_INTEGRATIONS:
        return "event"
    return None


def _index_domain(pattern: str) -> Optional[str]:
    """Domain of an index pattern or dataset value; None when it carries
    no integration (`logs-*`, `filebeat-*`, `.alerts-security.alerts-*`)."""
    m = _INDEX_RE.match(str(pattern).strip().lower())
    if not m:
        return None
    return _integration_domain(m.group(1), m.group(2) or "")


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)]


def resolve_event_action_domain(
    result: ExtractedFields,
    indices: Iterable[str] = (),
    integrations: Iterable[str] = (),
    default_domain: Optional[str] = None,
) -> Optional[str]:
    """Decide which stream a query's `event.action` belongs to:
    "endpoint", "cloud", "identity", "event" (generic), or the caller
    default when nothing in the query or its rule context is decisive.
    """
    # 1. Index patterns (rule-level, then ES|QL FROM) and integrations.
    for pattern in _as_str_list(indices) + list(result.source_tables):
        domain = _index_domain(pattern)
        if domain:
            return domain
    for name in _as_str_list(integrations):
        domain = _integration_domain(name.strip().lower())
        if domain:
            return domain

    # 2. EQL category head (`process where ...`).
    for table in result.source_tables:
        if table.lower() in _ENDPOINT_EVENT_CATEGORIES:
            return "endpoint"

    # 3. Companion terms.
    for obs in result.observables:
        name = obs.field.lower()
        if name in _DATASET_FIELDS:
            for value in obs.values:
                domain = _index_domain(value)
                if domain:
                    return domain
        elif name == "event.provider":
            for value in obs.values:
                v = value.lower()
                if v.startswith("microsoft-windows") or v in ("sysmon", "auditd"):
                    return "endpoint"
    fields = [f.lower() for f in result.fields_used]
    if any(f.startswith(_IDENTITY_NAMESPACES) for f in fields):
        return "identity"
    if any(f.startswith(_CLOUD_NAMESPACES) for f in fields):
        return "cloud"
    for obs in result.observables:
        if obs.field.lower() == "event.category" and any(
            v.lower() in _ENDPOINT_EVENT_CATEGORIES for v in obs.values
        ):
            return "endpoint"
    if any(f.startswith(_ENDPOINT_NAMESPACES) for f in fields):
        return "endpoint"

    # 4. Caller default.
    return default_domain


def _apply_event_action_domain(result: ExtractedFields, domain: Optional[str]) -> None:
    """Promote (event, event_action) observables to cloud/api_action or
    identity/action and route their values to api_actions. Endpoint,
    generic and undecided domains leave them as they are."""
    if domain == "cloud":
        obs_type, obs_subtype = "cloud", "api_action"
    elif domain == "identity":
        obs_type, obs_subtype = "identity", "action"
    else:
        return
    for obs in result.observables:
        if obs.field.lower() != "event.action":
            continue
        obs.type, obs.subtype = obs_type, obs_subtype
        if not obs.negated:
            result.api_actions.extend(v for v in obs.values if v)


# ===========================================================================
# ELASTIC EXTRACTOR (EQL / KQL / Lucene / ES|QL)
# ===========================================================================

def extract_elastic_fields(
    query: str,
    language: str = "eql",
    indices: Iterable[str] = (),
    integrations: Iterable[str] = (),
    default_domain: Optional[str] = None,
) -> ExtractedFields:
    """Extract fields from Elastic detection queries (EQL, KQL, Lucene, or ES|QL).

    Args:
        query: The query string
        language: One of "eql", "kql", "kuery", "lucene", "esql"
        indices: The rule `index` patterns (context for event.action
            domain resolution -- see resolve_event_action_domain)
        integrations: The rule `metadata.integration` names (same use)
        default_domain: Domain to assume when the query carries no
            decisive context ("endpoint" for protection artifacts)

    Returns:
        ExtractedFields with extracted observables
    """
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query = query.strip()
    lang = language.lower()

    if lang in ("ml", "machine_learning"):
        # ML rules carry no query -- the parser synthesizes
        # "Machine Learning Job: [...]" text, which used to yield a
        # bogus `Job` field. Nothing to extract.
        return result

    if lang == "esql":
        return extract_esql_fields(
            query, indices=indices, integrations=integrations,
            default_domain=default_domain,
        )
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

    _apply_event_action_domain(
        result,
        resolve_event_action_domain(result, indices, integrations, default_domain),
    )
    _deduplicate_all(result)
    return result


_EQL_OPS = ("not in~", "not in", "like~", "like", "regex~", "regex", "in~", "in", "==", "!=", ":")


def _eql_terms(query: str) -> list[tuple[str, list[str], bool, str]]:
    """Quote-aware scan of EQL comparisons: (field, values, negated, op).

    Reads every `field <op> value` where op is one of `==`, `!=`, `:`,
    `like`, `like~`, `regex`, `regex~`, `in`, `in~`, `not in`, and the
    value is a string literal, a number, or a parenthesised tuple of
    them (`process.name : ("cmd.exe", "pwsh.exe")`, possibly spanning
    lines). A `not` before the term or before an enclosing group flips
    negation, so exclusion blocks (`not (process.name : "x" and ...)`)
    are recorded negated instead of as things the rule detects (the
    2026-08-30 review found 17/28 EQL rules with allowlists landing on
    process_names and hash surfaces). `?field` optional-field syntax is
    read as the field.
    """
    terms: list[tuple[str, list[str], bool, str]] = []
    n = len(query)
    i = 0
    neg_stack: list[bool] = []
    pending_not = False

    def skip_string(pos: int) -> int:
        if query.startswith('"""', pos):
            j = query.find('"""', pos + 3)
            return n if j == -1 else j + 3
        q = query[pos]
        j = pos + 1
        while j < n:
            if query[j] == "\\":
                j += 2
                continue
            if query[j] == q:
                return j + 1
            j += 1
        return n

    def literal_at(pos: int) -> tuple[str | None, int]:
        """A string literal or number at pos -> (value, end) else (None, pos)."""
        if pos < n and query[pos] in "\"'":
            e = skip_string(pos)
            raw = query[pos:e]
            if raw.startswith('"""'):
                return raw[3:-3], e
            return raw[1:-1], e
        m = re.match(r"-?\d+(?:\.\d+)?", query[pos:])
        if m:
            return m.group(0), pos + len(m.group(0))
        return None, pos

    while i < n:
        ch = query[i]
        if ch in "\"'":
            i = skip_string(i)
            pending_not = False
            continue
        if ch == "(":
            neg_stack.append(pending_not)
            pending_not = False
            i += 1
            continue
        if ch == ")":
            if neg_stack:
                neg_stack.pop()
            i += 1
            continue
        if ch.isspace() or ch in ",|":
            i += 1
            continue
        m = re.match(r"\??[A-Za-z_][\w.]*", query[i:])
        if not m:
            i += 1
            continue
        token = m.group(0)
        j = i + len(token)
        low = token.lower()
        if low == "not":
            pending_not = True
            i = j
            continue
        if low in ("and", "or", "where", "sequence", "by", "until", "with", "maxspan"):
            pending_not = False
            i = j
            continue
        k = j
        while k < n and query[k] in " \t\r\n":
            k += 1
        op = None
        for cand in _EQL_OPS:
            if query[k:k + len(cand)].lower() == cand:
                after = query[k + len(cand):k + len(cand) + 1]
                if cand[-1].isalpha() and after and (after.isalnum() or after == "_"):
                    continue
                op = cand
                break
        if op is None:
            pending_not = False
            i = j
            continue
        k += len(op)
        while k < n and query[k] in " \t\r\n":
            k += 1
        context_neg = pending_not or any(neg_stack)
        pending_not = False
        op_neg = op in ("!=", "not in", "not in~")
        negated = context_neg != op_neg
        field = token.lstrip("?")
        values: list[str] = []
        if k < n and query[k] == "(":
            depth = 1
            p = k + 1
            while p < n and depth:
                if query[p] in "\"'":
                    lit, e = literal_at(p)
                    if lit is not None:
                        values.append(lit)
                    p = e
                    continue
                if query[p] == "(":
                    depth += 1
                elif query[p] == ")":
                    depth -= 1
                p += 1
            # numbers inside the tuple
            group = query[k + 1:p - 1] if depth == 0 else query[k + 1:p]
            if not values:
                values = re.findall(r"-?\d+(?:\.\d+)?", group)
            i = p
        else:
            lit, e = literal_at(k)
            if lit is None:
                i = k
                continue
            values = [lit]
            i = e
        if values:
            terms.append((field, values, negated, op))
    return terms


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

    for field_name, values, negated, _op in _eql_terms(query):
        _add_elastic_observable(field_name, values, negated, result)


_KQL_BARE_STOP = frozenset({"and", "or", "not", "true", "false", "null", "*"})


def _kql_field_terms(query: str) -> list[tuple[str, list[str], bool]]:
    """Quote-aware `field : value` scan shared by KQL and Lucene.

    The previous regex ran over the raw text and matched INSIDE string
    literals, so `process.executable : ("C:\\\\Program Files\\\\x.exe")`
    produced a bogus `C` field with value `\\\\Program` (issue #6 audit,
    2026-08-29). This walks the query once, skipping quoted strings,
    and for each `name :` outside quotes reads exactly one value:

      - `"quoted"`                -> [quoted]
      - `(a or "b" or c*)`        -> every quoted string inside the
                                     balanced group, else bare tokens
                                     split on and/or
      - `bare-token`              -> [token]

    A `not` immediately before the field (or before an opening group
    that contains it) marks the term negated. Comparison operators
    (`>=`, `<`) are not KQL colon terms and are skipped by design.
    """
    terms: list[tuple[str, list[str], bool]] = []
    n = len(query)
    i = 0
    # Stack of negation flags per open paren so `not (a:x or b:y)`
    # negates both terms.
    neg_stack: list[bool] = []
    pending_not = False

    def skip_string(pos: int) -> int:
        q = query[pos]
        j = pos + 1
        while j < n:
            if query[j] == "\\":
                j += 2
                continue
            if query[j] == q:
                return j + 1
            j += 1
        return n

    while i < n:
        ch = query[i]
        if ch in "\"'":
            i = skip_string(i)
            pending_not = False
            continue
        if ch == "(":
            neg_stack.append(pending_not)
            pending_not = False
            i += 1
            continue
        if ch == ")":
            if neg_stack:
                neg_stack.pop()
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        m = re.match(r"[A-Za-z_@][\w.@\-]*", query[i:])
        if not m:
            i += 1
            continue
        token = m.group(0)
        j = i + len(token)
        low = token.lower()
        if low == "not":
            pending_not = True
            i = j
            continue
        if low in ("and", "or"):
            pending_not = False
            i = j
            continue
        # field : value ?
        k = j
        while k < n and query[k] in " \t":
            k += 1
        if k >= n or query[k] != ":":
            pending_not = False
            i = j
            continue
        k += 1
        while k < n and query[k] in " \t\r\n":
            k += 1
        negated = pending_not or any(neg_stack)
        pending_not = False
        if k >= n:
            break
        if query[k] in "\"'":
            end = skip_string(k)
            terms.append((token, [query[k + 1:end - 1]], negated))
            i = end
            continue
        if query[k] == "(":
            depth = 1
            p = k + 1
            while p < n and depth:
                if query[p] in "\"'":
                    p = skip_string(p)
                    continue
                if query[p] == "(":
                    depth += 1
                elif query[p] == ")":
                    depth -= 1
                p += 1
            group = query[k + 1:p - 1] if depth == 0 else query[k + 1:p]
            values = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', group)
            if not values:
                values = [
                    v.strip() for v in re.split(r"\s+(?:or|and)\s+", group, flags=re.IGNORECASE)
                    if v.strip() and v.strip().lower() not in _KQL_BARE_STOP
                ]
            terms.append((token, values, negated))
            i = p
            continue
        bare = re.match(r"[^\s()]+", query[k:])
        if bare:
            value = bare.group(0)
            if value.lower() not in _KQL_BARE_STOP or value == "*":
                terms.append((token, [value], negated))
            i = k + len(value)
            continue
        i = k
    return terms


def _extract_elastic_kql_fields(query: str, result: ExtractedFields):
    """Extract fields from Elastic KQL (Kuery) queries."""
    conditions = len(re.findall(r'\b(and|or)\b', query, re.IGNORECASE))
    result.query_complexity = "moderate" if conditions > 2 else "simple"
    for field_name, values, negated in _kql_field_terms(query):
        _add_elastic_observable(field_name, values, negated, result)


def _extract_lucene_fields(query: str, result: ExtractedFields):
    """Extract fields from Lucene queries."""
    conditions = len(re.findall(r'\b(AND|OR)\b', query))
    result.query_complexity = "moderate" if conditions > 2 else "simple"
    for field_name, values, negated in _kql_field_terms(query):
        _add_elastic_observable(field_name, values, negated, result)


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
        # Numeric codes only ("4688"). O365/Azure integrations put
        # OPERATION NAMES in event.code (AzureActiveDirectoryStsLogon,
        # ComplianceDLPExchange) — 36.9% of elastic event_ids in the
        # 2026-08-26 baseline. Those are API actions, not event IDs.
        for v in values:
            s = str(v)
            if s.isdigit():
                result.event_ids.append(s)
            elif re.match(r"^[A-Za-z][\w.-]*$", s):
                result.api_actions.append(s)

    # Exclusions describe what the rule ignores, not what it detects:
    # negated values stay off the flat surfaces (2026-08-30 review --
    # EQL allowlists were landing on process_names and hashes).
    if negated:
        _route_domain_fields(obs_type, obs_subtype, values, negated, result)
        return

    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name", "process_path"):
        result.process_names.extend(_extract_exe_names(values))
        # Also add bare process names (without .exe) for Linux
        if obs_subtype != "process_path":
            for v in values:
                v_clean = v.strip('"').strip("*").strip("\\").strip("/")
                if v_clean and not v_clean.endswith('.exe') and '.' not in v_clean and '\\' not in v_clean and '/' not in v_clean and '*' not in v_clean:
                    if v_clean.lower() not in [n.lower() for n in result.process_names]:
                        result.process_names.append(v_clean.lower())

    if obs_type == "file" and "path" in obs_subtype:
        # Bare extensions / method names (".load") are not paths.
        result.file_paths.extend(v for v in values if ("\\" in v or "/" in v))

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

# ESCU (Splunk Security Content) macros that carry the observable
# themselves. `process_rundll32` expands upstream to
# `Processes.process_name=rundll32.exe OR Processes.original_file_name=RUNDLL32.EXE`;
# data-source macros expand to a sourcetype. Blanking them (the previous
# behaviour) lost the process name in 2/14 and the data source in 8/14
# sampled rules (2026-08-30 review). Unknown macros are still blanked.
_ESCU_PROCESS_MACRO_NAMES: dict[str, list[str]] = {
    "powershell": ["powershell.exe", "pwsh.exe"],
    "net": ["net.exe", "net1.exe"],
    "python": ["python.exe", "python3.exe"],
    "java": ["java.exe", "javaw.exe"],
    "cmd": ["cmd.exe"],
}
_ESCU_SOURCE_MACROS: dict[str, str] = {
    "sysmon": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "wineventlog_security": "XmlWinEventLog:Security",
    "wineventlog_system": "XmlWinEventLog:System",
    "wineventlog_application": "XmlWinEventLog:Application",
    "powershell": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
    "wmi": "XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational",
    "kube_audit": "kube:apiserver:audit",
    "linux_syslog": "linux:syslog",
    "linux_auditd": "linux:audit",
    "cloudtrail": "aws:cloudtrail",
    "aws_cloudwatchlogs_eks": "aws:cloudwatchlogs:eks",
    "azure_monitor_aad": "azure:monitor:aad",
    "azure_audit": "azure:monitor:activity",
    "o365_management_activity": "o365:management:activity",
    "okta": "OktaIM2:log",
    "gsuite_gmail": "gsuite:gmail:bigquery",
    "gws_reports_login": "gws:reports:login",
    "gws_reports_admin": "gws:reports:admin",
    "gcp_pubsub_events": "google:gcp:pubsub:message",
    "zeek_conn": "bro:conn:json",
    "suricata": "suricata",
    "cisco_secure_firewall": "cisco:sfw:estreamer",
    "circleci": "circleci",
    "github": "github",
    "splunkd": "splunkd",
    "audit_searches": "audittrail",
    "crowdstrike_stream": "CrowdStrike:Event:Streams:JSON",
    "sysmon_linux": "sysmon:linux",
    "osquery_process": "osquery:results",
    "snowflake": "snowflake",
}
_ESCU_MACRO_REF_RE = re.compile(r"`(process_[a-z0-9_]+|[a-z0-9_]+)(?:\([^`]*\))?`")


def _expand_escu_macros(search: str) -> str:
    """Inline the ESCU macros we understand; leave the rest for the
    blanking pass."""
    def sub(m: re.Match) -> str:
        name = m.group(1).lower()
        if name.startswith("process_"):
            stem = name[len("process_"):]
            exes = _ESCU_PROCESS_MACRO_NAMES.get(stem, [f"{stem}.exe"])
            return " (" + " OR ".join(f"Processes.process_name={e}" for e in exes) + ") "
        if name in _ESCU_SOURCE_MACROS:
            return f" sourcetype={_ESCU_SOURCE_MACROS[name]} "
        return m.group(0)
    return _ESCU_MACRO_REF_RE.sub(sub, search)
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
    if negated:
        # Exclusions stay off the flat surfaces.
        _route_domain_fields(obs_type, obs_subtype, values, negated, result)
        return
    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name", "process_path", "parent_process_path"):
        # `TargetImage=*lsass.exe` is a path field; the basename is the
        # observable people search for.
        result.process_names.extend(_extract_exe_names(values))
    if obs_type == "process" and obs_subtype == "command_line_pattern":
        # `TaskContent IN ("*powershell.exe*")`: a lone executable token
        # inside a command-line pattern names the process.
        result.process_names.extend(
            n for v in values if re.fullmatch(r"\*?[\w.-]+\.exe\*?", v.strip(), re.IGNORECASE)
            for n in _extract_exe_names([v])
        )
    if obs_type == "file" and "path" in obs_subtype:
        # Extensions and bare filenames are not paths.
        result.file_paths.extend(
            v for v in values if ("\\" in v or "/" in v)
        )
        # 4663 object access on a registry path (`object_file_path=
        # "*\\CurrentVersion\\Uninstall\\*"`) is a registry key.
        result.registry_keys.extend(_extract_registry_paths(values))
    if obs_type == "registry":
        if obs_subtype == "registry_key":
            result.registry_keys.extend(v for v in values if "\\" in v and v.strip("*\\"))
        else:
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
    # `NOT (a=x OR b=y)` groups: parse the inside negated, then blank it.
    text, negated_groups = _split_spl_not_groups(text)
    for inner in negated_groups:
        _parse_spl_expression_terms(inner, result, derived, negated=True)
    _parse_spl_expression_terms(text, result, derived, negated=False)


def _split_spl_not_groups(text: str) -> tuple[str, list[str]]:
    out = text
    groups: list[str] = []
    for m in list(re.finditer(r"\bNOT\s*\(", text, re.IGNORECASE))[::-1]:
        depth, p = 1, m.end()
        while p < len(text) and depth:
            if text[p] == "(":
                depth += 1
            elif text[p] == ")":
                depth -= 1
            p += 1
        if depth:
            continue
        groups.append(text[m.end():p - 1])
        out = out[:m.start()] + " " + out[p:]
    return out, groups


_SPL_NON_VALUES = frozenset({"null", "null()", "-", "*", "true", "false"})


def _parse_spl_expression_terms(
    text: str, result: ExtractedFields, derived: set[str], negated: bool
) -> None:
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
                for v in re.split(r"[,\s]+", values_str)
                if v.strip()
            ]
        values = [v for v in values if v.lower() not in _SPL_NON_VALUES]
        if values:
            _spl_add_observable(field_name, values, negated, result)

    remainder = _SPL_IN_RE.sub(" ", text)
    for m in _SPL_EXPR_RE.finditer(remainder):
        field_name, op = m.group(1), m.group(2)
        value = m.group(3) or m.group(4) or _spl_clean_bare_value(m.group(5) or "")
        if not _spl_valid_field(field_name, derived):
            continue
        # A "value" that is pure wildcard/punctuation is match-anything
        # noise, not an observable; `!= null` is an existence check; a
        # threshold (`ut_shannon > 3`) is tuning, not telemetry.
        if not value or not re.search(r"[A-Za-z0-9]", value) or value.lower() in _SPL_NON_VALUES or op in ("<", ">", "<=", ">="):
            result.fields_used.append(field_name)
            continue
        _spl_add_observable(field_name, [value], negated != (op == "!="), result)

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
    cleaned = _expand_escu_macros(_SPL_COMMENT_RE.sub(" ", search))

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

# Stage-aware KQL tokenizer (issue #6 rebuild). The previous extractor
# ran flat regexes over the whole query: `sort by RiskScore desc` fed
# the summarize-by scraper ("RiskScore desc"), `bin(TimeGenerated, 1d)`
# comma-split into "1d)", and multi-let scripts defeated the let-strip
# regex so KQL fragments landed in source_tables — 1,675 junk
# fields_used entries in the 2026-08-26 baseline. This version splits
# statements and pipeline stages with a quote-aware scanner, dispatches
# per operator, validates every field name, and tracks derived columns
# (let names, extend/summarize/project aliases, parse captures).

_KQL_IDENT_RE = re.compile(r"^[A-Za-z_][\w.]*$")
_KQL_KEYWORDS = frozenset({
    "and", "or", "not", "by", "on", "kind", "let", "where", "project",
    "extend", "summarize", "join", "union", "sort", "order", "asc",
    "desc", "nulls", "first", "last", "take", "limit", "top",
    "distinct", "count", "bin", "ago", "now", "datetime", "timespan",
    "dynamic", "true", "false", "null", "case", "iff", "iif",
    "between", "with", "matches", "regex", "has", "contains",
    "startswith", "endswith", "in", "string", "long", "int", "real",
    "bool", "boolean", "guid", "hint", "isfuzzy", "step", "of",
    "evaluate", "render", "serialize", "materialize", "pack",
    "toscalar", "range", "print",
})
# Scalar wrappers unwrapped before term matching: tolower(Field) == "x"
_KQL_SCALAR_FUNCS = (
    "tolower", "toupper", "tostring", "totitle", "trim", "tolong",
    "toint", "todouble", "todatetime", "todynamic", "tourl", "url_decode",
    "extract", "coalesce", "column_ifexists",
)
_KQL_AGG_ARG_RE = re.compile(
    r"\b(?:count|countif|dcount|dcountif|min|max|sum|sumif|avg|make_set|"
    r"make_list|make_bag|arg_max|arg_min|any|take_any|percentile)\s*\(\s*"
    r"([A-Za-z_][\w.]*)",
    re.IGNORECASE,
)


def _kql_split(text: str, sep: str) -> list[str]:
    """Split on `sep` at depth 0, outside strings. Handles KQL string
    forms: "..", '..', and verbatim @".." / @'..' (no escapes)."""
    parts: list[str] = []
    buf: list[str] = []
    quote: Optional[str] = None
    verbatim = False
    depth = 0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if not verbatim and ch == "\\":
                buf.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            verbatim = bool(buf) and buf[-1] == "@"
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p for p in (part.strip() for part in parts) if p]


def _kql_valid_field(name: str, derived: set[str]) -> bool:
    return (
        bool(_KQL_IDENT_RE.match(name))
        and name.lower() not in _KQL_KEYWORDS
        and name not in derived
    )


def _kql_is_table(name: str, derived: set[str]) -> bool:
    if not re.match(r"^[A-Za-z_]\w*$", name) or name in derived:
        return False
    return name.lower() in SENTINEL_TABLES or name[0].isupper()


class _KqlDerived(set):
    """Derived column names plus what the KQL pipeline told us about
    them: `alias_of` maps a derived name to the single real column it
    was computed from (`extend process = split(Image, '\\\\', -1)[-1]`
    -> process: Image), `lists` holds `let X = dynamic([...])` values
    and `scalars` holds `let x = "v"` / `declare query_parameters(x =
    "v")` defaults, so terms written against them resolve to the
    underlying column / values instead of vanishing (2026-08-30 review:
    an ADFS rule lost 7 process names and a named pipe, an Okta rule
    lost its 8 admin actions)."""

    def __init__(self) -> None:
        super().__init__()
        self.alias_of: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}
        self.scalars: dict[str, str] = {}


def _kql_resolve_alias(name: str, derived: set) -> str:
    alias_of = getattr(derived, "alias_of", {})
    seen = set()
    while name in alias_of and name not in seen:
        seen.add(name)
        name = alias_of[name]
    return name


_KQL_COLUMN_IFEXISTS_RE = re.compile(r"\bcolumn_ifexists\s*\(\s*[\"']([A-Za-z_][\w.]*)[\"']\s*,[^()]*\)", re.IGNORECASE)


def _kql_unwrap_column_ifexists(text: str) -> str:
    """column_ifexists("Image", "") -> Image (the real column)."""
    return _KQL_COLUMN_IFEXISTS_RE.sub(r"\1", text)


def _kql_mask_strings(text: str) -> str:
    return re.sub(r"@?\"[^\"]*\"|@?'[^']*'", '""', text)


def _kql_unwrap_scalars(text: str) -> str:
    """tolower(Field) -> Field, repeatedly, so term patterns see the
    underlying column."""
    text = _kql_unwrap_column_ifexists(text)
    pattern = re.compile(
        r"\b(?:%s)\s*\(([^()]*)\)" % "|".join(_KQL_SCALAR_FUNCS),
        re.IGNORECASE,
    )
    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(r"\1", text)
    return text


def _kql_expression(text: str, result: ExtractedFields, derived: set[str]) -> None:
    """Terms of a `where` expression."""
    text = _kql_unwrap_scalars(text)
    lists = getattr(derived, "lists", {})
    scalars = getattr(derived, "scalars", {})

    def field_ok(name: str) -> Optional[str]:
        real = _kql_resolve_alias(name, derived)
        return real if _kql_valid_field(real, derived) else None

    # field in/!in/in~/!in~ (list...)
    for m in re.finditer(
        r"([A-Za-z_][\w.]*)\s+(!?in~?)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)",
        text,
    ):
        field_name, op, values_str = m.group(1), m.group(2), m.group(3)
        real = field_ok(field_name)
        if real is None:
            continue
        values = re.findall(r'"([^"]*)"', values_str)
        values += re.findall(r"'([^']*)'", values_str)
        if not values:
            values = re.findall(r"\b(\d+)\b", values_str)
        if not values:
            # `Field in (AdminActivity)` where the list is a let-bound dynamic([...]).
            ref = values_str.strip()
            if ref in lists:
                values = list(lists[ref])
        if values:
            _add_sentinel_observable(
                real, values, op.startswith("!"), result
            )
        elif real not in result.fields_used:
            # `Field in (LetBoundList)` — the list content lives in a
            # let, but the field reference is real.
            result.fields_used.append(real)
    text_wo_in = re.sub(
        r"([A-Za-z_][\w.]*)\s+!?in~?\s*\([^()]*(?:\([^()]*\)[^()]*)*\)", " ", text
    )

    # Binary comparisons: == =~ != !~ with quoted / verbatim / numeric
    # values, or a let-bound scalar name (`TechnicalName == technicalName`).
    for m in re.finditer(
        r"([A-Za-z_][\w.]*)\s*(==|=~|!=|!~)\s*(?:@?\"([^\"]*)\"|@?'([^']*)'|(\d+)|([A-Za-z_]\w*))",
        text_wo_in,
    ):
        field_name, op = m.group(1), m.group(2)
        value = m.group(3) or m.group(4) or m.group(5) or ""
        if not value and m.group(6):
            value = scalars.get(m.group(6), "")
        real = field_ok(field_name)
        if real is not None and value != "":
            _add_sentinel_observable(
                real, [value], op.startswith("!"), result
            )

    # String operators with a single quoted (or verbatim @'...') value
    for m in re.finditer(
        r"([A-Za-z_][\w.]*)\s+(!?(?:contains|has|startswith|endswith)(?:_cs)?"
        r"|hasprefix|hassuffix|matches\s+regex)\s+@?(?:\"([^\"]*)\"|'([^']*)')",
        text_wo_in, re.IGNORECASE,
    ):
        field_name, op = m.group(1), m.group(2)
        value = m.group(3) or m.group(4) or ""
        real = field_ok(field_name)
        if real is not None and value:
            if op.lower().startswith("matches"):
                values, pattern = _kql_regex_values(value)
                _add_sentinel_observable(real, values, False, result, pattern=pattern)
            else:
                _add_sentinel_observable(
                    real, [value], op.startswith("!"), result
                )

    # has_any / has_all (list)
    for m in re.finditer(
        r"([A-Za-z_][\w.]*)\s+has_(?:any|all)\s*\(([^()]*)\)", text_wo_in,
        re.IGNORECASE,
    ):
        field_name, values_str = m.group(1), m.group(2)
        values = re.findall(r'"([^"]*)"', values_str) + re.findall(r"'([^']*)'", values_str)
        real = field_ok(field_name)
        if real is None:
            continue
        if not values and values_str.strip() in lists:
            values = list(lists[values_str.strip()])
        if values:
            _add_sentinel_observable(real, values, False, result)
        elif real not in result.fields_used:
            result.fields_used.append(real)

    # isempty/isnotempty/isnull/isnotnull(Field) — field reference only
    for m in re.finditer(
        r"\bis(?:not)?(?:empty|null)\s*\(\s*([A-Za-z_][\w.]*)\s*\)",
        text_wo_in, re.IGNORECASE,
    ):
        if _kql_valid_field(m.group(1), derived) and m.group(1) not in result.fields_used:
            result.fields_used.append(m.group(1))


def _kql_regex_values(pattern: str) -> tuple[list[str], bool]:
    """`Artifacts.Feed.(Org|Project).Modify` -> the two literal values;
    anything else stays one pattern value flagged as such."""
    m = re.fullmatch(r"([\w.\-/ ]*)\(([\w.\-/ |]+)\)([\w.\-/ ]*)", pattern)
    if m and "|" in m.group(2):
        return [m.group(1) + alt + m.group(3) for alt in m.group(2).split("|")], False
    is_pattern = bool(re.search(r"[\\^$*+?()\[\]{}|]", pattern))
    return [pattern], is_pattern


def _kql_field_list(
    text: str, result: ExtractedFields, derived: set[str],
    alias_targets_derived: bool = True,
) -> None:
    """Comma-separated column list (project / distinct / by / sort).

    Entries may be `Alias = expr` (alias derived, expr idents real),
    `bin(Field, 1d)` (Field real), or bare fields with sort modifiers.
    """
    for entry in _kql_split(text, ","):
        entry = entry.strip()
        m = re.match(r"([A-Za-z_][\w.]*)\s*=(?!=)(.*)$", entry, re.DOTALL)
        if m:
            alias = m.group(1)
            rhs = _kql_unwrap_column_ifexists(m.group(2))
            # Identifiers of the expression, minus string literals and
            # function names (`extract(`, `tostring(`, format strings).
            masked = _kql_mask_strings(rhs)
            idents = [
                i for i in re.findall(r"[A-Za-z_][\w.]*(?![\w.])(?!\s*\()", masked)
                if not re.match(r"^\d", i)
            ]
            idents = [_kql_resolve_alias(i, derived) for i in idents]
            real = [i for i in dict.fromkeys(idents) if _kql_valid_field(i, derived)]
            if alias_targets_derived and not (real == [alias]):
                # `extend Image = column_ifexists("Image", "")` keeps
                # Image a real column; a genuinely new name is derived,
                # remembering its single source column when there is one.
                derived.add(alias)
                if len(real) == 1 and hasattr(derived, "alias_of"):
                    derived.alias_of[alias] = real[0]
            for ident in real:
                if ident not in result.fields_used:
                    result.fields_used.append(ident)
            continue
        binm = re.match(r"bin\s*\(\s*([A-Za-z_][\w.]*)", entry, re.IGNORECASE)
        if binm:
            entry = binm.group(1)
        # Strip sort modifiers.
        entry = re.sub(
            r"\s+(?:asc|desc|nulls\s+(?:first|last))\s*$", "", entry,
            flags=re.IGNORECASE,
        ).strip()
        if _kql_valid_field(entry, derived) and entry not in result.fields_used:
            result.fields_used.append(entry)


def _kql_source_expr(
    text: str, result: ExtractedFields, derived: set[str], depth: int = 0
) -> None:
    """Stage-0 source: `Table`, `union [mods] T1, T2, (T3 | ...)`,
    `materialize(...)`."""
    text = text.strip()
    um = re.match(r"union\b(.*)$", text, re.IGNORECASE | re.DOTALL)
    if um:
        body = um.group(1)
        body = re.sub(r"\b(?:kind|hint\.\w+|isfuzzy)\s*=\s*\w+", " ", body)
        for token in _kql_split(body, ","):
            token = token.strip()
            if token.startswith("("):
                # Parenthesized union branch is a full sub-pipeline:
                # union isfuzzy=true (T1 | where ...), (T2 | where ...)
                _kql_pipeline(token, result, derived, depth + 1)
                continue
            token = token.rstrip("*").strip()
            if token and _kql_is_table(token, derived):
                result.source_tables.append(token)
        return
    first = re.match(r"[A-Za-z_]\w*", text)
    if first and _kql_is_table(first.group(0), derived):
        result.source_tables.append(first.group(0))


def _kql_pipeline(
    text: str, result: ExtractedFields, derived: set[str], depth: int = 0
) -> None:
    if depth > 6:
        return
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    text = re.sub(r"^materialize\s*\(", "(", text, flags=re.IGNORECASE)
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()

    stages = _kql_split(text, "|")
    if not stages:
        return
    _kql_source_expr(stages[0], result, derived, depth)

    for stage in stages[1:]:
        stage = stage.strip()
        first, _, rest = stage.partition(" ")
        cmd = first.lower().rstrip("-")
        if cmd == "where" or cmd == "and":
            _kql_expression(rest, result, derived)
        elif cmd in ("project", "distinct"):
            _kql_field_list(rest, result, derived)
        elif cmd.startswith("project"):
            # project-away/-keep/-rename/-reorder reference real columns
            _kql_field_list(rest, result, derived, alias_targets_derived=False)
        elif cmd == "extend":
            _kql_field_list(rest, result, derived)
        elif cmd == "summarize":
            parts = re.split(r"\bby\b", rest, maxsplit=1, flags=re.IGNORECASE)
            for m in _KQL_AGG_ARG_RE.finditer(parts[0]):
                if _kql_valid_field(m.group(1), derived) and m.group(1) not in result.fields_used:
                    result.fields_used.append(m.group(1))
            # `Alias = agg(...)` targets are derived.
            for am in re.finditer(r"(?:^|,)\s*([A-Za-z_][\w.]*)\s*=(?!=)", parts[0]):
                derived.add(am.group(1))
            if len(parts) > 1:
                _kql_field_list(parts[1], result, derived)
        elif cmd in ("sort", "order", "top"):
            bym = re.split(r"\bby\b", rest, maxsplit=1, flags=re.IGNORECASE)
            if len(bym) > 1:
                _kql_field_list(bym[1], result, derived)
        elif cmd == "join":
            # Optional (subpipeline) then `on` keys.
            sub = re.search(r"\((.*)\)\s*on\b", stage, re.DOTALL)
            on_part = re.split(r"\bon\b", stage, maxsplit=1, flags=re.IGNORECASE)
            if sub:
                _kql_pipeline(sub.group(1), result, derived, depth + 1)
            else:
                jt = re.search(
                    r"join\s+(?:kind\s*=\s*\w+\s+)?(?:hint\.\w+\s*=\s*\w+\s+)?"
                    r"\(?\s*([A-Za-z_]\w*)", stage, re.IGNORECASE,
                )
                if jt and _kql_is_table(jt.group(1), derived):
                    result.source_tables.append(jt.group(1))
            if len(on_part) > 1:
                for key in _kql_split(on_part[1], ","):
                    for ident in re.findall(r"\$(?:left|right)\.([\w.]+)|^\s*([A-Za-z_][\w.]*)\s*$", key):
                        name = ident[0] or ident[1]
                        if name and _kql_valid_field(name, derived) and name not in result.fields_used:
                            result.fields_used.append(name)
        elif cmd == "union":
            _kql_source_expr(stage, result, derived)
        elif cmd in ("mv-expand", "mvexpand"):
            _kql_field_list(rest, result, derived, alias_targets_derived=False)
        elif cmd == "parse":
            # `parse Field with * "lit" Capture ...` — source real,
            # captures derived.
            pm = re.match(r"(?:kind\s*=\s*\w+\s+)?([A-Za-z_][\w.]*)\s+with\b(.*)$", rest, re.IGNORECASE | re.DOTALL)
            if pm:
                if _kql_valid_field(pm.group(1), derived) and pm.group(1) not in result.fields_used:
                    result.fields_used.append(pm.group(1))
                cleaned = re.sub(r'"[^"]*"|\'[^\']*\'', " ", pm.group(2))
                derived.update(
                    t for t in re.findall(r"[A-Za-z_]\w*", cleaned)
                    if t not in ("with", "kind", "regex", "simple")
                )
        # count/take/limit/render/serialize/evaluate/invoke: no fields.


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

    # Determine complexity (same heuristic as pre-rebuild).
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

    # Strip // line comments (quote-naive strip is safe enough: URLs in
    # strings use ://, so require whitespace or line start before //).
    query = re.sub(r"(?:^|(?<=\s))//[^\n]*", " ", query)

    derived: _KqlDerived = _KqlDerived()
    statements = _kql_split(query, ";")

    # Pass 1: let-bound names are derived everywhere; list and scalar
    # lets (and query_parameters defaults) are remembered by value.
    let_bodies: list[str] = []
    pipelines: list[str] = []
    for stmt in statements:
        qp = re.match(r"\s*declare\s+query_parameters\s*\((.*)\)\s*$", stmt, re.IGNORECASE | re.DOTALL)
        if qp:
            for pm in re.finditer(r"([A-Za-z_]\w*)\s*:\s*\w+\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|(\d+))", qp.group(1)):
                derived.add(pm.group(1))
                derived.scalars[pm.group(1)] = pm.group(2) or pm.group(3) or pm.group(4) or ""
            continue
        lm = re.match(r"let\s+([A-Za-z_]\w*)\s*=\s*(.*)$", stmt, re.IGNORECASE | re.DOTALL)
        if lm:
            name, body = lm.group(1), lm.group(2).strip()
            derived.add(name)
            dyn = re.match(r"^dynamic\s*\(\s*\[(.*)\]\s*\)\s*$", body, re.DOTALL)
            if dyn:
                vals = re.findall(r'"([^"]*)"', dyn.group(1)) + re.findall(r"'([^']*)'", dyn.group(1))
                if vals:
                    derived.lists[name] = vals
                continue
            sc = re.match(r"^@?(?:\"([^\"]*)\"|'([^']*)')\s*$", body)
            if sc:
                derived.scalars[name] = sc.group(1) or sc.group(2) or ""
                continue
            let_bodies.append(body)
        elif stmt.strip():
            pipelines.append(stmt)

    # Pass 2: extract. Let bodies that are table expressions (contain a
    # pipe or start with a known table) are pipelines too — scalar lets
    # (`let timeframe = 1d`) contribute nothing and extract nothing.
    for body in let_bodies:
        b = body.strip()
        # Lambda lets — `let f = (tableName:string){ Table | ... };` —
        # carry their pipeline inside the braces.
        lam = re.match(r"^\([^()]*\)\s*\{(.*)\}\s*$", b, re.DOTALL)
        if lam:
            _kql_pipeline(lam.group(1), result, derived)
            continue
        starts_table = re.match(r"^(?:materialize\s*\(\s*)?\(?\s*([A-Za-z_]\w*)", b)
        if "|" in b or (
            starts_table and _kql_is_table(starts_table.group(1), derived)
        ):
            if not re.match(r"^(?:dynamic|datetime|ago|pack|toscalar|tostring)\b", b, re.IGNORECASE):
                _kql_pipeline(b, result, derived)
    for p in pipelines:
        _kql_pipeline(p, result, derived)

    _deduplicate_all(result)
    return result


_LA_SUFFIX_RE = re.compile(r"_(s|d|b|g|t)$")


def _sentinel_classify(field_name: str) -> tuple[str, str]:
    """Classify a Sentinel column, seeing through Log Analytics custom-log
    suffixes: `eventType_s` -> eventType, `outcome_result_s` ->
    outcome.result."""
    t = _classify_field(field_name)
    if t != ("other", "unknown"):
        return t
    base = _LA_SUFFIX_RE.sub("", field_name)
    if base != field_name:
        t = _classify_field(base)
        if t != ("other", "unknown"):
            return t
        t = _classify_field(base.replace("_", "."))
        if t != ("other", "unknown"):
            return t
    return ("other", "unknown")


def _add_sentinel_observable(field_name: str, values: list[str], negated: bool, result: ExtractedFields, pattern: bool = False):
    """Add an observable from Sentinel/KQL field extraction."""
    result.fields_used.append(field_name)
    obs_type, obs_subtype = _sentinel_classify(field_name)
    obs_type, obs_subtype = _retype_by_value_shape(obs_type, obs_subtype, values)

    observable = ExtractedObservable(
        field=field_name,
        values=values,
        type=obs_type,
        subtype=obs_subtype,
        negated=negated,
    )
    result.observables.append(observable)

    if _is_event_id_field(field_name):
        # Numeric codes only — parity with the other extractors.
        result.event_ids.extend(
            str(v) for v in values if str(v).isdigit()
        )

    if negated or pattern:
        # Exclusions and regex patterns stay off the flat surfaces.
        if not pattern:
            _route_domain_fields(obs_type, obs_subtype, values, negated, result)
        return

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

def extract_esql_fields(
    query: str,
    indices: Iterable[str] = (),
    integrations: Iterable[str] = (),
    default_domain: Optional[str] = None,
) -> ExtractedFields:
    """Extract fields from Elastic ES|QL queries.

    Delegates to services.esql_extractor (issue #6 rebuild): stage-
    aware, derived-name tracking, validated identifiers, SQL segments
    in hunting files skipped. Kept here so existing callers and the
    Elastic dispatcher keep one import point. The context arguments
    feed event.action domain resolution (see extract_elastic_fields).
    """
    from app.services.esql_extractor import extract_esql_fields_v2

    return extract_esql_fields_v2(
        query, indices=indices, integrations=integrations,
        default_domain=default_domain,
    )


# ===========================================================================
# SUBLIME MQL EXTRACTOR
# ===========================================================================

# MQL iterator functions whose first argument is a container and whose
# remaining arguments are predicates over ONE ELEMENT of it — inside
# them, `.field` is relative to the container. `any(body.links,
# strings.icontains(.display_text, 'x'))` means body.links.display_text.
_MQL_ITERATORS = frozenset({"any", "all", "filter", "map", "distinct"})
_MQL_TOKEN_RE = re.compile(r"\.?[A-Za-z_$][\w.$]*")
_MQL_FIELD_OK_RE = re.compile(r"^[A-Za-z_][\w.]*$")
_MQL_FIELD_STOPWORDS = frozenset({
    "and", "or", "not", "in", "true", "false", "null", "mode", "type",
    "strings", "regex", "ml", "length", "beta",
})
_MQL_MAX_DEPTH = 12


def _mql_strip_comments(text: str) -> str:
    """Remove `//` line comments outside string literals."""
    out: list[str] = []
    i, n = 0, len(text)
    quote: Optional[str] = None
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                out.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_LITERAL_MARK = "\x01"


def _mask_literals(text: str) -> tuple[str, list[str]]:
    """Replace the BODY of every string literal with an index marker,
    keeping the quotes, so field/value regexes still see a quoted value
    but can never match text that lives inside a literal."""
    out: list[str] = []
    literals: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    break
                j += 1
            literals.append(text[i + 1:j])
            out.append(f"{ch}{_LITERAL_MARK}{len(literals) - 1}{_LITERAL_MARK}{ch}")
            i = min(j + 1, n)
            continue
        out.append(ch)
        i += 1
    return "".join(out), literals


def _unmask_literal(value: str, literals: list[str]) -> str:
    m = re.fullmatch(rf"{_LITERAL_MARK}(\d+){_LITERAL_MARK}", value or "")
    return literals[int(m.group(1))] if m else value


def _mql_split_args(text: str) -> list[str]:
    """Split a call body on top-level commas (quote- and paren-aware)."""
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: Optional[str] = None
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                buf.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    args.append("".join(buf))
    return args


def _mql_container_of(expr: str, scope: str) -> str:
    """The field path an iterator's container expression refers to.

    `body.links` -> body.links; `filter(body.links, ...)` -> body.links;
    `ml.nlu_classifier(body.current_thread.text).intents` ->
    ml.nlu_classifier.intents (call parens collapsed).
    """
    expr = expr.strip()
    # List literal: the element is whichever member resolves to a field
    # first. `[strings.replace_confusables(sender.display_name), ...]`
    # used to resolve to the helper name (2026-08-29 audit).
    if expr.startswith("[") and expr.endswith("]"):
        for element in _mql_split_args(expr[1:-1]):
            if element.strip():
                found = _mql_container_of(element, "")
                if found:
                    return found
        return scope
    m = re.match(r"([A-Za-z_][\w.]*)\s*\(", expr)
    if m:
        name = m.group(1)
        # Find the call's closing paren (quote-aware) to see whether a
        # postfix attribute follows (`ml.nlu_classifier(x).entities`).
        depth, j, quote = 0, m.end() - 1, None
        while j < len(expr):
            cj = expr[j]
            if quote:
                if cj == "\\":
                    j += 2
                    continue
                if cj == quote:
                    quote = None
            elif cj in "\"'":
                quote = cj
            elif cj == "(":
                depth += 1
            elif cj == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = expr[m.end():j]
        postfix = expr[j + 1:].strip()
        if name.split(".")[-1] in _MQL_ITERATORS:
            return _mql_container_of(_mql_split_args(body)[0], scope)
        if not postfix and name.startswith(("strings.", "regex.")):
            # A transform over a field IS that field for scoping purposes.
            args = _mql_split_args(body)
            if args and args[0].strip():
                return _mql_container_of(args[0], scope)
    prev = None
    while prev != expr:
        prev = expr
        expr = re.sub(r"\([^()]*\)", "", expr)
    m2 = re.search(r"[A-Za-z_][\w.]*", expr)
    return m2.group(0) if m2 else scope


def _mql_resolve(text: str, scope: str, depth: int = 0) -> str:
    """Rewrite MQL so every relative `.field` carries its container path.

    Walks the text (quote-aware); iterator calls recurse with their
    container as the new scope; a bare `.` argument (the element
    itself, as in `ml.link_analysis(., ...)`) becomes the scope path.
    The result is a resolved query the flat term patterns can read
    without ever seeing a leading-dot field.
    """
    if depth > _MQL_MAX_DEPTH:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    break
                j += 1
            out.append(text[i:min(j + 1, n)])
            i = min(j + 1, n)
            continue
        m = _MQL_TOKEN_RE.match(text, i) if (ch == "." or ch == "_" or ch == "$" or ch.isalpha()) else None
        if m is None:
            # Bare `.` in argument position = the current element.
            if ch == ".":
                prev = next((c for c in reversed(out) for c in reversed(c) if not c.isspace()), "")
                nxt = text[i + 1] if i + 1 < n else ""
                if scope and prev in "(," and (nxt in ",)" or nxt.isspace()):
                    out.append(scope)
                    i += 1
                    continue
            out.append(ch)
            i += 1
            continue
        token = m.group(0)
        end = m.end()
        rel = token.startswith(".")
        # `.field` directly after `)` or `]` is postfix attribute access
        # on a call result (`ml.link_analysis(...).credphish`) or an
        # index (`headers.hops[0].received`), NOT a container-relative
        # field — keep it verbatim (including its dot).
        prev_char = next(
            (c for chunk in reversed(out) for c in reversed(chunk) if not c.isspace()),
            "",
        )
        if rel and prev_char and prev_char in ")]":
            out.append(token)
            i = end
            continue
        name = token[1:] if rel else token
        resolved = f"{scope}.{name}" if (rel and scope) else name
        # Call?
        k = end
        while k < n and text[k] in " \t\r\n":
            k += 1
        if k < n and text[k] == "(":
            depth_p, j = 1, k + 1
            quote: Optional[str] = None
            while j < n and depth_p:
                cj = text[j]
                if quote:
                    if cj == "\\":
                        j += 2
                        continue
                    if cj == quote:
                        quote = None
                elif cj in "\"'":
                    quote = cj
                elif cj == "(":
                    depth_p += 1
                elif cj == ")":
                    depth_p -= 1
                j += 1
            body = text[k + 1:j - 1] if depth_p == 0 else text[k + 1:j]
            if name.split(".")[-1] in _MQL_ITERATORS:
                args = _mql_split_args(body)
                cont_src = _mql_resolve(args[0], scope, depth + 1)
                cont = _mql_container_of(cont_src, scope)
                rest = [_mql_resolve(a, cont, depth + 1) for a in args[1:]]
                out.append(f"{resolved}({', '.join([cont_src.strip()] + [r.strip() for r in rest])})")
            else:
                out.append(f"{resolved}({_mql_resolve(body, scope, depth + 1)})")
            i = j
            continue
        out.append(resolved)
        i = end
    return "".join(out)


def _mql_valid_field(name: str) -> bool:
    return (
        bool(_MQL_FIELD_OK_RE.match(name))
        and ".." not in name
        and not name.endswith(".")
        and name.lower() not in _MQL_FIELD_STOPWORDS
    )


def extract_sublime_fields(query: str) -> ExtractedFields:
    """Extract fields from Sublime Security MQL (Message Query Language) queries.

    Scope-resolving rebuild (issue #6). The previous extractor's
    `([\\w.]+)` captures kept MQL's leading-dot relative fields verbatim
    (`.display_text` — 3,092 junk fields_used entries in the 2026-08-26
    baseline) and never connected them to their `any()`/`filter()`
    container. This version first REWRITES the query so every relative
    field carries its container path (`any(body.links,
    .display_text == 'x')` reads as `body.links.display_text`), then
    extracts terms from the resolved text with validated field names.

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
    # commented-out clauses leak into observables. Quote-aware: a
    # `//` inside a string literal (`html.xpath(body.html, '//title')`)
    # is content, and eating it unbalanced the quotes and silently
    # broke scope resolution for the rest of the rule (2026-08-29).
    query = _mql_strip_comments(query)

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

    # Resolve iterator scopes so relative fields carry container paths.
    resolved = _mql_resolve(query, "")

    # Numeric subscripts are positional, not part of the field path:
    # `headers.hops[0].received.server.raw` is the hops.received path.
    resolved = re.sub(r"\[\d+\]", "", resolved)

    # Mask string-literal bodies so the term patterns below can never
    # match INSIDE a literal: a regex like
    # `'<p class=".*?"><span style=".*?">'` used to yield `class` and
    # `style` observables with value `.*?`. Values are restored on add.
    resolved, literals = _mask_literals(resolved)

    def add(field_name: str, values: list[str], negated: bool) -> None:
        # Postfix attribute chains on call results keep a leading dot
        # in the resolved text (`...).credphish.disposition`) — the
        # trailing path is the usable field name.
        field_name = field_name.lstrip(".")
        values = [_unmask_literal(v, literals) for v in values]
        if _mql_valid_field(field_name):
            _add_sublime_observable(field_name, values, negated, result)

    seen_pairs: set[tuple[str, str]] = set()

    # Pattern: field == "value" / field == 'value'
    for field_name, dq, sq in re.findall(
        r'([\w.]+)\s*==\s*(?:"([^"]*)"|\'([^\']*)\')', resolved
    ):
        value = dq or sq
        seen_pairs.add((field_name, value))
        add(field_name, [value], False)

    # Pattern: field != "value"
    for field_name, dq, sq in re.findall(
        r'([\w.]+)\s*!=\s*(?:"([^"]*)"|\'([^\']*)\')', resolved
    ):
        add(field_name, [dq or sq], True)

    # Pattern: field = "value" (single equals, common in MQL)
    for field_name, dq, sq in re.findall(
        r'([\w.]+)\s*(?<![=!<>])=\s*(?!=)(?:"([^"]*)"|\'([^\']*)\')', resolved
    ):
        value = dq or sq
        if (field_name, value) not in seen_pairs:
            add(field_name, [value], False)

    # Pattern: field in ("v1", "v2")
    for field_name, values_str in re.findall(
        r'([\w.]+)\s+in~?\s*\(([^)]+)\)', resolved, re.IGNORECASE
    ):
        values = re.findall(r'"([^"]*)"|\'([^\']*)\'', values_str)
        values = [dq or sq for dq, sq in values]
        if values:
            add(field_name, values, False)

    # Pattern: field in $named_list — the list content isn't in the
    # rule, but the FIELD reference is real.
    for field_name in re.findall(r'([\w.]+)\s+in\s+\$[\w]+', resolved, re.IGNORECASE):
        field_name = field_name.lstrip(".")
        if _mql_valid_field(field_name) and field_name not in result.fields_used:
            result.fields_used.append(field_name)

    # Pattern: strings./regex. predicate functions — first arg is the
    # field, second the value/pattern. A transform wrapped around the
    # field (`strings.replace_confusables(sender.display_name)`,
    # `strings.to_lower(x)`) is unwrapped: the FIELD is the observable,
    # not the helper name.
    for wrapper, field_name, dq, sq in re.findall(
        r'(?:strings|regex)\.\w+\s*\(\s*(?:((?:strings|regex)\.\w+)\s*\(\s*)?([\w.]+)\s*\)?\s*,\s*'
        r'(?:"([^"]*)"|\'([^\']*)\')',
        resolved, re.IGNORECASE
    ):
        add(field_name, [dq or sq], False)

    # Unquoted comparisons (== true / >= 4 / != null): the field
    # reference is real even though the value isn't an observable.
    for field_name in re.findall(
        r'([\w.]+)\s*(?:[=!]=|<=?|>=?)\s*(?:true|false|null|\d+)\b',
        resolved, re.IGNORECASE
    ):
        field_name = field_name.lstrip(".")
        if _mql_valid_field(field_name) and field_name not in result.fields_used:
            result.fields_used.append(field_name)

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
        # Whitespace-bearing values are regex/pattern bodies or link
        # display text, not indicators (same policy as
        # _route_domain_fields).
        result.network_indicators.extend(
            v for v in values if v and not re.search(r"\s", v)
        )

    # Route domain-specific fields
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


# ===========================================================================
# PANTHER PYTHON EXTRACTOR (AST)
# ===========================================================================
#
# Panther detections are Python modules (`def rule(event): ...`), so
# regex extraction is hopeless — but the field-access idioms are few
# and structured: `event.get("field")`, `event["field"]`,
# `event.deep_get("a", "b")`, `deep_get(event, "a", "b")`,
# `event.udm("x")`, chained `.get("a", {}).get("b")`. An ast walk
# collects those paths, the comparison terms around them (==, in,
# startswith/endswith, against literals or module-level constant
# collections), and routes them through the same classification used
# by every other source. Serves both `panther` (panther-analysis) and
# the pypanther source (issue #27) — same idioms.

_PANTHER_GETTERS = frozenset({"get", "deep_get", "deep_walk", "udm"})


def _panther_field_path(
    node: ast.AST, var_fields: Optional[dict] = None
) -> Optional[str]:
    """Dotted field path if `node` is an event field access, else None.

    `var_fields` maps local variable names to previously-resolved
    field paths (`a = event.get("x")` ... `a == "y"`).
    """
    if isinstance(node, ast.Name):
        return (var_fields or {}).get(node.id)
    # event["field"]
    if isinstance(node, ast.Subscript):
        base = _panther_base_path(node.value, var_fields)
        if base is None:
            return None
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return f"{base}.{key.value}" if base else key.value
        return None
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    # event.get("A").lower() == "public" -- the method does not change
    # which field is being tested.
    if (
        isinstance(func, ast.Attribute)
        and func.attr in ("lower", "upper", "strip", "casefold", "lstrip", "rstrip")
        and not node.args
    ):
        return _panther_field_path(func.value, var_fields)
    # deep_get(event, "a", "b") / deep_walk(event, "a", "b")
    if isinstance(func, ast.Name) and func.id in ("deep_get", "deep_walk"):
        if node.args and _panther_base_path(node.args[0], var_fields) is not None:
            parts = [
                a.value for a in node.args[1:]
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
            return ".".join(parts) if parts else None
        return None
    # event.get("a") / event.deep_get("a", "b") / event.udm("x"),
    # incl. chained .get("a", {}).get("b")
    if isinstance(func, ast.Attribute) and func.attr in _PANTHER_GETTERS:
        base = _panther_base_path(func.value, var_fields)
        if base is None:
            return None
        # .get()/.udm() take ONE key (further args are defaults);
        # .deep_get()/.deep_walk() take a path of keys.
        key_args = node.args[:1] if func.attr in ("get", "udm") else node.args
        parts = [
            a.value for a in key_args
            if isinstance(a, ast.Constant) and isinstance(a.value, str)
            and not _PANTHER_PLACEHOLDER_RE.match(a.value)  # a default, not a key
        ]
        if not parts:
            return None
        prefix = f"{base}." if base else ""
        return prefix + ".".join(parts)
    return None


def _panther_base_path(
    node: ast.AST, var_fields: Optional[dict] = None
) -> Optional[str]:
    """'' for the event object itself, a dotted path for a chained
    field access, None for anything else."""
    if isinstance(node, ast.Name) and node.id == "event":
        return ""
    return _panther_field_path(node, var_fields)


def _panther_literals(node: ast.AST, constants: dict) -> list[str]:
    """String/int literals of a value expression, resolving
    module-level constant collections by name."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return [str(node.value)]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out = []
        for el in node.elts:
            out.extend(_panther_literals(el, constants))
        return out
    if isinstance(node, ast.Name):
        return list(constants.get(node.id, []))
    # self.CONST -- class-level collections on pypanther Rule classes.
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
        return list(constants.get(node.attr, []))
    return []


_PANTHER_PLACEHOLDER_RE = re.compile(r"^(?:<[^>]+>|\{[^}]+\})$")


class _PantherVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.constants: dict[str, list[str]] = {}
        self.var_fields: dict[str, str] = {}
        self.terms: list[tuple[str, list[str], bool]] = []
        self.fields: list[str] = []
        self.branchiness = 0

    def _path(self, node: ast.AST) -> Optional[str]:
        return _panther_field_path(node, self.var_fields)

    def visit_Assign(self, node: ast.Assign) -> None:
        # NAME = ("a", "b") / [...] / {...} of literals — value lists
        # referenced by comparisons later.
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            if isinstance(node.value, (ast.Tuple, ast.List, ast.Set)):
                vals = _panther_literals(node.value, self.constants)
                if vals:
                    self.constants[target] = vals
            else:
                # a = event.get("x") — later `a == "y"` resolves to x.
                path = self._path(node.value)
                if path:
                    self.var_fields[target] = path
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        op = node.ops[0]
        comp = node.comparators[0]
        left_path = self._path(node.left)
        if left_path:
            values = _panther_literals(comp, self.constants)
            negated = isinstance(op, (ast.NotEq, ast.NotIn))
            if isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) and values:
                self.terms.append((left_path, values, negated))
            else:
                self.fields.append(left_path)
        else:
            right_path = self._path(comp)
            if right_path:
                # "literal" in event.get("command")
                values = _panther_literals(node.left, self.constants)
                if isinstance(op, (ast.In, ast.NotIn)) and values:
                    self.terms.append(
                        (right_path, values, isinstance(op, ast.NotIn))
                    )
                else:
                    self.fields.append(right_path)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # event.get("x").startswith("prefix") — method terms
        if isinstance(func, ast.Attribute) and func.attr in (
            "startswith", "endswith",
        ):
            path = self._path(func.value)
            if path and node.args:
                values = _panther_literals(node.args[0], self.constants)
                if values:
                    self.terms.append((path, values, False))
                else:
                    self.fields.append(path)
        path = self._path(node)
        if path:
            self.fields.append(path)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        path = self._path(node)
        if path:
            self.fields.append(path)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.branchiness += 1
        # Guard clause: `if event.get(X) != "v": return False` means the
        # rule REQUIRES X == v. The terms inside the test are recorded
        # with their negation flipped (2026-08-30 review: 9/28 Panther
        # rules had their only action recorded negated, so api_actions
        # was empty).
        if _panther_is_reject_guard(node):
            before = len(self.terms)
            self.visit(node.test)
            self.terms[before:] = [(f, v, not neg) for f, v, neg in self.terms[before:]]
            for stmt in node.body + node.orelse:
                self.visit(stmt)
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # pypanther: `class R(Rule): EVENTS = ["a", "b"]` -- referenced
        # later as self.EVENTS.
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                if isinstance(stmt.value, (ast.Tuple, ast.List, ast.Set)):
                    vals = _panther_literals(stmt.value, self.constants)
                    if vals:
                        self.constants[stmt.targets[0].id] = vals
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                if isinstance(stmt.value, (ast.Tuple, ast.List, ast.Set)):
                    vals = _panther_literals(stmt.value, self.constants)
                    if vals:
                        self.constants[stmt.target.id] = vals
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.branchiness += len(node.values) - 1
        self.generic_visit(node)


def _panther_is_reject_guard(node: ast.If) -> bool:
    """`if <test>: return False` / `continue` with no else -- the test
    describes what the rule does NOT match."""
    if node.orelse or len(node.body) != 1:
        return False
    stmt = node.body[0]
    if isinstance(stmt, ast.Continue):
        return True
    return (
        isinstance(stmt, ast.Return)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is False
    )


# Panther log schemas reuse generic key names for the audited action;
# the Splunk-CIM defaults (`action` = firewall verdict) are wrong here.
_PANTHER_FIELD_MAP: dict[str, tuple[str, str]] = {
    "action": ("cloud", "api_action"),            # Slack / Wiz / GitHub audit
    "name": ("cloud", "api_action"),              # GSuite reports event name
    "event": ("event", "event_action"),           # Teleport (promoted when namespaced)
    "event_type": ("event", "event_action"),
    "p_log_type": ("cloud", "event_source"),
}


def _add_panther_observable(
    field_name: str, values: list[str], negated: bool, result: ExtractedFields
) -> None:
    result.fields_used.append(field_name)
    # `<UNKNOWN REASON>` / `{tenant}`: getter defaults and template
    # placeholders, not values anyone can search.
    values = [v for v in values if v and not _PANTHER_PLACEHOLDER_RE.match(str(v))]
    obs_type, obs_subtype = _PANTHER_FIELD_MAP.get(field_name.lower()) or _classify_field(field_name)
    if values:
        result.observables.append(
            ExtractedObservable(
                field=field_name,
                values=values,
                type=obs_type,
                subtype=obs_subtype,
                negated=negated,
            )
        )
    if field_name.lower() in ("eventid", "eventcode", "event_id"):
        result.event_ids.extend(v for v in values if v.isdigit())
    if negated:
        _route_domain_fields(obs_type, obs_subtype, values, negated, result)
        return
    if obs_type == "process" and obs_subtype in ("process_name", "parent_process_name"):
        result.process_names.extend(_extract_exe_names(values))
    if obs_type == "file" and "path" in obs_subtype:
        result.file_paths.extend(v for v in values if ("\\" in v or "/" in v))
    if obs_type == "registry":
        result.registry_keys.extend(_extract_registry_paths(values))
    if obs_type == "network":
        result.network_indicators.extend(
            v for v in values if v and not re.search(r"\s", v)
        )
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


def extract_panther_fields(
    source: str, log_types: Optional[list[str]] = None
) -> ExtractedFields:
    """Extract fields from a Panther Python detection module.

    Args:
        source: The Python source of the rule module.
        log_types: The YAML `LogTypes` — Panther's source-table
            equivalent, surfaced as extracted_source_tables.

    Returns:
        ExtractedFields with extracted observables.
    """
    result = ExtractedFields()
    for lt in log_types or []:
        if isinstance(lt, str) and lt.strip():
            result.source_tables.append(lt.strip())
    if not source or not isinstance(source, str):
        return result

    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Correlation/declarative rules store serialized YAML here —
        # not Python, nothing to extract.
        return result

    visitor = _PantherVisitor()
    visitor.visit(tree)

    if visitor.branchiness > 8:
        result.query_complexity = "complex"
    elif visitor.branchiness > 3:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    seen_terms: set[tuple[str, tuple[str, ...], bool]] = set()
    for field_name, values, negated in visitor.terms:
        key = (field_name, tuple(values), negated)
        if key in seen_terms:
            continue
        seen_terms.add(key)
        _add_panther_observable(field_name, values, negated, result)
    for field_name in visitor.fields:
        if field_name and field_name not in result.fields_used:
            result.fields_used.append(field_name)

    _deduplicate_all(result)
    return result
