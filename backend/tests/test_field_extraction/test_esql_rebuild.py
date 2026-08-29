"""ES|QL rebuild fixture (issue #6 tail): the junk classes the
2026-08-28 corpus tally measured -- 251 EVAL aliases in fields_used,
shredded BY clauses, osquery SQL segments parsed as ES|QL -- plus the
recall traps found while verifying (EVAL-only source fields, INLINE
STATS)."""

from app.services.field_extractor import extract_esql_fields

DNS_REBIND = '''
from logs-network_traffic.dns-*, logs-zeek.dns-*
| where
    event.dataset == "dns" and
    dns.question.name is not null and
    TO_UPPER(dns.response_code) == "NOERROR"
| eval
    Esql.client_ip = COALESCE(client.ip, source.ip),
    Esql.dataset = COALESCE(data_stream.dataset, event.dataset)
| where Esql.client_ip is not null
| mv_expand dns.resolved_ip
| stats Esql.agent_id_count_distinct = count_distinct(agent.id), Esql.n = count()
    by DATE_TRUNC(5 minutes, @timestamp), dns.question.registered_domain
| keep @timestamp, dns.question.registered_domain, Esql.client_ip
| sort Esql.n desc
'''

HUNTING_MIXED = '''
from logs-endpoint.events.process-*
| where process.name == "powershell.exe" and process.args_count > 3
| keep @timestamp, process.name, host.name

---

SELECT f.path, f.mtime, u.username AS file_owner
FROM file f JOIN users u USING (uid)
ORDER BY f.mtime DESC;
'''

SIP_EVAL_ONLY = '''
from logs-network_traffic.sip-*, packetbeat-* metadata _source
| eval
    Esql.method = TO_UPPER(COALESCE(
        JSON_EXTRACT(_source, "network_traffic.sip.cseq.method"),
        JSON_EXTRACT(_source, "sip.cseq.method")
    )),
    Esql.client_mac = COALESCE(network_traffic.dhcpv4.client_mac, dhcpv4.client_mac)
| where Esql.method == "REGISTER"
| INLINE STATS Esql.host_count = COUNT_DISTINCT(host.name) BY Esql.method
| stats Esql.n = count() by Esql.method
'''


def test_eval_and_stats_aliases_are_derived_not_fields():
    r = extract_esql_fields(DNS_REBIND)
    assert not any(f.startswith("Esql.") for f in r.fields_used)
    assert "dns.question.name" in r.fields_used
    assert "dns.resolved_ip" in r.fields_used
    assert "dns.question.registered_domain" in r.fields_used


def test_eval_right_hand_sides_are_source_fields():
    r = extract_esql_fields(DNS_REBIND)
    assert "client.ip" in r.fields_used
    assert "source.ip" in r.fields_used


def test_by_clause_unwraps_functions_and_drops_units():
    r = extract_esql_fields(DNS_REBIND)
    assert "@timestamp" in r.fields_used
    assert "@timestamp)" not in r.fields_used
    assert "minutes" not in r.fields_used
    assert not any("(" in f or ")" in f for f in r.fields_used)


def test_stats_aggregation_args_are_fields():
    r = extract_esql_fields(DNS_REBIND)
    assert "agent.id" in r.fields_used


def test_where_terms_still_produce_observables():
    r = extract_esql_fields(DNS_REBIND)
    obs = [o for o in r.observables if o.field == "event.dataset"]
    assert obs and obs[0].values == ["dns"]
    assert "logs-network_traffic.dns-*" in r.source_tables


def test_osquery_sql_segment_is_ignored():
    r = extract_esql_fields(HUNTING_MIXED)
    assert "powershell.exe" in r.process_names
    assert "host.name" in r.fields_used
    assert not any(";" in f or " " in f for f in r.fields_used)
    assert "f.path" not in r.fields_used
    assert "file_owner" not in r.fields_used


def test_eval_only_rules_keep_coverage_via_json_extract_and_inline_stats():
    # The 9 rules that lost coverage in the first cut: every source field
    # sits inside EVAL right-hand sides; later stages only touch aliases.
    r = extract_esql_fields(SIP_EVAL_ONLY)
    assert "network_traffic.sip.cseq.method" in r.fields_used
    assert "sip.cseq.method" in r.fields_used
    assert "dhcpv4.client_mac" in r.fields_used
    assert "host.name" in r.fields_used  # INLINE STATS arg
    assert not any(f.startswith("Esql.") for f in r.fields_used)
    assert "logs-network_traffic.sip-*" in r.source_tables
