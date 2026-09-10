"""cross_platform means agent or sensor telemetry that runs on any OS
(EDR, osquery, application frameworks). Alert streams, threat-intel
feeds and SaaS audit have no OS at all; they take a product value or
nothing and the platform split turns that into not_applicable or
unknown. This scans every mapping file so the misuse cannot creep back
(it had reached 49 entries by 2026-09-10)."""

from __future__ import annotations

from pathlib import Path

import yaml

MAPPINGS = Path(__file__).resolve().parents[2] / "app" / "services" / "taxonomy" / "mappings"

ALERT_STREAMS = {
    "siem_alert", "elastic_siem_alerts", "elastic_ml", "third_party_security_alerts",
    "splunk_internal_logs", "socradar_incidents", "panther_audit",
}
TI_KEY_WORDS = ("threat_intel", "threat intelligence", "threatintel")


def _entries_with_cross_platform(data):
    found = []

    def walk(node, path):
        if isinstance(node, dict):
            platforms = node.get("platforms")
            if isinstance(platforms, list) and "cross_platform" in platforms:
                found.append((".".join(path), list(node.get("data_sources") or [])))
            for key, value in node.items():
                walk(value, path + [str(key)])
        elif isinstance(node, list):
            for value in node:
                walk(value, path)

    walk(data, [])
    return found


def test_cross_platform_never_covers_an_alert_stream_or_ti_feed():
    offenders = []
    for path in sorted(MAPPINGS.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key, sources in _entries_with_cross_platform(data):
            if set(sources) & ALERT_STREAMS:
                offenders.append(f"{path.name}: {key} -> {sources}")
            elif any(word in key.lower() for word in TI_KEY_WORDS):
                offenders.append(f"{path.name}: {key} (threat-intel key)")
    assert offenders == [], "\n".join(offenders)


def test_cross_platform_still_exists_where_it_belongs():
    # A sanity anchor so the gate cannot pass by deleting the value outright.
    sigma = yaml.safe_load((MAPPINGS / "sigma.yaml").read_text(encoding="utf-8"))
    assert any("application_logs" in s for _, s in _entries_with_cross_platform(sigma))
