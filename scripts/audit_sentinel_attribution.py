#!/usr/bin/env python
"""Sentinel attribution audit (#141) -- is each Sentinel rule attributed
to the vendor its query names?

Runs the real parser, taxonomy resolver and platform split over every
analytic-rule YAML in the local Azure-Sentinel clone
(backend/data/repos/sentinel) and reports the attribution failure
modes the 2026-09-10 review found:

  - rules carrying two or more of the firewall sources (cisco_firewall,
    fortinet_firewall, palo_alto_firewall) although the query names a
    different DeviceVendor, or none, and the rule does not declare three
    or more connectors (a declared multi-source ASIM rule is by design);
  - rules with three or more data sources (a rule reads one or two
    tables; more means a tier unioned something);
  - KQL keywords or let-bound names extracted as tables;
  - CommonSecurityLog / SecurityAlert / AzureDiagnostics / Syslog /
    WindowsEvent rules and what they resolve to.

Exit code is 1 when a gate fails, so the script can run as a check:

    cd backend
    venv\\Scripts\\python.exe ..\\scripts\\audit_sentinel_attribution.py

Read-only. Needs the clone; says so and exits 0 when it is absent.
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend"
sys.path.insert(0, str(BACKEND))

from app.parsers.sentinel import SentinelParser  # noqa: E402
from app.services.taxonomy.domains import split_platforms  # noqa: E402
from app.services.taxonomy.vendors import sentinel as vsentinel  # noqa: E402

CLONE = BACKEND / "data" / "repos" / "sentinel"
FIREWALLS = {"cisco_firewall", "fortinet_firewall", "palo_alto_firewall"}
FIREWALL_VENDOR_WORDS = ("cisco", "fortinet", "palo alto", "paloalto")
JUNK_TABLES = {
    "and", "or", "not", "where", "let", "extend", "project", "summarize", "description",
    "firstseen", "extension_id", "algo_md5", "id", "structure", "reference", "firstrec",
}
GENERIC_TABLES = ("commonsecuritylog", "securityalert", "azurediagnostics", "syslog", "windowsevent", "event")

# Gates: the numbers the review measured before the fix were 126 / 255 / 192.
MAX_FIREWALL_SMEAR = 0
MAX_MANY_SOURCES_SHARE = 0.03
MAX_JUNK_TABLES = 0


def load_rules():
    parser = SentinelParser()
    seen: set[str] = set()
    rows = []
    for path in CLONE.rglob("*.yaml"):
        content = path.read_text(encoding="utf-8", errors="replace")
        if "query:" not in content:
            continue
        try:
            if not parser.can_parse(path):
                continue
            rel = path.relative_to(CLONE)
            parsed = parser.parse(rel, content)
        except Exception:
            continue
        if parsed is None:
            continue
        extra = parsed.extra or {}
        key = extra.get("id") or str(rel)
        if key in seen:
            continue
        seen.add(key)
        resolved = vsentinel.resolve(parsed)
        platforms, domains, products = split_platforms(
            list(resolved.get("platforms") or []), list(resolved.get("data_sources") or [])
        )
        rows.append({
            "path": str(rel),
            "tables": [t.lower() for t in extra.get("kql_tables") or []],
            "filters": extra.get("kql_filters") or {},
            "connectors": [
                (c.get("connectorId") or "") for c in (extra.get("requiredDataConnectors") or []) if isinstance(c, dict)
            ],
            "data_sources": sorted(resolved.get("data_sources") or []),
            "platforms": platforms,
            "domains": domains,
            "products": products,
        })
    return rows


def main() -> int:
    if not CLONE.exists():
        print(f"no Sentinel clone at {CLONE}; nothing to audit")
        return 0
    rows = load_rules()
    print(f"Sentinel rules parsed: {len(rows)}")

    failures = 0

    vendor_words = lambda r: " ".join(r["filters"].get("devicevendor", []) + r["filters"].get("deviceproduct", []))  # noqa: E731
    # A rule that matched no table and declares many connectors (the ASIM
    # Network Session Essentials rules) takes its sources from the
    # author's declaration; that is attribution by design, not a smear.
    smear = [
        r for r in rows
        if len(FIREWALLS & set(r["data_sources"])) >= 2
        and not any(w in vendor_words(r) for w in FIREWALL_VENDOR_WORDS)
        and len(r["connectors"]) < 3
    ]
    print(f"\nfirewall smear (2+ firewall sources, query names none of them, fewer than 3 declared connectors): {len(smear)} (gate: <= {MAX_FIREWALL_SMEAR})")
    for r in smear[:8]:
        print("   ", r["path"], r["data_sources"], "connectors=", r["connectors"][:4])
    if len(smear) > MAX_FIREWALL_SMEAR:
        failures += 1

    many = [r for r in rows if len(r["data_sources"]) >= 3]
    share = len(many) / max(len(rows), 1)
    print(f"\nrules with 3+ data sources: {len(many)} ({share:.1%}) (gate: <= {MAX_MANY_SOURCES_SHARE:.0%})")
    print("    top combos:", collections.Counter(tuple(r["data_sources"]) for r in many).most_common(5))
    if share > MAX_MANY_SOURCES_SHARE:
        failures += 1

    junk = [r for r in rows if any(t in JUNK_TABLES for t in r["tables"])]
    print(f"\nrules with a KQL keyword extracted as a table: {len(junk)} (gate: <= {MAX_JUNK_TABLES})")
    for r in junk[:5]:
        print("   ", r["path"], r["tables"])
    if len(junk) > MAX_JUNK_TABLES:
        failures += 1

    for table in GENERIC_TABLES:
        subset = [r for r in rows if table in r["tables"]]
        if not subset:
            continue
        print(f"\n{table}: {len(subset)} rules ->",
              collections.Counter(tuple(r["data_sources"]) for r in subset).most_common(6))

    unknown_domain = [r for r in rows if r["domains"] == ["unknown"]]
    print(f"\ndomains=[unknown]: {len(unknown_domain)}; top tables:",
          collections.Counter(t for r in unknown_domain for t in r["tables"]).most_common(10))
    print(f"platforms=[unknown]: {sum(1 for r in rows if r['platforms'] == ['unknown'])}")

    print("\nRESULT:", "FAIL" if failures else "PASS", f"({failures} gate(s) failed)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
