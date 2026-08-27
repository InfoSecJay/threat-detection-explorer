"""Vendor threat-tag classification (issue #20).

Sentinel rule tags mix bare threat references (``NOBELIUM``,
``Solorigate``, ``DEV-0537``, ``Zinc``) with compliance frameworks,
CVEs, and table names (``NIST 800-53 r5``, ``SigninLogs``). Nothing in
the tag marks which is which, so Threat Pulse / Threat Actors skipped
them all. A tag classifies as a threat reference when any of:

- the merged ATT&CK + MISP-galaxy GROUP alias registry resolves it
  (``actor_context_service.resolve_alias`` — issue #15), e.g.
  NOBELIUM -> G0016, Zinc -> G0032;
- it equals an ATT&CK SOFTWARE name/alias, e.g. Solorigate -> SUNBURST
  (S0559), Qakbot -> S0650, PsExec -> S0029;
- it matches a vendor tracking-code shape (APT##, DEV-####, Storm-####,
  UNC####, FIN##, TA###) the registries haven't caught up with yet
  (Dev-0270 has no public graduation).

Classified tags are returned VERBATIM for `use_cases`, which makes them
story labels: the dedicated tier already treats a vendor label equal to
an actor name/alias as "this rule was built FOR that actor" (issue
#34), so ID resolution, galaxy synonyms, and disjoint-tier bookkeeping
all happen at query time with no new mechanism.

Validation 2026-08-26 over the full Sentinel repo (3,351 rule files,
145 distinct tags): 16 tags classified — NOBELIUM x28, Solorigate x28,
DEV-0537 x13, Dev-0270, Zinc, Qakbot, POLONIUM, VoltTyphoon, Sunburst,
Trickbot, Ryuk, PsExec, Aqua Blizzard, Mercury, AADInternals, Tarrask —
and zero false positives; the 129 unclassified tags are frameworks,
CVEs, table names, and product names.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from app.services.actor_context import actor_context_service, normalize_alias
from app.services.mitre import mitre_service

# Vendor actor-tracking code shapes. `TA(?!0)` keeps Proofpoint's
# TA505/TA4557 while refusing ATT&CK tactic IDs (TA0001..TA0043).
ACTOR_CODE_RE = re.compile(
    r"^(?:APT[ -]?\d{1,3}|DEV[ -]\d{3,4}|Storm[ -]\d{3,4}|UNC\d{3,5}"
    r"|FIN\d{1,2}|TA(?!0)\d{3,4})$",
    re.IGNORECASE,
)

# (catalog fetch stamp, normalized alias -> S-ID) — rebuilt when the
# ATT&CK catalog refreshes, or on first use after it loads.
_sw_index: Optional[tuple] = None


def software_alias_index() -> dict[str, str]:
    """Normalized name/alias -> S-ID over the loaded ATT&CK software
    catalog. Empty (and harmless) when the catalog isn't loaded yet."""
    global _sw_index
    catalog = mitre_service.get_all_software()
    stamp = (mitre_service.get_stats().get("last_fetch"), len(catalog))
    if _sw_index is None or _sw_index[0] != stamp:
        index: dict[str, str] = {}
        for sid, s in catalog.items():
            for name in [s.get("name", ""), *s.get("aliases", [])]:
                key = normalize_alias(name)
                if key:
                    index.setdefault(key, sid)
        _sw_index = (stamp, index)
    return _sw_index[1]


def threat_reference_tags(
    tags: Iterable,
    resolve_group=None,
    software_index: Optional[dict[str, str]] = None,
) -> list[str]:
    """The subset of `tags` that names a threat actor or software,
    verbatim and deduped, order preserved.

    `resolve_group` / `software_index` exist for tests; production
    callers use the live registries. Callers must ensure
    mitre_service and actor_context_service are loaded first — an
    unloaded registry degrades to pattern-only classification rather
    than raising.
    """
    if resolve_group is None:
        resolve_group = actor_context_service.resolve_alias
    if software_index is None:
        software_index = software_alias_index()
    out: list[str] = []
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        t = tag.strip()
        if not t or t in out:
            continue
        if (
            resolve_group(t)
            or normalize_alias(t) in software_index
            or ACTOR_CODE_RE.match(t)
        ):
            out.append(t)
    return out
