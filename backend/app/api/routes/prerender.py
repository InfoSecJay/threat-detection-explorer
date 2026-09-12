"""Bot-facing prerendered pages (#76 / teardown F01+F02).

The SPA serves an identical shell for every route, so crawlers and
link unfurlers (Slack, LinkedIn, Discord, Google) see nothing. Vercel
rewrites route requests whose User-Agent matches known bots to these
endpoints, which return small server-rendered HTML documents with full
Open Graph / Twitter Card / canonical metadata and the page's actual
content. Humans keep getting the SPA.

Kept deliberately simple: no styling beyond honest content -- the
audience is a parser, and readable HTML is also the correct fallback
for a human who somehow lands here (every page links its canonical
URL).
"""

from __future__ import annotations

import json
from html import escape

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.mitre import mitre_service

router = APIRouter(prefix="/prerender", tags=["prerender"])

SITE = "Detection Explorer"
ORIGIN = "https://detectionexplorer.io"


def _jsonld(data: dict | None) -> str:
    """schema.org JSON-LD block (DX-18). `</` is escaped so rule text
    can never close the script element early."""
    if not data:
        return ""
    payload = json.dumps({"@context": "https://schema.org", **data}, ensure_ascii=False)
    return f'<script type="application/ld+json">{payload.replace("</", "<\\/")}</script>\n'


def _page(
    title: str,
    description: str,
    canonical_path: str,
    image_path: str,
    body: str,
    og_type: str = "article",
    jsonld: dict | None = None,
) -> HTMLResponse:
    t = escape(f"{title} · {SITE}" if title != SITE else SITE)
    d = escape((description or "").strip().replace("\n", " ")[:300])
    canonical = f"{ORIGIN}{canonical_path}"
    image = f"{ORIGIN}{image_path}"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{t}</title>
<meta name="description" content="{d}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{t}">
<meta property="og:description" content="{d}">
<meta property="og:url" content="{canonical}">
<meta property="og:type" content="{og_type}">
<meta property="og:site_name" content="{SITE}">
<meta property="og:image" content="{image}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
<meta name="twitter:image" content="{image}">
{_jsonld(jsonld)}</head>
<body>
{body}
<p><a href="{canonical}">Open in {escape(SITE)}</a></p>
</body>
</html>"""
    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "public, s-maxage=3600, stale-while-revalidate=86400"},
    )


def _kv(label: str, value: str) -> str:
    return f"<li><strong>{escape(label)}:</strong> {escape(value)}</li>"


@router.get("/detection/{detection_id}", response_class=HTMLResponse)
async def prerender_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    from app.services.detection_resolver import resolve_detection

    d, _via_alias = await resolve_detection(db, detection_id)
    if d is None:
        from app.services.tombstones import get_tombstone

        tomb = await get_tombstone(db, detection_id)
        if tomb is not None:
            succ = "".join(
                f'<li><a href="{ORIGIN}/detections/{escape(x["id"])}">{escape(x["title"])}</a> ({escape(x["source"])})</li>'
                for x in tomb["successors"]
            )
            body = f"""<h1>{escape(tomb["title"])} (removed upstream)</h1>
<p>Tracked from {escape((tomb.get("first_seen_at") or "?")[:10])} until {escape((tomb.get("removed_at") or "?")[:10])},
when it was removed from the {escape(tomb["source"])} repository.</p>
{f"<p>Current rules covering the same technique:</p><ul>{succ}</ul>" if succ else ""}"""
            return _page(
                f"{tomb['title']} (removed)",
                f"This {tomb['source']} rule was removed upstream on {(tomb.get('removed_at') or '')[:10]}.",
                f"/detections/{tomb['id']}",
                "/api/og/site.png",
                body,
            )
        return HTMLResponse(status_code=404, content="<h1>Rule not found</h1>")
    techniques = [t for t in (d.mitre_techniques or []) if isinstance(t, str)]
    tech_html = " ".join(
        f'<a href="{ORIGIN}/mitre/{escape(t)}">{escape(t)}</a>' for t in techniques[:10]
    )
    facts = "".join([
        _kv("Source", d.source),
        _kv("Language", d.language or ""),
        _kv("Severity", d.severity or ""),
        _kv("Status", d.status or ""),
    ])
    query = escape((d.detection_logic or "")[:4000])
    # DX-16: the prerequisites are indexable text, not just a raw-view field.
    notes = (getattr(d, "deploy_notes", None) or "").strip()
    deploy_html = f"<h2>Before you deploy</h2><p>{escape(notes[:1500])}</p>" if notes and notes != "[]" else ""
    body = f"""<h1>{escape(d.title)}</h1>
<p>{escape((d.description or "")[:1200])}</p>
<ul>{facts}</ul>
<p>ATT&amp;CK: {tech_html or "unmapped"}</p>
{deploy_html}
<h2>Detection logic</h2>
<pre>{query}</pre>"""
    desc = d.description or f"{d.source} detection rule"
    # JSON-LD (DX-18): license, dates and the upstream file, so a rule
    # page is citable as a document, not just a URL.
    from app.api.routes.methodology import LICENSES

    lic = LICENSES.get(d.source) or {}
    created = d.rule_created_date.date().isoformat() if d.rule_created_date else None
    modified = d.rule_modified_date.date().isoformat() if d.rule_modified_date else None
    jsonld = {
        "@type": "TechArticle",
        "headline": d.title,
        "description": (desc or "")[:300],
        "url": f"{ORIGIN}/detections/{d.id}",
        "isBasedOn": d.source_rule_url or None,
        "license": lic.get("url"),
        "dateCreated": created,
        "dateModified": modified or created,
        "keywords": techniques[:10],
        "publisher": {"@type": "Organization", "name": SITE, "url": ORIGIN},
        "sourceOrganization": {"@type": "Organization", "name": d.source},
    }
    jsonld = {k: v for k, v in jsonld.items() if v not in (None, [], "")}
    return _page(d.title, desc, f"/detections/{d.id}", f"/api/og/detection/{d.id}.png", body, jsonld=jsonld)


@router.get("/technique/{technique_id}", response_class=HTMLResponse)
async def prerender_technique(technique_id: str):
    await mitre_service.ensure_loaded()
    tid = technique_id.upper()
    info = mitre_service.get_technique(tid)
    if not info:
        return HTMLResponse(status_code=404, content="<h1>Technique not found</h1>")
    name = info.get("name", tid)
    desc = (info.get("description") or "").strip()
    body = f"""<h1>{escape(tid)} — {escape(name)}</h1>
<p>{escape(desc[:1200])}</p>
<p>Cross-vendor detection rules for this ATT&amp;CK technique, normalized from thirteen open-source repositories.</p>"""
    return _page(
        f"{tid} {name}",
        desc or f"Detection rules for ATT&CK technique {tid}",
        f"/mitre/{tid}",
        f"/api/og/technique/{tid}.png",
        body,
    )


@router.get("/actor/{actor_id}", response_class=HTMLResponse)
async def prerender_actor(actor_id: str):
    await mitre_service.ensure_loaded()
    aid = actor_id.upper()
    info = mitre_service.get_all_groups().get(aid) or mitre_service.get_all_software().get(aid)
    if not info:
        return HTMLResponse(status_code=404, content="<h1>Actor not found</h1>")
    name = info.get("name", aid)
    aliases = ", ".join(info.get("aliases", [])[:8])
    desc = (info.get("description") or "").strip()
    body = f"""<h1>{escape(name)} ({escape(aid)})</h1>
{f"<p><strong>Aliases:</strong> {escape(aliases)}</p>" if aliases else ""}
<p>{escape(desc[:1200])}</p>
<p>Which of this adversary's ATT&amp;CK techniques have public detection rules -- and which have none.</p>"""
    return _page(
        f"{name} ({aid})",
        desc or f"Detection coverage for {name}",
        f"/actors/{aid}",
        f"/api/og/actor/{aid}.png",
        body,
        og_type="profile",
    )


@router.get("/home", response_class=HTMLResponse)
async def prerender_home(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(Detection))).scalar() or 0
    desc = (
        f"{total:,} open-source detection rules from thirteen repositories -- Sigma, Elastic, Splunk, "
        "Sentinel, Panther, Sublime and more -- normalized into one schema, mapped to MITRE ATT&CK, "
        "with the observables each rule keys on."
    )
    body = f"""<h1>{escape(SITE)}</h1>
<p>{escape(desc)}</p>
<ul>
<li><a href="{ORIGIN}/detections">Search {total:,} detection rules</a></li>
<li><a href="{ORIGIN}/mitre">MITRE ATT&amp;CK coverage</a></li>
<li><a href="{ORIGIN}/actors">Threat actor gap analysis</a></li>
<li><a href="{ORIGIN}/observables">Observables: processes, event IDs, domains rules key on</a></li>
<li><a href="{ORIGIN}/digest">Weekly digest of new and updated rules</a></li>
</ul>"""
    return _page(SITE, desc, "/", "/api/og/site.png", body, og_type="website")


@router.get("/corpus-health", response_class=HTMLResponse)
async def prerender_corpus_health(db: AsyncSession = Depends(get_db)):
    """The corpus-health report (#124) as honest HTML, so the numbers are
    indexable and citable without running the app."""
    from app.services.corpus_cache import corpus_cache
    from app.services.corpus_health import build_report

    r = await corpus_cache.get(db, ("methodology", "corpus-health"), lambda: build_report(db))
    as_of = (r["corpus"]["updated_at"] or "")[:10] or "latest sync"
    fields = r["fields"]
    meta = r["field_meta"]
    totals = "".join(
        f"<li><strong>{escape(meta[f]['label'])}:</strong> {r['applicable'][f]['pct']:.1f}% "
        f"({r['applicable'][f]['count']:,} of {r['applicable'][f]['of']:,} rules whose format has the field)</li>"
        for f in fields
    )
    head = "".join(f"<th>{escape(meta[f]['label'])}</th>" for f in fields)
    rows = "".join(
        "<tr><td>" + escape(s_["source"]) + f"</td><td>{s_['total_rules']:,}</td>"
        + "".join(
            "<td>n/a</td>" if f in s_["not_applicable"] else f"<td>{s_['pct'][f]:.1f}% ({s_['fields'][f]:,})</td>"
            for f in fields
        )
        + "</tr>"
        for s_ in r["sources"]
    )
    defs = "".join(f"<dt>{escape(meta[f]['label'])}</dt><dd>{escape(meta[f]['definition'])}</dd>" for f in fields)
    a = r["applicable"]
    desc = (
        f"Of {r['total_rules']:,} open-source detection rules, {a['no_attack']['pct']:.0f}% carry no "
        f"ATT&CK mapping; where the format has the field, {a['no_references']['pct']:.0f}% cite no references and "
        f"{a['no_false_positives']['pct']:.0f}% document no false positives. Per source, as of {as_of}, with CSV."
    )
    body = f"""<h1>Corpus health</h1>
<p>{escape(desc)}</p>
<ul>{totals}</ul>
<table><thead><tr><th>Source</th><th>Rules</th>{head}</tr></thead><tbody>{rows}</tbody></table>
<p><a href="{ORIGIN}/api/v1/methodology/corpus-health.csv">Download the data (CSV)</a></p>
<h2>How each number is counted</h2>
<dl>{defs}</dl>
<p>n/a marks a field the rule format cannot express; headline percentages count only rules whose format has the field.</p>
<p>Cite as: Detection Explorer, Corpus health as of {escape(as_of)}, {ORIGIN}/methodology/corpus-health</p>"""
    return _page("Corpus health", desc, "/methodology/corpus-health", "/api/og/site.png", body)


# ── DX-18: pages that had no bot-facing render at all ───────────────────


@router.get("/methodology", response_class=HTMLResponse)
async def prerender_methodology(db: AsyncSession = Depends(get_db)):
    """The trust anchor -- per-source repo, branch, pinned commit, license
    and scope note -- as indexable HTML."""
    from app.api.routes.methodology import LICENSES, SCOPE_NOTES
    from app.models.repository import Repository
    from app.services.repository_sync import ALL_REPOSITORY_NAMES, RepositorySyncService
    from app.services.upstream_refs import branch_for

    repos = {r.name: r for r in (await db.execute(select(Repository))).scalars().all()}
    rows = []
    for name in ALL_REPOSITORY_NAMES:
        repo = repos.get(name)
        url = (RepositorySyncService.REPO_CONFIGS.get(name) or {}).get("url") or ""
        lic = LICENSES.get(name) or {}
        sha = (repo.last_commit_hash or "")[:7] if repo else ""
        rows.append(
            "<tr>"
            f"<td>{escape(name)}</td>"
            f'<td><a href="{escape(url)}">{escape(url)}</a></td>'
            f"<td>{escape(branch_for(name))}</td>"
            f"<td><code>{escape(sha)}</code></td>"
            f"<td>{repo.rule_count if repo else 0:,}</td>"
            f"<td>{escape(lic.get('name', ''))}</td>"
            f"<td>{escape(SCOPE_NOTES.get(name, ''))}</td>"
            "</tr>"
        )
    desc = (
        "How Detection Explorer counts rules: for each of the thirteen upstream repositories, the "
        "branch and pinned commit, the discovery scope, the license, and the decisions that move the number."
    )
    body = f"""<h1>Methodology</h1>
<p>{escape(desc)}</p>
<table><thead><tr><th>Source</th><th>Repository</th><th>Branch</th><th>Pinned commit</th><th>Rules</th><th>License</th><th>Scope</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p>Rule counts differ between aggregator sites because every site makes different scope choices. This table is read from the same configuration the ingester uses, so it cannot drift from the code.</p>
<p><a href="{ORIGIN}/methodology/corpus-health">Corpus health report</a> · <a href="{ORIGIN}/methodology/unclassified">Unclassified burn-down</a></p>"""
    return _page("Methodology", desc, "/methodology", "/api/og/site.png", body)


@router.get("/query", response_class=HTMLResponse)
async def prerender_query():
    """The search syntax and full field registry."""
    from app.services.query_parser import field_reference

    fields = field_reference()
    rows = "".join(
        "<tr>"
        f"<td><code>{escape(', '.join(f.get('aliases') or []))}</code></td>"
        f"<td>{escape(f.get('kind', ''))}</td>"
        f"<td>{escape(f.get('description', ''))}</td>"
        f"<td><code>{escape(' · '.join(f.get('examples') or []))}</code></td>"
        "</tr>"
        for f in fields
    )
    desc = (
        f"Lucene-style search across the catalog: {len(fields)} queryable fields with AND / OR / NOT, "
        "quoted phrases, ranges and wildcards, plus worked examples."
    )
    body = f"""<h1>Query syntax</h1>
<p>{escape(desc)}</p>
<p>Examples: <code>actor:APT29 AND severity:high</code> · <code>tech:T1059 NOT platform:linux</code> · <code>software:"Cobalt Strike" AND source:splunk</code></p>
<table><thead><tr><th>Field</th><th>Kind</th><th>Description</th><th>Examples</th></tr></thead><tbody>{rows}</tbody></table>"""
    return _page("Query syntax", desc, "/query", "/api/og/site.png", body)


def _digest_page(payload: dict, canonical_path: str) -> HTMLResponse:
    period = payload.get("period") or {}
    summary = payload.get("summary") or {}
    week = period.get("week")
    start, end = (period.get("start") or "")[:10], (period.get("end") or "")[:10]
    title = f"Digest {week}" if week else f"Digest, last {period.get('days', 7)} days"

    def rule_list(items: list[dict], cap: int = 40) -> str:
        return "".join(
            f'<li><a href="{ORIGIN}/detections/{escape(str(r.get("id", "")))}">{escape(str(r.get("title", "")))}</a>'
            f' <small>({escape(str(r.get("source", "")))}, {escape(str(r.get("severity", "")))})</small></li>'
            for r in items[:cap]
        )

    themes = "".join(
        f'<li><a href="{ORIGIN}/mitre/{escape(t["technique_id"])}">{escape(t["technique_id"])} {escape(t.get("technique_name", ""))}</a>: '
        f'{t.get("rules", 0)} new rule{"s" if t.get("rules", 0) != 1 else ""} across {escape(", ".join((t.get("sources") or {}).keys()))}</li>'
        for t in (payload.get("themes") or [])[:8]
    )
    new_rules = payload.get("new_rules") or []
    modified = payload.get("modified_rules") or []
    desc = (
        f"{summary.get('created', 0):,} new and {summary.get('modified', 0):,} updated detection rules "
        f"across the tracked repositories between {start} and {end}, grouped by ATT&CK technique."
    )
    body = f"""<h1>{escape(title)}</h1>
<p>{escape(desc)}</p>
{f"<h2>Themes</h2><ul>{themes}</ul>" if themes else ""}
<h2>New rules ({len(new_rules):,})</h2><ul>{rule_list(new_rules)}</ul>
<h2>Updated rules ({len(modified):,})</h2><ul>{rule_list(modified)}</ul>
<p>Feeds: <a href="{ORIGIN}/api/digest/feed.xml">new rules (RSS)</a> · <a href="{ORIGIN}/api/digest/modified.xml">updated rules (RSS)</a></p>"""
    return _page(title, desc, canonical_path, "/api/og/site.png", body)


@router.get("/digest", response_class=HTMLResponse)
async def prerender_digest(db: AsyncSession = Depends(get_db)):
    from app.services.digest import compute_digest

    payload = await compute_digest(db, days=7, limit=15, rules_limit=300)
    return _digest_page(payload, "/digest")


@router.get("/digest/{week}", response_class=HTMLResponse)
async def prerender_digest_week(week: str, db: AsyncSession = Depends(get_db)):
    from app.services.digest import compute_digest

    try:
        payload = await compute_digest(db, limit=15, rules_limit=300, week=week)
    except ValueError:
        return HTMLResponse(status_code=404, content="<h1>Digest week not found</h1>")
    return _digest_page(payload, f"/digest/{escape(week)}")


@router.get("/observables/{kind}", response_class=HTMLResponse)
async def prerender_observables(kind: str, db: AsyncSession = Depends(get_db)):
    from app.services.observables import OBSERVABLE_TYPES, top_values

    k = kind.lower()
    if k not in OBSERVABLE_TYPES:
        return HTMLResponse(status_code=404, content="<h1>Observable type not found</h1>")
    label = OBSERVABLE_TYPES[k][2]
    top = await top_values(db, k, limit=50)
    rows = "".join(
        "<tr>"
        f'<td><a href="{ORIGIN}/observables/{escape(k)}/{escape(str(v.get("value", "")))}"><code>{escape(str(v.get("value", "")))}</code></a></td>'
        f"<td>{v.get('rules', 0):,}</td>"
        f"<td>{escape(', '.join(v.get('sources') or []))}</td>"
        "</tr>"
        for v in top.get("values") or []
    )
    desc = (
        f"The {top.get('distinct', 0):,} distinct {label.lower()} values that open-source detection rules key on, "
        "ranked by how many rules reference each, with the sources that do."
    )
    body = f"""<h1>{escape(label)} observables</h1>
<p>{escape(desc)}</p>
<table><thead><tr><th>Value</th><th>Rules</th><th>Sources</th></tr></thead><tbody>{rows}</tbody></table>"""
    return _page(f"{label} observables", desc, f"/observables/{k}", "/api/og/site.png", body)
