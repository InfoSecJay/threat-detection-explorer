# Detection Explorer — Remediation Checklist

Derived from the teardown of detectionexplorer.io v1.4.0 (commit `beaec550`), reviewed 2026-08-30.
Finding IDs (`F01`–`F17`) map back to the teardown. Effort is rough solo-dev time.

**Suggested order:** Sprint 0 today → Sprint 1 before you share the link anywhere → Sprint 2 before it gets real traffic → Sprint 3+ for durability and reach.

---

## Sprint 0 — Verify today (½ day)

- [ ] **S0.1 · Confirm whether the mutating API routes are actually unauthenticated.** `F05`
  Check for auth middleware outside the OpenAPI spec on `POST /api/repositories/{name}/sync`, `/api/repositories/sync-all`, `/api/repositories/{name}/ingest`, `/api/repositories/ingest-all`, `POST /api/mitre/refresh`, `POST /api/scheduler/trigger`.
  *Done when:* you have a definitive yes/no, in writing, for each of the six routes.

- [ ] **S0.2 · If unauthenticated: remove them from the public router.** `F05`
  Move sync/ingest/refresh/trigger onto a separate internal router, driven by the scheduler or a GitHub Action with a repo secret. Do not just add a token to a public route — take the route off the internet.
  *Done when:* an unauthenticated POST to each of the six returns 404 or 401 from an outside host.

- [ ] **S0.3 · Gate the Swagger surface.** `F05`
  `docs_url` / `redoc_url` / `openapi_url` for the admin surface behind auth; keep a curated read-only spec public (see S3.1).
  *Done when:* `https://…railway.app/docs` no longer exposes write operations.

- [ ] **S0.4 · Add a `LICENSE` file to `InfoSecJay/threat-detection-explorer`.** `F08`
  Apache-2.0 if you want maximum adoption; AGPL-3.0 if you'd mind a vendor reskinning it.
  *Done when:* the GitHub API reports a non-null `license.spdx_id`.

- [ ] **S0.5 · Refresh the repo metadata.** `F08`
  Description still says five sources (it's thirteen). Add a README with a screenshot, the live URL, an architecture paragraph, and a "how to run it" section. Pin the repo on your profile.
  *Done when:* a stranger landing on the repo understands what it is in ten seconds.

---

## Sprint 1 — Make it shareable (2–3 days)

> Nothing else on this list matters until this sprint ships. Every link you post today is wasted.

- [ ] **S1.1 · Server-render per-page meta tags.** `F01` `F02`
  Prerender at build (or SSR/edge-render) at minimum: `/`, `/detections/:id`, `/mitre/techniques/:id`, `/actors/:id`, `/observables/:kind/:value`. You already compute title + description client-side in `useDocumentMeta` — reuse that logic server-side.
  *Done when:* `curl -s https://detectionexplorer.io/detections/<id> | grep '<title>'` returns the rule's title, not the shell.

- [ ] **S1.2 · Add Open Graph + Twitter card tags to every rendered page.** `F01`
  `og:title`, `og:description`, `og:image`, `og:url`, `og:type`, `og:site_name`, `twitter:card=summary_large_image`, `twitter:title`, `twitter:description`, `twitter:image`, plus `<link rel="canonical">`.
  *Done when:* the URL passes the LinkedIn Post Inspector, the Slack unfurl preview, and `opengraph.xyz`.

- [ ] **S1.3 · Build a dynamic OG image endpoint.** `F01`
  `GET /og/detection/:id.png` → 1200×630 card: rule title, source badge, query language, primary ATT&CK technique, hygiene score, site wordmark, in the terminal palette. Same for technique, actor, and the weekly digest.
  *Done when:* a rule link pasted in Slack renders a readable card at thumbnail size.

- [ ] **S1.4 · Fix the sitemap.** `F03`
  Proxy `/sitemap.xml` to the backend generator at the edge (or emit it to static at build). Split into a sitemap index if it exceeds 50k URLs / 50MB.
  *Done when:* `curl https://detectionexplorer.io/sitemap.xml` returns XML, and Search Console reports it read successfully.

- [ ] **S1.5 · Correct `robots.txt`.** `F03`
  Keep `Disallow: /api/` for the mutating surface but stop it blocking the sitemap and the public docs. Add `Allow: /api/docs`.
  *Done when:* Search Console's robots tester passes for `/sitemap.xml` and `/api/docs`.

- [ ] **S1.6 · Register the property in Google Search Console + Bing Webmaster Tools.** `F02`
  Submit the sitemap. Set a reminder to check the Coverage report in 30 days.
  *Done when:* first crawl data appears.

- [ ] **S1.7 · Add a mobile navigation drawer.** `F04`
  Collapse the eight nav items below 768px. The dense tables can stay horizontally scrollable; the nav cannot.
  *Done when:* every nav destination is reachable at 375px width.

- [ ] **S1.8 · Fix clipped controls at narrow widths.** `F04`
  The `LIMIT` select and the query input on `/detections` run past the viewport edge on mobile.
  *Done when:* no horizontal body scroll at 375px on `/`, `/detections`, `/actors`, `/digest`.

- [ ] **S1.9 · Add privacy-friendly analytics.** *(new)*
  Self-hosted Plausible or Umami — no cookie banner needed. You need to know which rule pages get shared before deciding what to build next.
  *Done when:* you can see top entry pages and referrers for the last 7 days.

---

## Sprint 2 — Survive the traffic (2–3 days)

- [ ] **S2.1 · Put a CDN in front of the backend.** `F06`
  Cloudflare (or Vercel edge functions) proxying `detectionexplorer.io/api/*` → Railway. Same-origin kills the CORS preflight as a bonus.
  *Done when:* the browser never talks to `*.up.railway.app` directly.

- [ ] **S2.2 · Set cache headers on read routes.** `F06`
  `Cache-Control: public, s-maxage=900, stale-while-revalidate=86400` on `/api/detections*`, `/api/mitre*`, `/api/actors*`, `/api/trending*`, `/api/observables*`. Your corpus changes once a day.
  *Done when:* a repeat request to `/api/detections/facets` returns a CDN `HIT`.

- [ ] **S2.3 · Purge cache on sync completion.** `F06`
  Fire a CDN purge at the end of the nightly ingest job so stale data has a bounded lifetime.
  *Done when:* rule counts update within minutes of a sync, without waiting out the TTL.

- [ ] **S2.4 · Precompute facets and filters.** `F06`
  `/api/detections/facets` (1,503 ms) and `/api/detections/filters` (695 ms) are the slowest calls on the critical path and their answers only change nightly. Generate them as static JSON at the end of each ingest.
  *Done when:* both serve in <100 ms from cache.

- [ ] **S2.5 · Profile and index the default list query.** `F06`
  `/api/detections?sort_by=rule_created_date&limit=25` takes 1,278 ms for 25 rows out of 15,579. Something is missing an index or doing a full scan for the count.
  *Done when:* p95 < 300 ms uncached.

- [ ] **S2.6 · Add skeleton loading states.** `F07`
  `/actors` currently paints "— (0 with rules)" for ~1.5 s. Replace zero-states with skeletons everywhere a count or table is pending.
  *Done when:* no page ever displays a real-looking zero it doesn't mean.

- [ ] **S2.7 · Bake headline counts into the prerendered HTML.** `F07`
  Rules, repos, technique coverage, actor/software totals should be correct at first paint.
  *Done when:* the hero and `/actors` header numbers are right before any XHR resolves.

- [ ] **S2.8 · Add rate limiting to the public API.** `F17`
  Per-IP token bucket at the edge, generous for humans (e.g. 60 req/min) and a documented higher tier on request.
  *Done when:* a scraping loop gets 429s with a `Retry-After`.

- [ ] **S2.9 · Self-host and subset the fonts.** *(new)*
  Orbitron, Rajdhani and JetBrains Mono load render-blocking from `fonts.googleapis.com` — a third-party DNS round trip on first paint.
  *Done when:* no third-party font requests, and `font-display: swap` is set.

---

## Sprint 3 — Trust and credibility (3–5 days)

- [ ] **S3.1 · Re-normalize the hygiene score per rule format.** `F09`
  Measured means (n=50 recent per source): Splunk 70 · Elastic 67 · Panther 63 · Sigma 59 · Elastic Protections 59 · PyPanther 53 · Sentinel 49 · LOLRMM 48 · Google SecOps 38 · Sublime 34. That gradient tracks schema similarity, not quality. Score each rule only against dimensions its format and repo conventions can actually express — an MQL email rule should not lose 20 points for absent ATT&CK tags.
  *Done when:* per-source means fall within roughly 15 points of each other, and a spot-check of ten Sublime rules reads as fair.

- [ ] **S3.2 · Rename it and drop the vendor ranking.** `F09`
  "Metadata Completeness", not "Hygiene". Never surface a cross-vendor leaderboard of it. Move the "not a measure of detection accuracy" caveat *above* the number.
  *Done when:* no page ranks sources against each other on this metric.

- [ ] **S3.3 · Make detection IDs deterministic.** `F10`
  UUIDv5 over `(source, upstream_rule_id)` so permalinks survive re-ingest, file moves and full rebuilds. Migrate existing IDs with 301s from the old ones.
  *Done when:* a full rebuild from scratch produces byte-identical URLs.

- [ ] **S3.4 · Accept the upstream rule ID as an alias route.** `F10`
  `/detections/c28c8fa1-…` should resolve to the same page as the internal ID, so people can link with the ID their vendor uses.
  *Done when:* both IDs resolve; one canonicalises to the other.

- [ ] **S3.5 · Publish the permalink stability guarantee.** `F10`
  One paragraph on the methodology page stating that rule URLs are stable for the life of the site.
  *Done when:* it's written down and true.

- [ ] **S3.6 · Serve tombstones instead of 404s for removed rules.** `F11`
  "Tracked from 2025-11-02 until 2026-08-12, removed from SigmaHQ at `abc123`. Last version we saw: […]. Three current rules covering the same technique: […]."
  *Done when:* no previously-valid rule URL returns a 404.

- [ ] **S3.7 · Fix the cross-vendor similarity fallback.** `F12`
  On the rule I checked, "Same behaviour, other vendors" reported "12 rules · 0 other sources" and filled every slot with same-source rules matched on shared source table. When there is no genuine cross-vendor match, say so — that's a gap finding, not an empty state to paper over.
  *Done when:* same-source neighbours appear in a separate, clearly labelled block and the cross-vendor count is never padded.

- [ ] **S3.8 · Weight search relevance toward titles.** `F13`
  `q=ransomware` returns 588 hits whose top three have none of the term in their titles. Postgres `setweight`: title A, rule name/tags B, description C, query body D.
  *Done when:* `ransomware`, `phishing`, `lateral movement`, `persistence` each return an obviously-on-topic rule at rank 1.

- [ ] **S3.9 · Show per-source licenses.** `F14`
  License badge in the source table on the methodology page and on every rule detail page, linking to the upstream LICENSE. Elastic's ELv2 managed-service restriction matters a lot to your MSSP readers.
  *Done when:* every rule page states the license its content is under.

---

## Sprint 4 — Structure and reach (3–5 days)

- [ ] **S4.1 · Promote "What we count" to `/methodology`.** `F15`
  It's your strongest trust artifact and it's buried at the bottom of `/about` under a bio, while `/methodology` 404s and an `/api/methodology` endpoint already exists.
  *Done when:* `/methodology` resolves and is in the primary nav.

- [ ] **S4.2 · Link methodology from every number.** `F15`
  Hero "15,579", the source cards, "186 / 207", the coverage percentages — each should link to how it's counted.
  *Done when:* no headline figure on the site is unsourced.

- [ ] **S4.3 · Fold `/integrations` into `/intel`.** `F15`
  Three pages currently tell the sync story. `/integrations` adds nothing `/intel` doesn't.
  *Done when:* one canonical sync-status page, with redirects from the old URL.

- [ ] **S4.4 · Give every digest week a permanent URL.** `F16`
  `/digest/2026-w35`, archived forever, with `/digest` redirecting to the latest. A rolling window can't be cited or archived.
  *Done when:* a digest link shared today shows the same content next month.

- [ ] **S4.5 · Add email subscription to the digest.** `F16`
  Buttondown or self-hosted Listmonk. Double opt-in, one-click unsubscribe, plain-text-friendly template.
  *Done when:* a visitor can subscribe from the digest page and receives the next issue.

- [ ] **S4.6 · Add a Slack/Teams webhook format for the digest.** `F16`
  Detection teams read in chat, not in feed readers.
  *Done when:* a documented webhook payload posts a readable weekly summary.

- [ ] **S4.7 · Commit to a weekly public post for six months.** `F16`
  Same digest to LinkedIn every Monday. Consistency is what turns it into a fixture people expect.
  *Done when:* it's on your calendar as a recurring task with the copy template written.

- [ ] **S4.8 · Publish the API at `detectionexplorer.io/api/docs`.** `F17`
  Read-only spec, `/v1` prefix, stated deprecation policy, fair-use note, link in the footer and nav.
  *Done when:* the Railway hostname appears nowhere in the frontend bundle or the docs.

- [ ] **S4.9 · Write three worked API examples.** `F17`
  (1) Pull this week's new rules into a Slack channel. (2) Export a Navigator layer for a given actor. (3) Diff your own rule set against the corpus to find coverage gaps. Copy-pasteable, with real output.
  *Done when:* each runs unmodified against the live API.

- [ ] **S4.10 · Ship the MCP server.** `F17`
  The stdio npm package plus hosted HTTP you'd already planned. This is the version people use inside an agent loop daily.
  *Done when:* published to npm and listed on the site.

- [ ] **S4.11 · Open a contribution path.** `F17`
  `CONTRIBUTING.md`, GitHub Issues enabled with a "suggest a source" template, Discussions on, and a "Suggest a source" link in the site footer.
  *Done when:* a stranger can propose a new repo without emailing you.

- [ ] **S4.12 · Settle the naming.** *(new)*
  The site says "Threat Detection Explorer"; the domain and your resume say "Detection Explorer". Pick one and use it everywhere — wordmark, `<title>`, README, OG tags, LinkedIn.
  *Done when:* one name appears in all surfaces.

- [ ] **S4.13 · Reconsider the default sort on `/detections`.** *(new)*
  "Created (Newest)" currently shows a first-time visitor eight Sublime email rules in a row. Relevance, or a curated "start here" set, sells the corpus better.
  *Done when:* the first screen a new visitor sees represents the breadth of the corpus.

- [ ] **S4.14 · Surface `/query` in the nav and improve syntax discovery.** *(new)*
  The query language is genuinely good; the `?` button is not enough to discover it.
  *Done when:* `/query` is linked from the nav and the search bar.

- [ ] **S4.15 · Replace `Author: unknown` with the source repo.** *(new)*
  More accurate and reads better than "unknown".
  *Done when:* no rule page shows "unknown" as an author.

---

## Sprint 5 — The long game (ongoing)

- [ ] **S5.1 · Retain every nightly snapshot, permanently.** `Strategic`
  The longitudinal record is the only asset a competitor starting tomorrow cannot replicate. Store the full normalized corpus per sync date, even the parts you don't currently surface. Do this before you need it.
  *Done when:* you can reconstruct the exact state of the corpus for any past date.

- [ ] **S5.2 · Rebuild the home page around the gap, not the catalog.** `Strategic`
  "21 ATT&CK techniques have no public detection rule anywhere; here are the 40 actors whose distinctive TTPs nobody covers" is a headline people repost. "15,579 rules, searchable" is one they scroll past. Your `/actors` gap ranking is the most interesting page on the site and it's currently the fourth nav item.
  *Done when:* the gap analysis is above the fold and search is the utility underneath it.

- [ ] **S5.3 · Publish a quarterly coverage report with a stable URL.** `Strategic`
  Coverage growth by technique, which vendors moved, what stayed uncovered, with the underlying data downloadable as CSV/JSON. Citations outlive traffic, and inbound links are the only SEO that survives a platform change.
  *Done when:* the first report is published and submitted to the usual detection-engineering newsletters.

- [ ] **S5.4 · Decide: portfolio piece or institution.** `Strategic`
  "Engineered by Jay Tymchuk" is excellent for the former and a visible bus factor for the latter. If longevity wins, shift the framing to a project with a license, contributors and a governance note, and move the byline to a credits line. The two goals genuinely conflict — pick deliberately rather than by default.
  *Done when:* you've made the call and the site's framing reflects it.

---

## Rollup

| Sprint | Items | Theme | Blocking? |
|---|---|---|---|
| 0 | 5 | Verify auth, license the repo | Yes — security |
| 1 | 9 | Meta tags, SSR, sitemap, mobile | Yes — blocks all sharing |
| 2 | 9 | CDN, caching, perf, loading states | Before real traffic |
| 3 | 9 | Scoring fairness, permalinks, relevance | Before outreach to maintainers |
| 4 | 15 | IA, digest distribution, API, MCP | Growth |
| 5 | 4 | Snapshots, positioning, citations | Ongoing |

**Suggested GitHub labels:** `seo`, `security`, `performance`, `trust`, `ia`, `api`, `growth`, `strategic`
**Suggested milestones:** `v1.5 — shareable`, `v1.6 — durable`, `v2.0 — reference`
