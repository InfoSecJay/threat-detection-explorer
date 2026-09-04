# API worked examples

Three copy-pasteable workflows against the live API (#92 / teardown
S4.9). Base URL: `https://detectionexplorer.io/api/v1` (same data as the
site; read-only; 40 requests per 10 seconds per IP at the edge).

Interactive docs: https://detectionexplorer.io/api/docs (spec at `/api/openapi.json`).

---

## 1. This week's new rules into a Slack channel

Pull the permanent weekly digest and post a summary to an incoming
webhook. Works as a Monday cron.

```bash
#!/usr/bin/env bash
API="https://detectionexplorer.io/api/v1"
WEEK=$(date -u +%G-w%V)                       # ISO week, e.g. 2026-w36
SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"

DIGEST=$(curl -s "$API/digest/week/$WEEK")
TEXT=$(echo "$DIGEST" | python3 -c '
import json, sys
d = json.load(sys.stdin)
lines = [f"*Detection digest {d["period"]["week"]}*: "
         f"{d["summary"]["created"]} new / {d["summary"]["modified"]} updated"]
for r in d["new_rules"][:10]:
    lines.append(f"- [{r["source"]}] <https://detectionexplorer.io/detections/{r["id"]}|{r["title"]}>")
print("\\n".join(lines))
')
curl -s -X POST -H 'Content-type: application/json' \
  --data "$(python3 -c "import json,sys;print(json.dumps({'text':sys.argv[1]}))" "$TEXT")" \
  "$SLACK_WEBHOOK"
```

There is also RSS if you'd rather not script: `/api/digest/feed.xml`
(new rules, `?source=` filterable) and `/api/digest/modified.xml`.

## 2. A MITRE Navigator layer for one actor

Every rule that covers the techniques a group is known for, as an
ATT&CK Navigator layer you can open at mitre-attack.github.io:

```bash
API="https://detectionexplorer.io/api/v1"

# Find the actor id (APT29 = G0016)
curl -s "$API/actors/catalog" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print([g for g in d["groups"] if g["name"] == "APT29"])'

# Rules covering that actor via the query language, exported as a layer
curl -s -X POST "$API/export" \
  -H "content-type: application/json" \
  -d '{"format": "navigator", "filters": {"q": "actor:APT29"}}' \
  -o apt29-coverage.json
```

## 3. Diff your own rule set against the corpus

Which ATT&CK techniques have public rules while your SIEM has none?
Feed it the technique tags you export from your own platform:

```bash
API="https://detectionexplorer.io/api/v1"

# your_techniques.txt: one technique id per line (T1059.001, ...)
python3 - <<'PY'
import json, urllib.request

API = "https://detectionexplorer.io/api"
mine = {t.strip().upper() for t in open("your_techniques.txt") if t.strip()}

matrix = json.load(urllib.request.urlopen(f"{API}/mitre/coverage-by-data-source?limit=200"))
for row in matrix["rows"]:
    tid = row["technique_id"]
    if tid not in mine and row["rules"] >= 3:
        print(f"{tid:12s} {row['technique_name'][:45]:45s} "
              f"{row['rules']:4d} public rules, none of yours")
PY
```

The observables endpoints slice the other way -- "which rules key on
this process/event ID my telemetry already collects":
`/api/observables/process?q=rundll32`.

## 4. Diff two vendors' rules for the same behaviour

Sigma and Elastic both have a rule for rundll32 running JavaScript.
Which process names, command-line patterns and parent processes does
each one test, and does either exclude something the other matches?

```bash
API="https://detectionexplorer.io/api/v1"

# Find the two rules, then diff them by id (any 2-6 ids work).
A=$(curl -s "$API/detections?q=rundll32+javascript&sources=sigma&limit=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['items'][0]['id'])")
B=$(curl -s "$API/detections?q=rundll32+javascript&sources=elastic&limit=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['items'][0]['id'])")

curl -s "$API/compare/diff?ids=$A,$B" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ids = [r['id'] for r in d['rules']]
for o in d['observables']:
    cells = ['NOT' if i in o['negated_in'] else 'x' if i in o['present_in'] else '-' for i in ids]
    fields = ' / '.join(', '.join(o['fields'].get(i, [])) or '-' for i in ids)
    print(f"{o['type']}/{o['subtype']:22s} {o['value']:40s} {' '.join(f'{c:>3s}' for c in cells)}   {fields}")
print('shared by both:', d['summary']['shared_by_all'], '| contradictions:', len(d['summary']['contradictions']))
"
```

The same matrix is the `/compare?ids=...` page, which also copies as
Markdown for a tuning ticket.

## 5. Everything the public rule set says about one attack surface

`domains=` is the attack-surface axis (endpoint, identity, cloud, saas,
network, email, devops, data); `products=` is the vendor whose telemetry
a rule reads. Together they answer "which identity rules exist, and for
which IdPs" across every source at once:

```bash
API="https://detectionexplorer.io/api/v1"

# Identity-domain rules per vendor product, newest first
curl -s "$API/detections/facets?domains=identity" | python3 -c "
import sys, json
for p in json.load(sys.stdin)['products'][:15]:
    print(f\"{p['value']:24s} {p['count']:5d}\")"

# ATT&CK coverage computed over identity rules only (the /mitre?domain=identity view)
curl -s "$API/compare/coverage-matrix?domain=identity&include_subtechniques=false" | python3 -c "
import sys, json
s = json.load(sys.stdin)['summary']
print(s['techniques_with_any_coverage'], 'of', s['total_techniques'], 'parent techniques have an identity rule')"

# The Okta rules themselves, across Sigma, Elastic, Splunk, Panther and Okta's own repo
curl -s "$API/detections?products=okta&sort_by=rule_created_date&limit=25"
```

---

Questions or a workflow these don't cover: open an issue.
