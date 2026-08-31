# API worked examples

Three copy-pasteable workflows against the live API (#92 / teardown
S4.9). Base URL: `https://detectionexplorer.io/api` (same data as the
site; read-only; be reasonable with request rates).

Interactive docs: the OpenAPI spec ships read-only at `/openapi.json`.

---

## 1. This week's new rules into a Slack channel

Pull the permanent weekly digest and post a summary to an incoming
webhook. Works as a Monday cron.

```bash
#!/usr/bin/env bash
API="https://detectionexplorer.io/api"
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
API="https://detectionexplorer.io/api"

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
API="https://detectionexplorer.io/api"

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

---

Questions or a workflow these don't cover: open an issue.
