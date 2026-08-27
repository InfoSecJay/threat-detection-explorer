"""Issue #35 audit: attribute actor/software mention hits by alias + field.

Replays the production mention matcher (app.services.actor_matching)
over a local corpus and, per software entry, tallies which alias fired
in which field with snippets around each match. Use it to decide
whether a new catalog name belongs in AMBIGUOUS_TOKENS (standalone-
word-only matching) or UNMATCHABLE_TOKENS (dropped from free text) --
see app/services/actor_matching.py.

Run from the repo root:

    backend\\venv\\Scripts\\python.exe scripts\\audit_mention_matching.py
    backend\\venv\\Scripts\\python.exe scripts\\audit_mention_matching.py --db path\\to.db --detail S0039 S0041

Findings from the 2026-08-26 round (12,031-rule corpus), referenced
tier before -> after AMBIGUOUS/UNMATCHABLE:

    S0039 Net    268 -> 15   (.net TLD in URLs, ".NET framework" prose)
    S0613 PS1     87 ->  2   (.ps1 script paths)
    S0041 Wiper   83 ->  8   (hermetic_wiper etc. compound names)
    S0081 Elise   52 ->  0   (alias "Page": Outlook Home Page prose)
    S0103 route   ~21->  8   (route_53 tags/URLs)
    S0363 Empire  35 -> 35   (hits were genuine; left flexible)
"""
import argparse
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
from app.services.actor_matching import compile_name_regex  # noqa: E402

MIN_LEN = 3  # parity with actor_scores.MIN_MENTION_NAME_LEN


def jlist(v):
    if not v:
        return []
    try:
        x = json.loads(v)
        return x if isinstance(x, list) else []
    except (ValueError, TypeError):
        return []


def snippet(text, m, pad=45):
    s, e = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def load_corpus(db_path):
    con = sqlite3.connect(db_path)
    rows = con.execute(
        "select id, source, title, description, tags, [references] from detections"
    ).fetchall()
    corpus = []
    for rid, source, title, desc, tags, refs in rows:
        corpus.append((rid, source, {
            "title": title or "",
            "description": desc or "",
            "tags": " ".join(t for t in jlist(tags) if isinstance(t, str)),
            "references": " ".join(r for r in jlist(refs) if isinstance(r, str)),
        }))
    return corpus


def entity_name_list(entry):
    return [n for n in dict.fromkeys([entry["name"], *entry.get("aliases", [])])
            if n and len(n) >= MIN_LEN]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(REPO / "backend/data/threat_detection.db"))
    ap.add_argument("--mitre", default=str(REPO / "backend/data/mitre_attack.json"))
    ap.add_argument("--top", type=int, default=30, help="rows in the ranking table")
    ap.add_argument("--detail", nargs="*", default=[],
                    help="S-IDs to attribute per-alias/per-field (default: top 10)")
    args = ap.parse_args()

    software = json.load(open(args.mitre, encoding="utf-8"))["software"]
    corpus = load_corpus(args.db)
    print(f"corpus: {len(corpus)} rules")

    per_sw = {}
    for sid, entry in software.items():
        rx = compile_name_regex(entity_name_list(entry))
        if rx is None:
            continue
        hits, title_hits = set(), set()
        for rid, _source, fields in corpus:
            if rx.search(" ".join(fields.values())):
                hits.add(rid)
                if rx.search(fields["title"]):
                    title_hits.add(rid)
        if hits - title_hits:
            per_sw[sid] = (entry["name"], len(hits - title_hits), len(title_hits))

    print(f"\n== top {args.top} software by referenced-tier mentions ==")
    top = sorted(per_sw.items(), key=lambda kv: -kv[1][1])[:args.top]
    for sid, (name, refc, titc) in top:
        print(f"{sid:7} {name:24} referenced={refc:5}  title={titc:4}")

    for sid in args.detail or [s for s, _ in top[:10]]:
        entry = software.get(sid)
        if not entry:
            print(f"\n==== {sid}: not in catalog ====")
            continue
        names = entity_name_list(entry)
        print(f"\n==== {sid} {entry['name']} (aliases: {names}) ====")
        tally, samples, hit_rules = Counter(), defaultdict(list), set()
        for name in names:
            rx = compile_name_regex([name])
            if rx is None:
                continue
            for rid, source, fields in corpus:
                for fname, text in fields.items():
                    m = rx.search(text)
                    if m:
                        tally[(name, fname)] += 1
                        hit_rules.add(rid)
                        if len(samples[(name, fname)]) < 4:
                            samples[(name, fname)].append(
                                f"[{source}] ...{snippet(text, m)}..."
                            )
        print(f"  distinct rules hit: {len(hit_rules)}")
        for (name, fname), c in tally.most_common():
            print(f"  {name!r:14} in {fname:12} {c:5}")
            for s in samples[(name, fname)]:
                print(f"      {s}")


if __name__ == "__main__":
    main()
