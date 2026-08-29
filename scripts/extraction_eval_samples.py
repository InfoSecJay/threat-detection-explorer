#!/usr/bin/env python
# Usage: python scripts/extraction_eval_samples.py samples.json out_dir [source,source]
"""Re-run the exact ingestion path (parser -> normalizer -> extractor) on
sampled production rules and report precision signals per source:
  - fallback (`*_field`) subtype share + the field names behind it
  - other/unknown observables and their field names
  - per-surface value listings for manual review
Also writes a readable per-source dump for semantic inspection.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.services.ingestion import IngestionService  # noqa: E402

SAMPLES = Path(sys.argv[1])
OUT_DIR = Path(sys.argv[2])
ONLY = sys.argv[3].split(",") if len(sys.argv) > 3 else None
OUT_DIR.mkdir(exist_ok=True)

svc = IngestionService(None)
samples = json.loads(SAMPLES.read_text(encoding="utf-8"))

report = {}
for source, rules in samples.items():
    if ONLY and source not in ONLY:
        continue
    parser = svc.parsers.get(source)
    normalizer = svc.normalizers.get(source)
    if not parser or not normalizer:
        print(f"{source}: no parser/normalizer", file=sys.stderr)
        continue
    fallback_fields = Counter()
    unknown_fields = Counter()
    pair_counts = Counter()
    surfaces = defaultdict(Counter)
    n_ok = n_fail = 0
    dump_lines = []
    total_obs = 0
    for r in rules:
        try:
            parsed = parser.parse(Path(r["source_file"]), r["raw_content"])
            if parsed is None:
                n_fail += 1
                continue
            norm = normalizer.normalize(parsed)
        except Exception as e:  # noqa: BLE001
            n_fail += 1
            dump_lines.append(f"!! {r['title'][:70]} :: {type(e).__name__}: {e}")
            continue
        n_ok += 1
        obs = norm.extracted_observables or []
        total_obs += len(obs)
        for o in obs:
            t, st = o.get("type"), o.get("subtype")
            pair_counts[(t, st)] += 1
            if isinstance(st, str) and st.endswith("_field"):
                fallback_fields[o.get("field")] += 1
            if t == "other":
                unknown_fields[o.get("field")] += 1
        for surf in ("extracted_process_names", "extracted_file_paths", "extracted_registry_keys",
                     "extracted_network_indicators", "extracted_event_ids", "extracted_api_actions",
                     "extracted_target_resources", "extracted_source_tables"):
            for v in getattr(norm, surf, None) or []:
                surfaces[surf][v] += 1
        # readable dump
        logic = (norm.detection_logic or "")[:900]
        dump_lines.append("=" * 100)
        dump_lines.append(f"{r['title']}  [{norm.language}]  {r['source_file']}")
        dump_lines.append("-" * 100)
        dump_lines.append(logic)
        dump_lines.append("-- observables:")
        for o in obs:
            neg = "NOT " if o.get("negated") else ""
            vals = ", ".join(str(v) for v in (o.get("values") or [])[:6])
            dump_lines.append(f"   {neg}{o.get('type')}/{o.get('subtype'):<26} {o.get('field'):<40} = {vals}")
        dump_lines.append(f"-- fields_used: {', '.join((norm.extracted_fields_used or [])[:25])}")
        dump_lines.append(f"-- tables: {norm.extracted_source_tables}  event_ids: {norm.extracted_event_ids}  api: {norm.extracted_api_actions[:8]}")
    fb = sum(fallback_fields.values())
    report[source] = {
        "rules_ok": n_ok, "rules_fail": n_fail, "observables": total_obs,
        "fallback_share": round(100 * fb / total_obs, 1) if total_obs else None,
        "top_fallback_fields": fallback_fields.most_common(40),
        "top_unknown_fields": unknown_fields.most_common(40),
        "top_pairs": [(f"{t}/{st}", n) for (t, st), n in pair_counts.most_common(12)],
    }
    (OUT_DIR / f"{source}.txt").write_text("\n".join(dump_lines), encoding="utf-8")
    (OUT_DIR / f"{source}_surfaces.txt").write_text(
        "\n".join(f"## {surf}\n" + "\n".join(f"{n:4d}  {v}" for v, n in c.most_common(80)) for surf, c in surfaces.items()),
        encoding="utf-8",
    )

for source, rep in report.items():
    print(f"=== {source}: ok={rep['rules_ok']} fail={rep['rules_fail']} obs={rep['observables']} fallback={rep['fallback_share']}%")
    print("  pairs:", rep["top_pairs"])
    print("  fallback fields:", rep["top_fallback_fields"][:25])
    print("  unknown fields:", rep["top_unknown_fields"][:20])
(OUT_DIR / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
