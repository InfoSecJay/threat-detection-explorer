#!/usr/bin/env python
"""Coverage audit — measure the gap between upstream and our catalog.

For each of the 8 sources, this script:

  1. Fresh-clones (or `git pull`s) the upstream repo into a cache dir.
  2. Walks the tree and counts every file matching the source's
     rule extensions (`*.toml` for Elastic, `*.yml`/`*.yaml` for Sigma,
     etc.) under the directories where rules legitimately live upstream.
  3. Runs each candidate file through our parser AND normalizer.
     Categorises the outcome:
        CAN_PARSE_FALSE — parser rejected by design (deprecated dir,
                          test fixture, wrong extension subtree).
        PARSE_NONE      — parser returned None (silent validation
                          failure — usually missing required field).
        PARSE_RAISED    — parser raised an exception (silent crash —
                          this is what we WANT to find. The legacy
                          `toml` library bug fixed in 801d358 was
                          exactly this class.)
        NORMALIZE_RAISED — parsed OK but normalizer crashed (covers
                          the per-vendor cross-layer wiring).
        OK              — parsed AND normalized cleanly.
  4. Hits the production API for the live stored count.
  5. Prints a per-source report with the delta + sample failures.

A non-zero PARSE_RAISED / NORMALIZE_RAISED count is the strongest
signal — those are rules silently dropped that we likely want to
recover. PARSE_NONE is informational; some rules are genuinely
malformed upstream.

Usage:
    python scripts/audit_coverage.py
    python scripts/audit_coverage.py --source elastic
    python scripts/audit_coverage.py --json
    python scripts/audit_coverage.py --fresh        # nuke cache + re-clone

Exits 0 always (this is a report, not a gate). Use the output to
decide what to fix.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

# Reach the backend without booting the FastAPI app — parsers +
# normalizers are pure Python, no DB / settings required.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.normalizers import (  # noqa: E402
    BaseNormalizer,
    ElasticHuntingNormalizer,
    ElasticNormalizer,
    ElasticProtectionsNormalizer,
    Auth0Normalizer,
    GoogleSecOpsNormalizer,
    LOLRMMNormalizer,
    OktaNormalizer,
    SentinelNormalizer,
    SigmaNormalizer,
    SplunkNormalizer,
    SublimeNormalizer,
)
from app.parsers import (  # noqa: E402
    BaseParser,
    ElasticHuntingParser,
    ElasticParser,
    ElasticProtectionsParser,
    Auth0Parser,
    GoogleSecOpsParser,
    LOLRMMParser,
    OktaParser,
    SentinelParser,
    SigmaParser,
    SplunkParser,
    SublimeParser,
)


PRODUCTION_API = (
    "https://threat-detection-explorer-production.up.railway.app/api"
)
DEFAULT_CACHE_ROOT = Path(tempfile.gettempdir()) / "detection-explorer-audit"
SAMPLE_LIMIT = 5  # show this many example paths per failure category


# ── Source registry ──────────────────────────────────────────────────


@dataclass
class SourceConfig:
    name: str
    repo_url: str
    parser_factory: Callable[[], BaseParser]
    normalizer_factory: Callable[[str], BaseNormalizer]
    extensions: tuple[str, ...]
    # Top-level directories under the clone where rules live. None =
    # walk the whole tree (Sigma uses several `rules-*` siblings).
    walk_roots: Optional[tuple[str, ...]] = None


SOURCES: list[SourceConfig] = [
    SourceConfig(
        name="sigma",
        repo_url="https://github.com/SigmaHQ/sigma",
        parser_factory=SigmaParser,
        normalizer_factory=SigmaNormalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=None,
    ),
    SourceConfig(
        name="elastic",
        repo_url="https://github.com/elastic/detection-rules",
        parser_factory=ElasticParser,
        normalizer_factory=ElasticNormalizer,
        extensions=(".toml",),
        walk_roots=("rules", "rules_building_block"),
    ),
    SourceConfig(
        name="elastic_hunting",
        repo_url="https://github.com/elastic/detection-rules",  # same repo as elastic
        parser_factory=ElasticHuntingParser,
        normalizer_factory=ElasticHuntingNormalizer,
        extensions=(".toml",),
        walk_roots=("hunting",),
    ),
    SourceConfig(
        name="elastic_protections",
        repo_url="https://github.com/elastic/protections-artifacts",
        parser_factory=ElasticProtectionsParser,
        normalizer_factory=ElasticProtectionsNormalizer,
        extensions=(".toml",),
        walk_roots=("behavior",),
    ),
    SourceConfig(
        name="splunk",
        repo_url="https://github.com/splunk/security_content",
        parser_factory=SplunkParser,
        normalizer_factory=SplunkNormalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=("detections",),
    ),
    SourceConfig(
        name="sublime",
        repo_url="https://github.com/sublime-security/sublime-rules",
        parser_factory=SublimeParser,
        normalizer_factory=SublimeNormalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=("detection-rules",),
    ),
    SourceConfig(
        name="lolrmm",
        repo_url="https://github.com/magicsword-io/LOLRMM",
        parser_factory=LOLRMMParser,
        normalizer_factory=LOLRMMNormalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=("detections",),
    ),
    SourceConfig(
        name="sentinel",
        repo_url="https://github.com/Azure/Azure-Sentinel",
        parser_factory=SentinelParser,
        normalizer_factory=SentinelNormalizer,
        extensions=(".yaml", ".yml"),
        # Sentinel publishes rules across three parallel locations.
        # ASIM/ used to be a fourth but contains no analytic rules —
        # see the comment in app/services/rule_discovery.py.
        walk_roots=("Solutions", "Detections", "Summary rules"),
    ),
    SourceConfig(
        name="google_secops",
        repo_url="https://github.com/chronicle/detection-rules",
        parser_factory=GoogleSecOpsParser,
        normalizer_factory=GoogleSecOpsNormalizer,
        extensions=(".yaral",),
        # Chronicle community rules only. `rules/_deprecated/` contains
        # a Windows-invalid filename so we never walk it.
        walk_roots=("rules/community",),
    ),
    SourceConfig(
        name="okta",
        repo_url="https://github.com/okta/customer-detections",
        parser_factory=OktaParser,
        normalizer_factory=OktaNormalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=("detections",),
    ),
    SourceConfig(
        name="auth0",
        repo_url="https://github.com/auth0/auth0-customer-detections",
        parser_factory=Auth0Parser,
        normalizer_factory=Auth0Normalizer,
        extensions=(".yml", ".yaml"),
        walk_roots=("detections",),
    ),
]


# ── Result type ──────────────────────────────────────────────────────


@dataclass
class AuditResult:
    source: str
    upstream_files: int = 0
    can_parse_false: int = 0
    parse_none: int = 0
    parse_raised: int = 0
    normalize_raised: int = 0
    ok: int = 0
    sample_parse_none: list[str] = field(default_factory=list)
    sample_parse_raised: list[tuple[str, str]] = field(default_factory=list)
    sample_normalize_raised: list[tuple[str, str]] = field(default_factory=list)
    production_count: Optional[int] = None

    @property
    def silent_failures(self) -> int:
        """PARSE_RAISED + NORMALIZE_RAISED — bugs we want to fix."""
        return self.parse_raised + self.normalize_raised

    @property
    def delta(self) -> Optional[int]:
        """OK (locally parseable) − production stored count."""
        if self.production_count is None:
            return None
        return self.ok - self.production_count


# ── Clone management ─────────────────────────────────────────────────


def repo_dir_name(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")


def get_clone(url: str, cache_root: Path, fresh: bool) -> Path:
    """Ensure a shallow clone of ``url`` exists at ``cache_root/<name>``.

    Returns its absolute path. ``fresh=True`` removes any existing
    clone and re-clones; otherwise we ``git pull`` to update.
    """
    cache_root.mkdir(parents=True, exist_ok=True)
    target = cache_root / repo_dir_name(url)

    if fresh and target.exists():
        shutil.rmtree(target)

    if target.exists():
        # git pull to refresh. Don't fail the audit if pull fails — we
        # can still report against what we have.
        subprocess.run(
            ["git", "-C", str(target), "fetch", "--depth=1", "origin"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(target), "reset", "--hard", "origin/HEAD"],
            check=False,
            capture_output=True,
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth=1", url, str(target)],
            check=True,
            capture_output=True,
        )
    return target


# ── File enumeration ─────────────────────────────────────────────────


def walk_candidates(
    repo_root: Path,
    extensions: tuple[str, ...],
    walk_roots: Optional[tuple[str, ...]],
) -> list[Path]:
    """Return every relative path under ``repo_root`` matching ``extensions``."""
    if walk_roots is None:
        roots = [repo_root]
    else:
        roots = [repo_root / r for r in walk_roots]

    ext_set = {e.lower() for e in extensions}
    out: list[Path] = []
    for src in roots:
        if not src.exists():
            continue
        for path in src.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in ext_set:
                continue
            rel = path.relative_to(repo_root)
            # Skip dotted directories (.git, .github, etc.) — they
            # never contain real rules and create noise.
            if any(part.startswith(".") for part in rel.parts):
                continue
            out.append(rel)
    return sorted(out)


# ── Classification ───────────────────────────────────────────────────


def _add_sample(bucket: list, value, limit: int = SAMPLE_LIMIT) -> None:
    if len(bucket) < limit:
        bucket.append(value)


def classify(cfg: SourceConfig, repo_root: Path) -> AuditResult:
    parser = cfg.parser_factory()
    normalizer = cfg.normalizer_factory(cfg.repo_url)

    files = walk_candidates(repo_root, cfg.extensions, cfg.walk_roots)
    result = AuditResult(source=cfg.name, upstream_files=len(files))

    # Silence per-rule debug/warn logs from the parsers — they spam the
    # audit output with one line per skipped file.
    logging.disable(logging.CRITICAL)

    for rel in files:
        full = repo_root / rel
        # Mirror IngestionService.ingest_repository: it passes the
        # ABSOLUTE path to can_parse() but the RELATIVE path to
        # parse(). Sentinel's can_parse depends on `/solutions/`
        # (with leading slash) appearing in the string; bare relative
        # paths break that check and produce bogus numbers.
        if not parser.can_parse(full):
            result.can_parse_false += 1
            continue
        try:
            content = full.read_text(encoding="utf-8")
        except Exception as e:
            result.parse_raised += 1
            _add_sample(
                result.sample_parse_raised, (str(rel), f"read: {type(e).__name__}: {e}")
            )
            continue
        try:
            parsed = parser.parse(rel, content)
        except Exception as e:
            result.parse_raised += 1
            _add_sample(
                result.sample_parse_raised, (str(rel), f"{type(e).__name__}: {e}")
            )
            continue
        if parsed is None:
            result.parse_none += 1
            _add_sample(result.sample_parse_none, str(rel))
            continue
        try:
            normalizer.normalize(parsed)
        except Exception as e:
            result.normalize_raised += 1
            _add_sample(
                result.sample_normalize_raised,
                (str(rel), f"{type(e).__name__}: {e}"),
            )
            continue
        result.ok += 1

    logging.disable(logging.NOTSET)
    return result


# ── Production count ─────────────────────────────────────────────────


def fetch_production_count(source: str) -> Optional[int]:
    url = f"{PRODUCTION_API}/detections?sources={source}&limit=1"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("total")
    except Exception as e:
        sys.stderr.write(
            f"  warning: could not fetch production count for {source}: {e}\n"
        )
        return None


# ── Rendering ────────────────────────────────────────────────────────


def render_text(result: AuditResult) -> str:
    lines = [f"=== {result.source} ==="]
    lines.append(f"  upstream files matched:  {result.upstream_files:>6}")
    lines.append(f"  CAN_PARSE_FALSE:         {result.can_parse_false:>6}")
    lines.append(f"  PARSE_NONE:              {result.parse_none:>6}")
    lines.append(f"  PARSE_RAISED:            {result.parse_raised:>6}")
    lines.append(f"  NORMALIZE_RAISED:        {result.normalize_raised:>6}")
    lines.append(f"  OK (parse + normalize):  {result.ok:>6}")
    if result.production_count is not None:
        lines.append(f"  production stored:       {result.production_count:>6}")
        delta = result.delta
        marker = "OK" if delta == 0 else ("LAG" if delta > 0 else "OVER")
        lines.append(f"  DELTA (ok - prod):       {delta:>+6}  [{marker}]")
    if result.sample_parse_none:
        lines.append("  sample PARSE_NONE files:")
        for s in result.sample_parse_none:
            lines.append(f"    {s}")
    if result.sample_parse_raised:
        lines.append("  sample PARSE_RAISED files:")
        for path, err in result.sample_parse_raised:
            lines.append(f"    {path}")
            lines.append(f"      {err}")
    if result.sample_normalize_raised:
        lines.append("  sample NORMALIZE_RAISED files:")
        for path, err in result.sample_normalize_raised:
            lines.append(f"    {path}")
            lines.append(f"      {err}")
    return "\n".join(lines)


def render_summary(results: list[AuditResult]) -> str:
    total_silent = sum(r.silent_failures for r in results)
    total_parse_none = sum(r.parse_none for r in results)
    total_delta = sum(r.delta or 0 for r in results)

    lines = ["=" * 50, "SUMMARY"]
    lines.append(
        f"  total silent failures (RAISED):  {total_silent}"
    )
    lines.append(f"  total PARSE_NONE:                {total_parse_none}")
    lines.append(f"  total DELTA (ok - prod):         {total_delta:+}")
    lines.append("")
    lines.append("  ranked by silent failures:")
    for r in sorted(results, key=lambda x: -x.silent_failures):
        if r.silent_failures == 0 and r.parse_none == 0:
            tag = "clean"
        elif r.silent_failures > 0:
            tag = "silent failures"
        else:
            tag = "parse_none only"
        lines.append(
            f"    {r.source:22s} silent={r.silent_failures:>3} "
            f"none={r.parse_none:>3} delta={(r.delta or 0):>+5}  [{tag}]"
        )
    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(
        description="Coverage audit for the Detection Explorer ingest pipeline."
    )
    p.add_argument(
        "--source", help="Run only for one source by name (e.g. elastic, sigma)."
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text.",
    )
    p.add_argument(
        "--fresh",
        action="store_true",
        help="Discard cached clones and re-clone everything.",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_ROOT,
        help=f"Where to cache shallow clones (default: {DEFAULT_CACHE_ROOT}).",
    )
    p.add_argument(
        "--no-production",
        action="store_true",
        help="Skip the production-count API calls (offline / faster runs).",
    )
    args = p.parse_args()

    sources = SOURCES
    if args.source:
        sources = [s for s in SOURCES if s.name == args.source]
        if not sources:
            sys.stderr.write(
                f"unknown source: {args.source}. Known: "
                f"{', '.join(s.name for s in SOURCES)}\n"
            )
            return 2

    seen_clones: dict[str, Path] = {}
    results: list[AuditResult] = []

    for cfg in sources:
        sys.stderr.write(f"-- {cfg.name}\n")
        if cfg.repo_url not in seen_clones:
            sys.stderr.write(f"   cloning/updating {cfg.repo_url}\n")
            try:
                seen_clones[cfg.repo_url] = get_clone(
                    cfg.repo_url, args.cache_dir, fresh=args.fresh
                )
            except subprocess.CalledProcessError as e:
                sys.stderr.write(f"   clone failed: {e.stderr.decode(errors='replace')}\n")
                continue
        clone = seen_clones[cfg.repo_url]
        sys.stderr.write("   classifying\n")
        result = classify(cfg, clone)
        if not args.no_production:
            sys.stderr.write("   fetching production count\n")
            result.production_count = fetch_production_count(cfg.name)
        results.append(result)
        if not args.json:
            sys.stdout.write(render_text(result) + "\n\n")

    if args.json:
        sys.stdout.write(json.dumps([asdict(r) for r in results], indent=2) + "\n")
    else:
        sys.stdout.write(render_summary(results) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
