#!/usr/bin/env python
"""Local Postgres for pre-deploy verification (#38).

Production is Postgres 17 holding data with a year of schema history;
the dev loop is SQLite over a synthetic or stale corpus. Three
incidents traced to that gap: the 2026-08-28 detail-page 500s (a
column shape that existed only in prod), the #37 snapshot-restore
wedge, and #12 blocked outright on "no Postgres in dev". This script
closes it: pull a production snapshot, restore it into a local
Postgres 17, run the checked-out code's migrations over the real
schema, then drive the API through every route that reads rows.

    python scripts/dev_db.py up          # start the compose Postgres (Docker only)
    python scripts/dev_db.py snapshot    # pg_dump prod -> backend/data/snapshots/
    python scripts/dev_db.py restore     # latest dump -> local database
    python scripts/dev_db.py migrate     # init_db() over the restored schema
    python scripts/dev_db.py smoke       # API against it; --all hits every rule
    python scripts/dev_db.py refresh     # snapshot + restore + migrate + smoke
    python scripts/dev_db.py url         # print the local DATABASE_URL

Run it with the backend venv interpreter from anywhere; paths are
resolved from this file.

Postgres client tools come from one of two places, checked in order:

  1. --pg-bin DIR or the PG_BIN env var: a directory holding pg_dump,
     pg_restore and psql. The portable EDB zip works and needs no admin
     install; the target server can be anything reachable by
     DEV_DATABASE_URL.
  2. The `postgres` service in docker-compose.yml, via
     `docker compose exec`. Nothing is installed on the host.

`snapshot` needs the production URL in DATABASE_PUBLIC_URL. When it is
absent and the Railway CLI is on PATH, the script re-runs itself under
`railway run --service Postgres`, which injects it. The URL is passed
to the tools through the PG* environment, never on a command line, and
is never printed.

What the snapshot leaves out (every row is derived from public repos
and no credential lives in the database, so "sanitised" is short):

  - corpus_snapshots ROWS (two thirds of the database: the nightly
    gzipped payloads behind /methodology/unclassified history). The
    table is kept, empty, so the code paths still run. --with-snapshots
    includes them.
  - worker_leases ROWS, so a local worker never sees a held prod lease.

Dumps land in backend/data/snapshots/ (gitignored) in pg_dump custom
format, with a JSON manifest beside each.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BACKEND = REPO / "backend"
COMPOSE_FILE = REPO / "docker-compose.yml"
COMPOSE_SERVICE = "postgres"
SNAPSHOT_DIR = BACKEND / "data" / "snapshots"

LOCAL_URL_DEFAULT = (
    "postgresql://detection_explorer:detection_explorer@localhost:5433/detection_explorer"
)

# Tables whose rows never leave production.
EXCLUDE_DATA_ALWAYS = ("worker_leases",)
# Tables whose rows are left out unless asked for.
EXCLUDE_DATA_DEFAULT = ("corpus_snapshots",)

REEXEC_FLAG = "DEV_DB_REEXEC"

# The public source ids the API knows. The smoke test samples detail
# pages per source so a shape that only one normalizer writes is hit.
SOURCES = (
    "sigma", "elastic", "elastic_hunting", "elastic_protections", "splunk",
    "sublime", "lolrmm", "sentinel", "google_secops", "okta", "auth0",
    "panther", "pypanther",
)

# Read routes hit once each, beyond the per-source detail sweep. Every
# one of them serialises detection rows or aggregates over them.
SMOKE_ROUTES = (
    "/api/health",
    "/api/v1/detections/statistics",
    "/api/v1/detections?limit=100",
    "/api/v1/detections?q=powershell&limit=50",
    "/api/v1/detections/filters",
    "/api/v1/mitre/stats",
    "/api/v1/actors/G0016",
    "/api/v1/compare?technique=T1059.001",
)


# --------------------------------------------------------------------------
# URL handling
# --------------------------------------------------------------------------

def pg_env_from_url(url: str) -> dict[str, str]:
    """Translate a libpq/SQLAlchemy URL into PG* environment variables.

    Accepts postgres://, postgresql:// and postgresql+asyncpg:// forms.
    Only the parts present in the URL are returned, so libpq defaults
    (port 5432, the OS user, sslmode=prefer) still apply for the rest.
    """
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.split("+", 1)[0]
    if scheme not in ("postgres", "postgresql"):
        raise ValueError(f"not a Postgres URL (scheme {parsed.scheme!r})")
    env: dict[str, str] = {}
    if parsed.hostname:
        env["PGHOST"] = parsed.hostname
    if parsed.port:
        env["PGPORT"] = str(parsed.port)
    if parsed.username:
        env["PGUSER"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    database = parsed.path.lstrip("/")
    if database:
        env["PGDATABASE"] = database
    query = urllib.parse.parse_qs(parsed.query)
    if query.get("sslmode"):
        env["PGSSLMODE"] = query["sslmode"][0]
    return env


def async_url(url: str) -> str:
    """The SQLAlchemy async form the app's config expects."""
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+asyncpg://" + url[len(prefix):]
    raise ValueError(f"not a Postgres URL: {url!r}")


# --------------------------------------------------------------------------
# Tool runners: local binaries or the compose container
# --------------------------------------------------------------------------

class LocalTools:
    """pg_dump / pg_restore / psql from a directory on this machine."""

    kind = "local"

    def __init__(self, bin_dir: Path):
        self.bin_dir = bin_dir
        for tool in ("pg_dump", "pg_restore", "psql"):
            if self._path(tool) is None:
                raise SystemExit(f"{tool} not found in {bin_dir}")

    def _path(self, tool: str) -> Optional[Path]:
        for name in (tool, f"{tool}.exe"):
            candidate = self.bin_dir / name
            if candidate.exists():
                return candidate
        return None

    def command(self, tool: str, args: list[str], env: dict[str, str]) -> list[str]:
        return [str(self._path(tool))] + args

    def local_env(self, local_url: str) -> dict[str, str]:
        return pg_env_from_url(local_url)

    def describe(self) -> str:
        return f"local binaries in {self.bin_dir}"


class DockerTools:
    """The same tools, run inside the compose Postgres container.

    Connection settings travel as `-e NAME` pass-throughs: docker reads
    each value from the client's environment, so nothing secret lands
    in a command line.
    """

    kind = "docker"

    def __init__(self, compose_file: Path = COMPOSE_FILE, service: str = COMPOSE_SERVICE):
        self.compose_file = compose_file
        self.service = service

    def compose(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.compose_file), *args]

    def command(self, tool: str, args: list[str], env: dict[str, str]) -> list[str]:
        passthrough: list[str] = []
        for name in sorted(env):
            passthrough += ["-e", name]
        return self.compose("exec", "-T", *passthrough, self.service, tool, *args)

    def local_env(self, local_url: str) -> dict[str, str]:
        # Inside the container the server is the local socket, whatever
        # port the host maps it to; only user and database carry over.
        env = pg_env_from_url(local_url)
        return {k: v for k, v in env.items() if k in ("PGUSER", "PGPASSWORD", "PGDATABASE")}

    def describe(self) -> str:
        return f"docker compose service '{self.service}' ({self.compose_file.name})"


Tools = LocalTools | DockerTools


def select_tools(pg_bin: Optional[str], which: Callable[[str], Optional[str]] = shutil.which) -> Tools:
    """PG_BIN / --pg-bin wins; otherwise the compose container; else fail with the two options."""
    bin_dir = pg_bin or os.environ.get("PG_BIN")
    if bin_dir:
        return LocalTools(Path(bin_dir).expanduser().resolve())
    if which("docker"):
        return DockerTools()
    raise SystemExit(
        "No Postgres client tools. Either install Docker Desktop and run\n"
        "  docker compose up -d --wait\n"
        "or point PG_BIN (or --pg-bin) at a directory with pg_dump, pg_restore\n"
        "and psql -- the portable EDB zip from\n"
        "  https://www.enterprisedb.com/download-postgresql-binaries\n"
        "works without an admin install."
    )


def run(cmd: list[str], env: dict[str, str], *, stdin=None, stdout=None, capture: bool = False) -> subprocess.CompletedProcess:
    full_env = {**os.environ, **env}
    return subprocess.run(
        cmd, env=full_env, stdin=stdin, stdout=stdout,
        stderr=subprocess.PIPE if capture else None,
        text=capture, check=False,
    )


def psql_scalar(tools: Tools, env: dict[str, str], sql: str, database: Optional[str] = None) -> str:
    args = ["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql]
    if database:
        args = ["-d", database] + args
    proc = subprocess.run(
        tools.command("psql", args, env), env={**os.environ, **env},
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"psql failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


# --------------------------------------------------------------------------
# snapshot
# --------------------------------------------------------------------------

def dump_args(with_snapshots: bool) -> list[str]:
    """pg_dump arguments for a snapshot; output goes to stdout."""
    args = ["--format=custom", "--no-owner", "--no-privileges", "--compress=6"]
    excluded = list(EXCLUDE_DATA_ALWAYS)
    if not with_snapshots:
        excluded += list(EXCLUDE_DATA_DEFAULT)
    for table in excluded:
        args.append(f"--exclude-table-data={table}")
    return args


def excluded_tables(with_snapshots: bool) -> list[str]:
    return [a.split("=", 1)[1] for a in dump_args(with_snapshots) if a.startswith("--exclude-table-data=")]


def local_commit() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    return out.stdout.strip() or None


def reexec_under_railway(argv: list[str]) -> int:
    """Re-run this invocation with the Postgres service variables injected."""
    if not shutil.which("railway"):
        raise SystemExit(
            "DATABASE_PUBLIC_URL is not set and the Railway CLI is not on PATH.\n"
            "Either run this under `railway run --service Postgres -- ...` or\n"
            "pass --source <postgres url>."
        )
    cmd = ["railway", "run", "--service", "Postgres", "--", sys.executable, str(Path(__file__).resolve()), *argv]
    print("DATABASE_PUBLIC_URL not set; re-running under railway run --service Postgres")
    env = {**os.environ, REEXEC_FLAG: "1"}
    return subprocess.run(cmd, env=env, check=False).returncode


def needs_prod_url(args: argparse.Namespace, environ: dict[str, str]) -> bool:
    """True when the command dumps production and no URL is available yet."""
    if args.command not in ("snapshot", "refresh"):
        return False
    return not (getattr(args, "source", None) or environ.get("DATABASE_PUBLIC_URL"))


def cmd_snapshot(args: argparse.Namespace) -> int:
    source = args.source or os.environ.get("DATABASE_PUBLIC_URL")
    if not source:
        raise SystemExit("no production URL: set DATABASE_PUBLIC_URL, run under railway run, or pass --source")

    tools = select_tools(args.pg_bin)
    src_env = pg_env_from_url(source)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M")
    out = SNAPSHOT_DIR / f"prod-{stamp}.dump"

    server_version = psql_scalar(tools, src_env, "select version()")
    print(f"source:   {src_env.get('PGHOST', '?')} ({server_version.split(' on ')[0]})")
    print(f"tools:    {tools.describe()}")
    print(f"excluded: rows of {', '.join(excluded_tables(args.with_snapshots))}")
    print(f"writing:  {out}")

    started = time.monotonic()
    with open(out, "wb") as fh:
        proc = run(tools.command("pg_dump", dump_args(args.with_snapshots), src_env), src_env, stdout=fh, capture=True)
    if proc.returncode != 0:
        out.unlink(missing_ok=True)
        raise SystemExit(f"pg_dump failed ({proc.returncode}):\n{proc.stderr}")
    size = out.stat().st_size
    manifest = {
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "server_version": server_version,
        "with_snapshots": bool(args.with_snapshots),
        "excluded_table_data": excluded_tables(args.with_snapshots),
        "bytes": size,
        "seconds": round(time.monotonic() - started, 1),
        "tools": tools.kind,
        "local_commit": local_commit(),
    }
    out.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"done:     {size / 1e6:.1f} MB in {manifest['seconds']} s")
    return 0


# --------------------------------------------------------------------------
# restore / migrate
# --------------------------------------------------------------------------

def latest_dump(directory: Path = SNAPSHOT_DIR) -> Optional[Path]:
    dumps = sorted(directory.glob("prod-*.dump")) if directory.exists() else []
    return dumps[-1] if dumps else None


def recreate_sql(database: str) -> list[str]:
    """Statements that give a clean database, kicking out anything connected."""
    quoted = '"' + database.replace('"', '""') + '"'
    return [
        f"DROP DATABASE IF EXISTS {quoted} WITH (FORCE)",
        f"CREATE DATABASE {quoted}",
    ]


def restore_args(database: str) -> list[str]:
    """pg_restore arguments; the dump arrives on stdin."""
    return ["--no-owner", "--no-privileges", "--exit-on-error", "--dbname", database]


def cmd_restore(args: argparse.Namespace) -> int:
    dump = Path(args.dump) if args.dump else latest_dump()
    if dump is None or not dump.exists():
        raise SystemExit(f"no dump found; run `snapshot` first (looked in {SNAPSHOT_DIR})")
    tools = select_tools(args.pg_bin)
    local_url = args.target
    env = tools.local_env(local_url)
    database = env.get("PGDATABASE") or "detection_explorer"
    manifest_path = dump.with_suffix(".json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}

    print(f"dump:     {dump.name} ({dump.stat().st_size / 1e6:.1f} MB, taken {manifest.get('created_at', '?')})")
    print(f"target:   {database} via {tools.describe()}")

    # Talk to the maintenance database while the target is dropped.
    admin_env = {**env, "PGDATABASE": "postgres"}
    for sql in recreate_sql(database):
        psql_scalar(tools, admin_env, sql)

    started = time.monotonic()
    with open(dump, "rb") as fh:
        proc = run(tools.command("pg_restore", restore_args(database), env), env, stdin=fh, capture=True)
    if proc.returncode != 0:
        raise SystemExit(f"pg_restore failed ({proc.returncode}):\n{proc.stderr}")
    rules = psql_scalar(tools, env, "select count(*) from detections")
    print(f"restored: {rules} detections in {time.monotonic() - started:.1f} s")
    print("next:     migrate, then smoke")
    return 0


def ensure_database(tools: Tools, local_url: str) -> bool:
    """Create the target database when it is missing (a self-run server
    has none; the compose service creates it from POSTGRES_DB)."""
    env = tools.local_env(local_url)
    database = env.get("PGDATABASE") or "detection_explorer"
    admin_env = {**env, "PGDATABASE": "postgres"}
    exists = psql_scalar(tools, admin_env, f"select 1 from pg_database where datname = '{database}'")
    if exists == "1":
        return False
    psql_scalar(tools, admin_env, recreate_sql(database)[1])
    return True


def cmd_migrate(args: argparse.Namespace) -> int:
    """Run the checked-out code's startup migrations over the restored schema.

    This is the pre-deploy check proper: whatever main.py does on
    startup in Railway, done here first, against the real shapes.
    """
    if ensure_database(select_tools(args.pg_bin), args.target):
        print(f"created:  empty database {args.target.rsplit('/', 1)[-1]}")
    os.environ["DATABASE_URL"] = async_url(args.target)
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ["DEBUG"] = "false"  # no SQL echo; the migration log lines still print
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)
    import app.models  # noqa: F401  (registers every table on Base)
    from app.database import engine, init_db

    async def _migrate() -> None:
        await init_db()
        await engine.dispose()

    started = time.monotonic()
    asyncio.run(_migrate())
    print(f"migrated: init_db() over {args.target.rsplit('/', 1)[-1]} in {time.monotonic() - started:.1f} s")
    return 0


# --------------------------------------------------------------------------
# smoke
# --------------------------------------------------------------------------

Fetch = Callable[[str], tuple[int, str]]


def http_fetch(base: str) -> Fetch:
    def fetch(path: str) -> tuple[int, str]:
        req = urllib.request.Request(base + path, headers={"User-Agent": "dev_db-smoke/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            # Connection refused (server still starting, or it died):
            # status 0 so callers can tell it from an HTTP answer.
            return 0, str(exc)
    return fetch


def detail_ids(fetch: Fetch, source: str, per_source: Optional[int], page: int = 200) -> list[str]:
    """Ids to sweep for one source: a sample, or every rule when per_source is None."""
    ids: list[str] = []
    offset = 0
    while True:
        limit = page if per_source is None else min(page, per_source - len(ids))
        if limit <= 0:
            break
        status, body = fetch(f"/api/v1/detections?sources={source}&limit={limit}&offset={offset}")
        if status != 200:
            raise RuntimeError(f"list for {source} -> {status}: {body[:200]}")
        payload = json.loads(body)
        items = payload.get("items", [])
        ids += [item["id"] for item in items]
        offset += len(items)
        if not items or offset >= payload.get("total", 0) or (per_source is not None and len(ids) >= per_source):
            break
    return ids


def run_smoke(fetch: Fetch, per_source: Optional[int], sources: Iterable[str] = SOURCES,
              routes: Iterable[str] = SMOKE_ROUTES, log: Callable[[str], None] = print) -> list[tuple[str, int, str]]:
    """Hit every route; return the failures as (path, status, body head)."""
    failures: list[tuple[str, int, str]] = []
    for path in routes:
        status, body = fetch(path)
        if status != 200:
            failures.append((path, status, body[:300]))
        log(f"  {status}  {path}")
    swept = 0
    for source in sources:
        try:
            ids = detail_ids(fetch, source, per_source)
        except RuntimeError as exc:
            failures.append((f"list {source}", 0, str(exc)))
            continue
        bad = 0
        for rule_id in ids:
            status, body = fetch(f"/api/v1/detections/{rule_id}")
            if status != 200:
                bad += 1
                failures.append((f"/api/v1/detections/{rule_id}", status, body[:300]))
        swept += len(ids)
        log(f"  {source:<20} {len(ids):>6} detail pages, {bad} failed")
    log(f"  {swept} detail pages swept")
    return failures


def wait_for_health(fetch: Fetch, timeout: float, proc: Optional[subprocess.Popen] = None) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise SystemExit(f"API exited with {proc.returncode} before becoming healthy")
        status, _ = fetch("/api/health")
        if status == 200:
            return
        time.sleep(1)
    raise SystemExit(f"API not healthy after {timeout:.0f} s")


def cmd_smoke(args: argparse.Namespace) -> int:
    base = f"http://127.0.0.1:{args.port}"
    fetch = http_fetch(base)
    proc: Optional[subprocess.Popen] = None
    if not args.attach:
        env = {
            **os.environ,
            "DATABASE_URL": async_url(args.target),
            "ENVIRONMENT": "development",
            "ENABLE_SCHEDULER": "false",
            "WARM_CACHES_ON_START": "false",
            "DEBUG": "false",
        }
        env.pop("ADMIN_TOKEN", None)
        cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.port), "--log-level", "warning"]
        print(f"starting: uvicorn on {base} against {args.target.rsplit('/', 1)[-1]}")
        proc = subprocess.Popen(cmd, cwd=BACKEND, env=env)
    try:
        wait_for_health(fetch, args.timeout, proc)
        per_source = None if args.all else args.per_source
        print(f"smoke:    {'every rule' if per_source is None else f'{per_source} rules per source'}")
        started = time.monotonic()
        failures = run_smoke(fetch, per_source)
        print(f"took:     {time.monotonic() - started:.1f} s")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
    if failures:
        print(f"\nFAILED: {len(failures)} request(s)")
        for path, status, body in failures[:20]:
            print(f"  {status}  {path}\n        {body}")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more")
        return 1
    print("\nOK: every route answered 200")
    return 0


# --------------------------------------------------------------------------
# compose helpers, refresh, url
# --------------------------------------------------------------------------

def cmd_up(args: argparse.Namespace) -> int:
    tools = select_tools(args.pg_bin)
    if not isinstance(tools, DockerTools):
        raise SystemExit("`up` manages the docker compose service; with PG_BIN you run your own server")
    return subprocess.run(tools.compose("up", "-d", "--wait", tools.service), check=False).returncode


def cmd_down(args: argparse.Namespace) -> int:
    tools = select_tools(args.pg_bin)
    if not isinstance(tools, DockerTools):
        raise SystemExit("`down` manages the docker compose service; with PG_BIN you run your own server")
    extra = ["--volumes"] if args.volumes else []
    return subprocess.run(tools.compose("down", *extra), check=False).returncode


def cmd_refresh(args: argparse.Namespace) -> int:
    for step in (cmd_snapshot, cmd_restore, cmd_migrate, cmd_smoke):
        print(f"\n== {step.__name__.removeprefix('cmd_')} ==")
        rc = step(args)
        if rc != 0:
            return rc
    return 0


def cmd_url(args: argparse.Namespace) -> int:
    print(async_url(args.target))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _snapshot_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--source", help="production URL (default: DATABASE_PUBLIC_URL, injected by railway run)")
    p.add_argument("--with-snapshots", action="store_true", help="include corpus_snapshots rows (large)")


def _restore_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dump", help="dump file (default: newest in backend/data/snapshots/)")


def _smoke_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--all", action="store_true", help="sweep every rule's detail page, not a sample")
    p.add_argument("--per-source", type=int, default=25, help="detail pages per source when not --all")
    p.add_argument("--port", type=int, default=8010)
    p.add_argument("--attach", action="store_true", help="use an API already listening on --port instead of starting one")
    p.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for /api/health")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pg-bin", help="directory with pg_dump/pg_restore/psql (default: PG_BIN env, else docker compose)")
    parser.add_argument("--target", default=os.environ.get("DEV_DATABASE_URL", LOCAL_URL_DEFAULT),
                        help="local Postgres URL (default: DEV_DATABASE_URL env, else the compose service)")
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="pg_dump production into backend/data/snapshots/")
    _snapshot_args(snap)
    snap.set_defaults(func=cmd_snapshot)

    rest = sub.add_parser("restore", help="drop, create and pg_restore the local database from a dump")
    _restore_args(rest)
    rest.set_defaults(func=cmd_restore)

    mig = sub.add_parser("migrate", help="run init_db() (the startup migrations) over the local database")
    mig.set_defaults(func=cmd_migrate)

    smoke = sub.add_parser("smoke", help="start the API on the local database and hit every read route")
    _smoke_args(smoke)
    smoke.set_defaults(func=cmd_smoke)

    refresh = sub.add_parser("refresh", help="snapshot, restore, migrate, smoke")
    _snapshot_args(refresh)
    _restore_args(refresh)
    _smoke_args(refresh)
    refresh.set_defaults(func=cmd_refresh)

    up = sub.add_parser("up", help="docker compose up -d --wait postgres")
    up.set_defaults(func=cmd_up)
    down = sub.add_parser("down", help="docker compose down (keeps the volume unless --volumes)")
    down.add_argument("--volumes", action="store_true")
    down.set_defaults(func=cmd_down)

    url = sub.add_parser("url", help="print the local DATABASE_URL in the form the app expects")
    url.set_defaults(func=cmd_url)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    if needs_prod_url(args, os.environ):
        if os.environ.get(REEXEC_FLAG):
            raise SystemExit("railway run did not inject DATABASE_PUBLIC_URL; is the CLI logged in and linked?")
        return reexec_under_railway(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
