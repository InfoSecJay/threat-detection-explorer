"""scripts/dev_db.py (#38): the pure parts -- URL handling, tool
selection, pg_dump/pg_restore argument shape, the smoke sweep."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "dev_db.py"
_spec = importlib.util.spec_from_file_location("dev_db", SCRIPT)
dev_db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dev_db)


# --- URL handling ----------------------------------------------------------

def test_pg_env_from_url_maps_every_part():
    env = dev_db.pg_env_from_url("postgresql://u%40x:p%3Ass@db.example:5433/name?sslmode=require")
    assert env == {
        "PGHOST": "db.example",
        "PGPORT": "5433",
        "PGUSER": "u@x",
        "PGPASSWORD": "p:ss",
        "PGDATABASE": "name",
        "PGSSLMODE": "require",
    }


def test_pg_env_from_url_omits_absent_parts_so_libpq_defaults_apply():
    assert dev_db.pg_env_from_url("postgres://localhost/db") == {"PGHOST": "localhost", "PGDATABASE": "db"}


def test_pg_env_from_url_accepts_the_sqlalchemy_async_scheme():
    assert dev_db.pg_env_from_url("postgresql+asyncpg://a:b@h/d")["PGUSER"] == "a"


def test_pg_env_from_url_rejects_other_schemes():
    with pytest.raises(ValueError):
        dev_db.pg_env_from_url("sqlite+aiosqlite:///x.db")


@pytest.mark.parametrize("url", [
    "postgres://a:b@h:1/d",
    "postgresql://a:b@h:1/d",
    "postgresql+asyncpg://a:b@h:1/d",
])
def test_async_url_normalises_every_prefix(url):
    assert dev_db.async_url(url) == "postgresql+asyncpg://a:b@h:1/d"


# --- pg_dump / pg_restore shape -------------------------------------------

def test_dump_leaves_out_lease_and_snapshot_rows_by_default():
    args = dev_db.dump_args(with_snapshots=False)
    assert "--format=custom" in args and "--no-owner" in args and "--no-privileges" in args
    assert "--exclude-table-data=worker_leases" in args
    assert "--exclude-table-data=corpus_snapshots" in args
    assert dev_db.excluded_tables(False) == ["worker_leases", "corpus_snapshots"]


def test_with_snapshots_keeps_the_snapshot_rows_but_never_the_leases():
    args = dev_db.dump_args(with_snapshots=True)
    assert "--exclude-table-data=corpus_snapshots" not in args
    assert "--exclude-table-data=worker_leases" in args


def test_restore_reads_stdin_and_stops_on_the_first_error():
    args = dev_db.restore_args("detection_explorer")
    assert "--exit-on-error" in args
    assert args[-2:] == ["--dbname", "detection_explorer"]
    assert not any(a.endswith(".dump") for a in args)


def test_recreate_sql_quotes_the_name_and_forces_out_connections():
    drop, create = dev_db.recreate_sql('odd"name')
    assert drop == 'DROP DATABASE IF EXISTS "odd""name" WITH (FORCE)'
    assert create == 'CREATE DATABASE "odd""name"'


def test_latest_dump_is_the_newest_by_timestamped_name(tmp_path):
    for name in ("prod-20260901-0200.dump", "prod-20260926-1400.dump", "prod-20260910-0900.dump"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "prod-20260926-1400.json").write_text("{}", encoding="utf-8")
    assert dev_db.latest_dump(tmp_path).name == "prod-20260926-1400.dump"
    assert dev_db.latest_dump(tmp_path / "missing") is None


# --- tool runners ------------------------------------------------------------

def _fake_bins(tmp_path: Path) -> Path:
    for tool in ("pg_dump", "pg_restore", "psql"):
        (tmp_path / f"{tool}.exe").write_bytes(b"")
    return tmp_path


def test_local_tools_run_the_binaries_from_the_directory(tmp_path):
    tools = dev_db.LocalTools(_fake_bins(tmp_path))
    cmd = tools.command("pg_dump", ["--format=custom"], {"PGHOST": "h"})
    assert cmd[0] == str(tmp_path / "pg_dump.exe")
    assert cmd[1:] == ["--format=custom"]
    assert tools.local_env("postgresql://u:p@localhost:5433/d") == {
        "PGHOST": "localhost", "PGPORT": "5433", "PGUSER": "u", "PGPASSWORD": "p", "PGDATABASE": "d",
    }


def test_local_tools_refuse_a_directory_missing_a_tool(tmp_path):
    (tmp_path / "psql.exe").write_bytes(b"")
    with pytest.raises(SystemExit):
        dev_db.LocalTools(tmp_path)


def test_docker_tools_pass_env_names_only_never_values():
    tools = dev_db.DockerTools(compose_file=Path("/repo/docker-compose.yml"))
    cmd = tools.command("pg_dump", ["--format=custom"], {"PGPASSWORD": "hunter2", "PGHOST": "prod.example"})
    assert cmd[:6] == ["docker", "compose", "-f", str(Path("/repo/docker-compose.yml")), "exec", "-T"]
    assert "-e" in cmd and "PGPASSWORD" in cmd and "PGHOST" in cmd
    assert "hunter2" not in " ".join(cmd) and "prod.example" not in " ".join(cmd)
    assert cmd[-3:] == ["postgres", "pg_dump", "--format=custom"]


def test_docker_local_env_drops_host_and_port_because_the_server_is_in_the_container():
    tools = dev_db.DockerTools()
    assert tools.local_env("postgresql://u:p@localhost:5433/d") == {"PGUSER": "u", "PGPASSWORD": "p", "PGDATABASE": "d"}


def test_select_tools_prefers_explicit_binaries_then_docker_then_fails(tmp_path, monkeypatch):
    bins = _fake_bins(tmp_path)
    monkeypatch.delenv("PG_BIN", raising=False)

    assert isinstance(dev_db.select_tools(str(bins), which=lambda _: "/usr/bin/docker"), dev_db.LocalTools)

    monkeypatch.setenv("PG_BIN", str(bins))
    assert isinstance(dev_db.select_tools(None, which=lambda _: None), dev_db.LocalTools)

    monkeypatch.delenv("PG_BIN")
    assert isinstance(dev_db.select_tools(None, which=lambda _: "/usr/bin/docker"), dev_db.DockerTools)

    with pytest.raises(SystemExit) as exc:
        dev_db.select_tools(None, which=lambda _: None)
    assert "Docker Desktop" in str(exc.value) and "PG_BIN" in str(exc.value)


# --- railway re-exec decision ----------------------------------------------

def _args(command: str, **kw) -> argparse.Namespace:
    return argparse.Namespace(command=command, **kw)


def test_only_the_dumping_commands_need_the_prod_url():
    assert dev_db.needs_prod_url(_args("snapshot", source=None), {})
    assert dev_db.needs_prod_url(_args("refresh", source=None), {})
    assert not dev_db.needs_prod_url(_args("snapshot", source="postgres://x/y"), {})
    assert not dev_db.needs_prod_url(_args("snapshot", source=None), {"DATABASE_PUBLIC_URL": "postgres://x/y"})
    for command in ("restore", "migrate", "smoke", "up", "down", "url"):
        assert not dev_db.needs_prod_url(_args(command), {})


def test_parser_accepts_every_documented_command():
    parser = dev_db.build_parser()
    for argv in (["snapshot"], ["snapshot", "--with-snapshots"], ["restore", "--dump", "x.dump"], ["migrate"],
                 ["smoke", "--all"], ["refresh", "--per-source", "5", "--source", "postgres://a/b"], ["up"],
                 ["down", "--volumes"], ["url"]):
        args = parser.parse_args(argv)
        assert callable(args.func)


# --- smoke sweep ------------------------------------------------------------

class FakeAPI:
    """A tiny corpus behind the two endpoints the sweep uses."""

    def __init__(self, per_source: dict[str, int], broken: set[str] = frozenset(), broken_routes: set[str] = frozenset()):
        self.ids = {s: [f"{s}-{i:04d}" for i in range(n)] for s, n in per_source.items()}
        self.broken = set(broken)
        self.broken_routes = set(broken_routes)
        self.calls: list[str] = []

    def __call__(self, path: str) -> tuple[int, str]:
        self.calls.append(path)
        if path in self.broken_routes:
            return 500, '{"detail":"boom"}'
        if path.startswith("/api/v1/detections/") and "?" not in path:
            rule_id = path.rsplit("/", 1)[1]
            return (500, "Internal Server Error") if rule_id in self.broken else (200, "{}")
        if path.startswith("/api/v1/detections?"):
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(path).query)
            source = q["sources"][0]
            limit, offset = int(q["limit"][0]), int(q.get("offset", ["0"])[0])
            ids = self.ids.get(source, [])
            items = [{"id": i} for i in ids[offset:offset + limit]]
            return 200, json.dumps({"items": items, "total": len(ids), "offset": offset, "limit": limit})
        return 200, "{}"


def test_detail_ids_samples_the_requested_count():
    api = FakeAPI({"sigma": 1000})
    assert dev_db.detail_ids(api, "sigma", per_source=25) == [f"sigma-{i:04d}" for i in range(25)]
    assert len([c for c in api.calls if "sources=sigma" in c]) == 1


def test_detail_ids_pages_through_every_rule_when_unbounded():
    api = FakeAPI({"okta": 450})
    ids = dev_db.detail_ids(api, "okta", per_source=None, page=200)
    assert len(ids) == 450 and ids[-1] == "okta-0449"
    assert len([c for c in api.calls if "sources=okta" in c]) == 3


def test_detail_ids_handles_an_empty_source():
    assert dev_db.detail_ids(FakeAPI({"auth0": 0}), "auth0", per_source=25) == []


def test_run_smoke_reports_every_non_200_and_nothing_else():
    api = FakeAPI({"sigma": 30, "okta": 2}, broken={"sigma-0003"}, broken_routes={"/api/v1/mitre/stats"})
    lines: list[str] = []
    failures = dev_db.run_smoke(api, per_source=25, sources=("sigma", "okta"),
                                routes=("/api/health", "/api/v1/mitre/stats"), log=lines.append)
    assert [(p, s) for p, s, _ in failures] == [("/api/v1/mitre/stats", 500), ("/api/v1/detections/sigma-0003", 500)]
    assert failures[1][2] == "Internal Server Error"
    assert any("27 detail pages swept" in line for line in lines)


def test_run_smoke_is_clean_on_a_healthy_corpus():
    api = FakeAPI({"sigma": 5, "okta": 5})
    assert dev_db.run_smoke(api, per_source=None, sources=("sigma", "okta"), routes=("/api/health",), log=lambda _: None) == []
