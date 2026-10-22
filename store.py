"""SQLite access shared by sync.py (writes) and serve.py (reads). Stdlib only.

Config files (settings.json, servers.json, sites.json, .env) are read from INFRA_CONFIG_DIR (default: this folder),
the database lives in INFRA_DATA_DIR (default: ./data).
"""
import json
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONF = Path(os.environ.get("INFRA_CONFIG_DIR", ROOT))
DATA = Path(os.environ.get("INFRA_DATA_DIR", ROOT / "data"))
DB = DATA / "infra.db"


def connect():
    DATA.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript((ROOT / "schema.sql").read_text())
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    for col in ("kind", "code"):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
    return conn


def load_env():
    env = {}
    path = CONF / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def config(name):
    p = CONF / name
    if not p.exists():
        return {}
    return json.loads(p.read_text())


DEFAULT_SETTINGS = {
    "title": "Infra Dashboard", "subtitle": "servers · sites · apps", "port": 8796,
    "jump_host": None, "ssh_world_ok": [], "expected_public_ports": [80, 443],
    "google": {"python": "~/.config/infra-dashboard/google-venv/bin/python",
               "service_account_json": "~/.config/infra-dashboard/google-service-account.json",
               "ga4_properties": "ga4-properties.json"},
    "appstore": {"python": "~/.config/infra-dashboard/asc-venv/bin/python",
                 "config": "~/.config/infra-dashboard/appstore.json"},
}


def settings():
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    for k, v in config("settings.json").items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(s.get(k), dict):
            s[k].update(v)
        else:
            s[k] = v
    return s


def _j(v, default=None):
    if v is None:
        return default
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


def _row(r):
    return dict(r) if r is not None else None


def latest_with(conn, table, where="", args=()):
    """Highest sync_id that has rows in `table` (optionally matching where)."""
    r = conn.execute(f"SELECT MAX(sync_id) FROM {table} {'WHERE ' + where if where else ''}", args).fetchone()
    return r[0]


def sync_time(conn, sync_id):
    r = conn.execute("SELECT finished_at, started_at FROM syncs WHERE id=?", (sync_id,)).fetchone()
    return (r["finished_at"] or r["started_at"]) if r else None


def latest_state(conn):
    """Everything the page needs, from the freshest data of each kind."""
    env = load_env()
    cfg = config("servers.json") or {"servers": {}}
    sites_cfg = config("sites.json") or {"sites": []}
    st = settings()
    out = {
        "config": {"hetzner_token": bool(env.get("HETZNER_API_TOKEN")),
                   "cloudflare_token": bool(env.get("CLOUDFLARE_API_TOKEN")),
                   "title": st["title"], "subtitle": st["subtitle"], "jump_host": st["jump_host"],
                   "ssh_world_ok": st["ssh_world_ok"]},
        "links": cfg.get("links", []),
        "syncs": [_row(r) for r in conn.execute(
            "SELECT id, started_at, finished_at, mode, status FROM syncs ORDER BY id DESC LIMIT 15")],
    }
    last = conn.execute("SELECT * FROM syncs ORDER BY id DESC LIMIT 1").fetchone()
    out["last_sync"] = dict(last, log=_j(last["log"], [])) if last else None

    # Servers: Hetzner view + latest probe of each box.
    sid = latest_with(conn, "servers")
    servers = []
    if sid:
        for r in conn.execute("SELECT * FROM servers WHERE sync_id=?", (sid,)):
            s = dict(r)
            s["private_ips"] = _j(s["private_ips"], [])
            s["firewall_ids"] = _j(s["firewall_ids"], [])
            s["cfg"] = cfg.get("servers", {}).get(s["name"], {})
            s["api_synced_at"] = sync_time(conn, sid)
            v = conn.execute("SELECT * FROM vitals WHERE name=? ORDER BY sync_id DESC LIMIT 1", (s["name"],)).fetchone()
            if v:
                s["vitals"] = dict(v, disks=_j(v["disks"], []), synced_at=sync_time(conn, v["sync_id"]))
            c = conn.execute("SELECT * FROM checks WHERE name=? ORDER BY sync_id DESC LIMIT 1", (s["name"],)).fetchone()
            s["checks"] = _j(c["data"], {}) if c else None
            s["metrics"] = [list(m) for m in conn.execute(
                "SELECT ts, cpu, disk_read, disk_write, net_in, net_out FROM metrics "
                "WHERE server=? AND ts >= (SELECT MAX(ts) FROM metrics WHERE server=?) - 7*86400 ORDER BY ts",
                (s["name"], s["name"]))]
            servers.append(s)
    servers.sort(key=lambda s: s["cfg"].get("order", 99))
    out["servers"] = servers

    fid = latest_with(conn, "firewalls")
    out["firewalls"] = [dict(dict(r), applied_to=_j(r["applied_to"], []), rules=_j(r["rules"], []))
                        for r in conn.execute("SELECT * FROM firewalls WHERE sync_id=?", (fid,))] if fid else []

    out["resources"] = {}
    for r in conn.execute("SELECT kind, MAX(sync_id) AS sid FROM resources GROUP BY kind"):
        row = conn.execute("SELECT data FROM resources WHERE kind=? AND sync_id=?", (r["kind"], r["sid"])).fetchone()
        out["resources"][r["kind"]] = _j(row["data"])

    fsid = latest_with(conn, "findings")
    prev = conn.execute("SELECT MAX(sync_id) FROM findings WHERE sync_id < ?", (fsid or 0,)).fetchone()[0]
    prev_keys = {r[0] for r in conn.execute("SELECT key FROM findings WHERE sync_id=?", (prev,))} if prev else set()
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out["findings"] = sorted(
        [dict(dict(r), new=bool(prev) and r["key"] not in prev_keys)
         for r in conn.execute("SELECT * FROM findings WHERE sync_id=?", (fsid,))] if fsid else [],
        key=lambda f: (order.get(f["severity"], 9), f["scope"] or "", f["title"] or ""))
    out["resolved"] = sorted(prev_keys - {f["key"] for f in out["findings"]}) if prev else []
    now = conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')").fetchone()[0]
    acks = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM acks")}
    for f in out["findings"]:
        a = acks.get(f["key"])
        f["ack"] = a if a and (not a["until"] or a["until"] > now) else None
    out["events"] = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT 400")]

    # Websites.
    sites = []
    for site in sites_cfg.get("sites", []):
        d = {"cfg": site, "domain": site["domain"]}
        for src in ("http", "gsc", "ga4", "cloudflare"):
            r = conn.execute("SELECT sync_id, data FROM sites WHERE domain=? AND source=? ORDER BY sync_id DESC LIMIT 1",
                             (site["domain"], src)).fetchone()
            if r:
                d[src] = _j(r["data"], {})
                d[src]["synced_at"] = sync_time(conn, r["sync_id"])
        d["daily"] = {}
        for r in conn.execute("SELECT date, source, metric, value FROM site_daily WHERE domain=? "
                              "AND date >= date('now', '-120 days') ORDER BY date", (site["domain"],)):
            d["daily"].setdefault(f"{r['source']}.{r['metric']}", []).append([r["date"], r["value"]])
        sites.append(d)
    out["sites"] = sites

    apps = []
    for app in sites_cfg.get("apps", []):
        a = {"cfg": app, "id": app["id"]}
        r = conn.execute("SELECT sync_id, data FROM apps WHERE app_id=? ORDER BY sync_id DESC LIMIT 1", (app["id"],)).fetchone()
        if r:
            a["info"] = _j(r["data"], {})
            a["synced_at"] = sync_time(conn, r["sync_id"])
        a["daily"] = [list(x) for x in conn.execute(
            "SELECT date, downloads, redownloads, updates, iap FROM app_daily WHERE app_id=? "
            "AND date >= date('now', '-120 days') ORDER BY date", (app["id"],))]
        apps.append(a)
    out["apps"] = apps
    out["asc_days"] = conn.execute("SELECT COUNT(*), MAX(date) FROM asc_days WHERE status IN ('ok','none')").fetchone()[:]
    return out


def history(conn, server, days=30):
    """RAM / disk / load per sync for one server (trend charts)."""
    rows = conn.execute(
        "SELECT s.finished_at AS t, v.mem_total, v.mem_available, v.swap_total, v.swap_used, v.disk_total, v.disk_used, v.load1 "
        "FROM vitals v JOIN syncs s ON s.id=v.sync_id WHERE v.name=? AND v.ok=1 "
        "AND s.finished_at >= datetime('now', ?) ORDER BY v.sync_id", (server, f"-{int(days)} days"))
    return [dict(r) for r in rows]
