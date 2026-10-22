#!/usr/bin/env python3
"""Collect the latest infra data into data/infra.db. Read-only everywhere.

    python3 sync.py                  # everything: Hetzner API, SSH probe of each box, websites, Google, App Store, Cloudflare
    python3 sync.py --api-only       # everything except SSH
    python3 sync.py --host web-1     # Hetzner API + SSH probe of one box only
    python3 sync.py --skip google,asc,cloudflare,sites,ssh
    python3 sync.py --suggest-servers   # print a servers.json draft from the Hetzner API + ~/.ssh/config

Prints one JSON line per step on stdout (serve.py streams these to the page).
SSH runs strictly one box after another: fail2ban on a box (or on a shared jump host) bans bursts of connections.
"""
import argparse
import datetime as dt
import fcntl
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import store

ROOT = store.ROOT
HETZNER = "https://api.hetzner.cloud/v1"
CF = "https://api.cloudflare.com/client/v4"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
SETTINGS = store.settings()
GSC_PY = Path(SETTINGS["google"]["python"]).expanduser()
ASC_PY = Path(SETTINGS["appstore"]["python"]).expanduser()
EXPECTED_WORLD_PORTS = set(SETTINGS.get("expected_public_ports") or [80, 443])
SSH_WORLD_OK = set(SETTINGS.get("ssh_world_ok") or [])   # server names allowed to expose SSH to the internet (a jump host)
LOG = []


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def step(name, state, detail=""):
    e = {"t": now(), "step": name, "state": state, "detail": str(detail)[:400]}
    if state != "run":
        LOG.append(e)
    print(json.dumps(e), flush=True)


# ---------------------------------------------------------------- Hetzner API

class Hetzner:
    def __init__(self, token):
        self.token = token

    def get(self, path, params=None):
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        req = urllib.request.Request(HETZNER + path + q, headers={"Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def all(self, path, key, params=None):
        items, page = [], 1
        while page:
            d = self.get(path, {**(params or {}), "page": page, "per_page": 50})
            items += d.get(key, [])
            page = (d.get("meta") or {}).get("pagination", {}).get("next_page")
        return items


def price_for(prices, location):
    for p in prices or []:
        if p.get("location") == location:
            return float(p["price_monthly"]["net"])
    return None


def collect_hetzner(conn, sid, api):
    servers = api.all("/servers", "servers")
    pricing = api.get("/pricing")["pricing"]
    backup_pct = float(pricing["server_backup"]["percentage"]) / 100
    ipv4_price = {p["location"]: float(p["price_monthly"]["net"])
                  for t in pricing["primary_ips"] if t["type"] == "ipv4" for p in t["prices"]}
    # The API only knows today's list prices. Servers created earlier keep their original (often lower)
    # price, which the API does not expose; an optional "price_eur" per server in servers.json overrides it.
    overrides = {n: c.get("price_eur") for n, c in (store.config("servers.json").get("servers") or {}).items() if c.get("price_eur")}
    cost = {"servers": 0.0, "backups": 0.0, "ipv4": 0.0, "images": 0.0, "currency": pricing["currency"],
            "per_server": {}, "price_source": {}, "list_price": {}}
    for s in servers:
        st, loc = s["server_type"], s["location"]
        list_price = price_for(st.get("prices"), loc["name"]) or 0.0
        price = float(overrides.get(s["name"]) or list_price)
        cost["price_source"][s["name"]] = "override" if s["name"] in overrides else "list"
        cost["list_price"][s["name"]] = list_price
        backups = s.get("backup_window") is not None
        ip4 = (s["public_net"].get("ipv4") or {}).get("ip")
        server_cost = price + (price * backup_pct if backups else 0) + (ipv4_price.get(loc["name"], 0.5) if ip4 else 0)
        cost["servers"] += price
        cost["backups"] += price * backup_pct if backups else 0
        cost["ipv4"] += ipv4_price.get(loc["name"], 0.5) if ip4 else 0
        cost["per_server"][s["name"]] = round(server_cost, 2)
        conn.execute("INSERT OR REPLACE INTO servers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            sid, s["name"], s["id"], s["status"], st["name"], st.get("cpu_type"), st["cores"], st["memory"],
            s.get("primary_disk_size") or st.get("disk"), loc["name"], loc.get("city"), loc.get("country"),
            loc.get("network_zone"), loc.get("latitude"), loc.get("longitude"), ip4,
            (s["public_net"].get("ipv6") or {}).get("ip"), json.dumps([p["ip"] for p in s.get("private_net", [])]),
            s.get("ingoing_traffic"), s.get("outgoing_traffic"), s.get("included_traffic"), round(server_cost, 2),
            int(backups), s.get("backup_window"), int(s["protection"]["delete"]), int(s["protection"]["rebuild"]),
            json.dumps([f["id"] for f in s["public_net"].get("firewalls", [])]),
            (s.get("image") or {}).get("description"), s.get("created")))
    step("Hetzner servers", "ok", f"{len(servers)} servers")

    fws = api.all("/firewalls", "firewalls")
    names = {s["id"]: s["name"] for s in servers}
    for f in fws:
        applied = [names.get(a.get("server", {}).get("id"), a.get("label_selector") or a.get("type")) for a in f["applied_to"]]
        conn.execute("INSERT OR REPLACE INTO firewalls VALUES (?,?,?,?,?)",
                     (sid, f["id"], f["name"], json.dumps(applied), json.dumps(f["rules"])))
    images = api.all("/images", "images", {"type": "snapshot"}) + api.all("/images", "images", {"type": "backup"})
    img_price = float(pricing["image"]["price_per_gb_month"]["net"])
    cost["images"] = sum((i.get("image_size") or 0) * img_price for i in images if i["type"] == "snapshot")
    cost["total"] = round(cost["servers"] + cost["backups"] + cost["ipv4"] + cost["images"], 2)
    for k in ("servers", "backups", "ipv4", "images"):
        cost[k] = round(cost[k], 2)
    res = {
        "networks": [{"name": n["name"], "ip_range": n["ip_range"], "servers": [names.get(i, i) for i in n["servers"]],
                      "subnets": [x["ip_range"] for x in n["subnets"]]} for n in api.all("/networks", "networks")],
        "volumes": [{"name": v["name"], "size": v["size"], "server": names.get(v.get("server")), "location": v["location"]["name"]}
                    for v in api.all("/volumes", "volumes")],
        "images": [{"type": i["type"], "description": i["description"], "created": i["created"], "size_gb": i.get("image_size"),
                    "disk_gb": i.get("disk_size"), "server": (i.get("created_from") or {}).get("name")} for i in images],
        "primary_ips": [{"ip": p["ip"], "type": p["type"], "server": names.get(p.get("assignee_id")),
                         "location": (p.get("location") or {}).get("name"), "blocked": p.get("blocked")}
                        for p in api.all("/primary_ips", "primary_ips")],
        "ssh_keys": [{"name": k["name"], "fingerprint": k["fingerprint"], "created": k["created"]}
                     for k in api.all("/ssh_keys", "ssh_keys")],
        "load_balancers": [{"name": lb["name"], "type": lb["load_balancer_type"]["name"]}
                           for lb in api.all("/load_balancers", "load_balancers")],
        "cost": cost,
    }
    for kind, data in res.items():
        conn.execute("INSERT OR REPLACE INTO resources VALUES (?,?,?)", (sid, kind, json.dumps(data)))
    step("Hetzner firewalls & storage", "ok", f"{len(fws)} firewalls, {len(images)} images, €{cost['total']}/mo")

    end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start = end - dt.timedelta(days=7)
    for s in servers:
        try:
            m = api.get(f"/servers/{s['id']}/metrics", {"type": "cpu,disk,network", "start": start.isoformat(),
                                                         "end": end.isoformat(), "step": 1800})["metrics"]["time_series"]
        except Exception as e:
            step(f"Metrics {s['name']}", "warn", e)
            continue
        cols = ["cpu", "disk.0.bandwidth.read", "disk.0.bandwidth.write", "network.0.bandwidth.in", "network.0.bandwidth.out"]
        by_ts = {}
        for i, c in enumerate(cols):
            for ts, val in (m.get(c) or {}).get("values", []):
                by_ts.setdefault(int(ts), [None] * 5)[i] = float(val) if val not in (None, "NaN") else None
        conn.executemany("INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?,?)",
                         [(s["name"], ts, *v) for ts, v in by_ts.items()])
    step("Hetzner metrics", "ok", "7 days, 30-min steps")
    conn.execute("INSERT OR REPLACE INTO raw VALUES (?,?,?)", (sid, "hetzner.servers", json.dumps(servers)))
    return servers


def collect_static_servers(conn, sid):
    """Servers without the Hetzner API (any provider): take what servers.json says about them."""
    servers = store.config("servers.json").get("servers") or {}
    for name, c in servers.items():
        conn.execute("INSERT OR REPLACE INTO servers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            sid, name, None, c.get("status", "running"), c.get("type", c.get("provider", "server")), None,
            c.get("cores"), c.get("memory_gb"), c.get("disk_gb"), c.get("location"), c.get("city"), c.get("country"),
            None, c.get("lat"), c.get("lon"), c.get("ipv4"), c.get("ipv6"), json.dumps(c.get("private_ips", [])),
            None, None, None, c.get("price_eur"), None, None, None, None, "[]", c.get("image"), None))
    prices = {n: c.get("price_eur") for n, c in servers.items() if c.get("price_eur")}
    if prices:
        conn.execute("INSERT OR REPLACE INTO resources VALUES (?,?,?)", (sid, "cost", json.dumps({
            "servers": round(sum(prices.values()), 2), "backups": 0, "ipv4": 0, "images": 0, "currency": "EUR",
            "per_server": prices, "price_source": {n: "override" for n in prices}, "total": round(sum(prices.values()), 2)})))
    step("Servers (servers.json)", "ok", f"{len(servers)} servers, no Hetzner API token")


def suggest_servers():
    """Print a servers.json draft: Hetzner servers (if a token is set) matched to Host aliases in ~/.ssh/config."""
    aliases, host = {}, None
    cfgfile = Path.home() / ".ssh" / "config"
    for line in (cfgfile.read_text().splitlines() if cfgfile.exists() else []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "host":
            host = parts[1].split()[0]
        elif len(parts) == 2 and parts[0].lower() == "hostname" and host:
            aliases[parts[1].strip()] = host
    env = store.load_env()
    out = {"servers": {}, "links": []}
    if env.get("HETZNER_API_TOKEN"):
        for i, srv in enumerate(Hetzner(env["HETZNER_API_TOKEN"]).all("/servers", "servers"), 1):
            ip = (srv["public_net"].get("ipv4") or {}).get("ip")
            out["servers"][srv["name"]] = {"ssh": aliases.get(ip, ip or ""), "role": "", "product": "", "order": i}
    else:
        for i, (ip, alias) in enumerate(aliases.items(), 1):
            out["servers"][alias] = {"ssh": alias, "ipv4": ip, "role": "", "product": "", "order": i}
    print(json.dumps(out, indent=2))


def collect_status_feed(conn, sid):
    try:
        req = urllib.request.Request("https://status.hetzner.com/en.atom", headers={"User-Agent": BROWSER_UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            root = ET.fromstring(r.read())
    except Exception as e:
        step("Hetzner status page", "warn", e)
        return
    ns = {"a": "http://www.w3.org/2005/Atom"}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=14)
    words = re.compile(r"cloud|nbg1|fsn1|ash|nuremberg|falkenstein|ashburn|storage box|object storage|console|api", re.I)
    items = []
    for e in root.findall("a:entry", ns):
        updated = dt.datetime.fromisoformat(e.findtext("a:updated", "", ns))
        if updated < cutoff:
            continue
        content = ET.tostring(e.find("a:content", ns), encoding="unicode", method="text") if e.find("a:content", ns) is not None else ""
        text = re.sub(r"\s+", " ", content).strip()
        start = re.search(r"Start:\s*(\S+)", text)
        end = re.search(r"(?:\bEnd|Ends on|Estimated end):\s*(\S+)", text, re.I)
        cat = (e.find("a:category", ns).get("term") if e.find("a:category", ns) is not None else "")
        title = e.findtext("a:title", "", ns)
        items.append({"title": title, "link": (e.find("a:link", ns).get("href") if e.find("a:link", ns) is not None else ""),
                      "updated": updated.isoformat(), "category": cat, "start": start and start.group(1),
                      "end": end and end.group(1), "relevant": bool(words.search(title + " " + cat + " " + text[:400])),
                      "summary": re.sub(r"^(Start|End|Ends on|Estimated end):\s*\S+\s*", "", text)[:300]})
    conn.execute("INSERT OR REPLACE INTO resources VALUES (?,?,?)", (sid, "status_feed", json.dumps(items)))
    step("Hetzner status page", "ok", f"{len(items)} notices in the last 14 days")


# ---------------------------------------------------------------- SSH probe

def sections(text):
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            out[cur] = []
        elif cur:
            out[cur].append(line.rstrip())
    return out


def parse_listen(lines):
    res = []
    for line in lines:
        parts = line.split(" ", 1)
        if not parts or ":" not in parts[0]:
            continue
        addr, _, port = parts[0].rpartition(":")
        addr = addr.split("%")[0].strip("[]")
        proc = re.search(r'\(\("([^",]+)', parts[1] if len(parts) > 1 else "")
        if not port.isdigit():
            continue
        local = addr in ("127.0.0.1", "::1", "localhost") or addr.startswith("127.")
        private = addr.startswith("10.") or addr.startswith("192.168.") or addr.startswith("172.")
        res.append({"addr": addr, "port": int(port), "proc": proc.group(1) if proc else "",
                    "scope": "local" if local else ("private" if private else "public")})
    return res


def parse_probe(text):
    s = sections(text)
    if "end" not in s:
        raise RuntimeError("probe output incomplete")
    v, c = {}, {}
    host = s.get("host", [])
    v["hostname"], v["kernel"], v["os"] = (host + ["", "", ""])[:3]
    v["uptime_s"] = int(float(s["uptime"][0].split()[0])) if s.get("uptime") else None
    load = s.get("load", [])
    if load:
        l = load[0].split()
        v["load1"], v["load5"], v["load15"] = float(l[0]), float(l[1]), float(l[2])
        v["cpus"] = int(load[1]) if len(load) > 1 and load[1].isdigit() else None
    for line in s.get("mem", []):
        p = line.split()
        if p and p[0] == "Mem:":
            v["mem_total"], v["mem_used"], v["mem_available"] = int(p[1]), int(p[2]), int(p[6])
        elif p and p[0] == "Swap:":
            v["swap_total"], v["swap_used"] = int(p[1]), int(p[2])
    disks = []
    for line in s.get("disk", [])[1:]:
        p = line.split()
        if len(p) >= 6 and p[1].isdigit():
            disks.append({"fs": p[0], "total": int(p[1]), "used": int(p[2]), "avail": int(p[3]), "mount": " ".join(p[5:])})
    v["disks"] = disks
    root = next((d for d in disks if d["mount"] == "/"), disks[0] if disks else None)
    v["disk_total"], v["disk_used"] = (root["total"], root["used"]) if root else (None, None)
    v["reboot_required"] = int((s.get("reboot") or ["no"])[0] == "yes")
    up = (s.get("updates") or [""])[0].split()
    v["updates"], v["security_updates"] = (int(up[0]), int(up[1])) if len(up) == 2 else (None, None)

    st = (s.get("aptstamp") or [""])[0]
    c["apt_last_update"] = int(st) if st.isdigit() else None
    c["services"] = {p[0]: {"active": p[1], "enabled": p[2] if len(p) > 2 else ""}
                     for p in (l.split() for l in s.get("services", [])) if len(p) >= 2}
    c["failed_units"] = [l for l in s.get("failed", []) if l]
    ufw = s.get("ufw", [])
    c["ufw"] = {"status": ("active" if any(l.startswith("Status: active") for l in ufw)
                           else "inactive" if ufw or "ufw" in c["services"] else "not installed"),
                "default": next((l.split(":", 1)[1].strip() for l in ufw if l.startswith("Default:")), ""),
                "rules": [re.sub(r"\s{2,}", " | ", l.strip()) for l in ufw
                          if l and not l.startswith(("Status", "Logging", "Default", "New profiles", "To ", "--"))]}
    c["fail2ban"] = [{"jail": p[0], "banned": int(p[1]), "total": int(p[2])}
                     for p in (l.split() for l in s.get("f2b", [])) if len(p) == 3]
    c["sshd"] = dict(l.split(" ", 1) for l in s.get("sshd", []) if " " in l)
    c["tcp"] = parse_listen(s.get("ports", []))
    c["udp"] = parse_listen(s.get("udp", []))
    certs = []
    for line in s.get("certs", []):
        name, _, rest = line.partition(" ")
        try:
            exp = dt.datetime.strptime(re.sub(r"\s+", " ", rest.strip()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            certs.append({"name": name, "expires": exp.strftime("%Y-%m-%d"),
                          "days": (exp - dt.datetime.now(dt.timezone.utc)).days})
        except ValueError:
            pass
    c["certs"] = certs
    c["docker"] = [dict(zip(("name", "status", "image"), l.split("|", 2))) for l in s.get("docker", []) if "|" in l]
    pm2 = []
    for l in s.get("pm2", []):
        p = l.split("|")
        if len(p) == 6:
            pm2.append({"name": p[0], "status": p[1], "mem": int(float(p[2] or 0)), "cpu": float(p[3] or 0),
                        "restarts": int(float(p[4] or 0)), "uptime_s": int(float(p[5] or 0))})
    c["pm2"] = pm2
    c["last_logins"] = [l for l in s.get("lastlogin", []) if l.strip()]
    c["php"] = [dict(zip(("kind", "name", "version"), l.split("|", 2))) for l in s.get("php", []) if l.count("|") == 2]
    c["node"] = [{"path": x[0], "version": x[1].lstrip("v"), "procs": int(x[2] or 0)} for x in (l.split("|") for l in s.get("node", [])) if len(x) == 3 and x[1]]
    mg = []
    for l in s.get("memgroups", []):
        p = l.rsplit("|", 3)
        if len(p) == 4 and p[1].isdigit():
            kind, _, name = p[0].partition(":")
            mg.append({"kind": kind, "name": name, "pss": int(p[1]) * 1024, "swap": int(p[2]) * 1024, "procs": int(p[3])})
    c["memgroups"] = mg
    return v, c


# Optional jump host (settings.json "jump_host", an ssh alias). All hops share ONE connection to it for the whole
# sync: a jump host with a ufw LIMIT rule refuses the 6th new SSH connection within 30 s, and every ProxyJump counts.
# The socket path is fixed (no %C) so the ProxyCommand below can reuse it without escaping.
JUMP = SETTINGS.get("jump_host") or ""
MUX_PATH = str(Path.home() / ".ssh" / "infra-dash-jump.sock")
MUX = ["-o", "ControlMaster=auto", "-o", f"ControlPath={MUX_PATH}", "-o", "ControlPersist=60"]


def ssh_base(cfg):
    base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12", "-o", "ServerAliveInterval=10"]
    if JUMP and cfg["ssh"] == JUMP:
        return base + MUX + [cfg["ssh"]]
    if cfg.get("jump"):
        # Overrides the ProxyJump from ~/.ssh/config with the same hop, but through the shared socket.
        hop = f"ssh -o BatchMode=yes -o ConnectTimeout=12 {' '.join(MUX)} -W %h:%p {cfg['jump']}"
        return base + ["-o", f"ProxyCommand={hop}", cfg["ssh"]]
    return base + [cfg["ssh"]]


def open_mux():
    """Start the shared jump-host connection up front, detached, so no later ssh forks a master
    that keeps our output pipe open."""
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12", "-o", "ControlMaster=yes",
                    "-o", f"ControlPath={MUX_PATH}", "-o", "ControlPersist=120", "-fN", JUMP],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def close_mux():
    if not JUMP:
        return
    subprocess.run(["ssh", "-o", f"ControlPath={MUX_PATH}", "-O", "exit", JUMP], capture_output=True, timeout=15)


def probe(name, cfg):
    script = (ROOT / "collect.sh").read_text()
    base = ssh_base(cfg)
    if cfg.get("via_host"):
        inner = f"ssh -o BatchMode=yes -o ConnectTimeout=10 -i {cfg['via_key']} {cfg['via_host']} bash -s"
        cmd = base + [inner]
    else:
        cmd = base + ["bash -s"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=120)
    if "@@end" not in r.stdout:
        err = "\n".join(l for l in r.stderr.splitlines() if not l.startswith("**")).strip()
        raise RuntimeError(err or f"ssh exited {r.returncode}")
    return r.stdout


VITAL_COLS = ["hostname", "os", "kernel", "uptime_s", "cpus", "load1", "load5", "load15", "mem_total", "mem_used",
              "mem_available", "swap_total", "swap_used", "disk_total", "disk_used", "disks", "updates",
              "security_updates", "reboot_required"]


def collect_ssh(conn, sid, only=None):
    cfg = {n: c for n, c in (store.config("servers.json").get("servers") or {}).items() if c.get("ssh")}
    names = sorted(cfg, key=lambda n: cfg[n].get("order", 99))
    if only:
        names = [n for n in names if n.lower() == only.lower()]
        if not names:
            step("SSH", "fail", f"no server named {only} in servers.json")
            return
    if JUMP and any(cfg[n]["ssh"] == JUMP or cfg[n].get("jump") for n in names):
        try:
            open_mux()
        except subprocess.TimeoutExpired:
            pass
    for name in names:                       # strictly serial, never parallel
        step(f"SSH {name}", "run", cfg[name]["ssh"] + (f" → {cfg[name]['via_host']}" if cfg[name].get("via_host") else ""))
        t0 = time.time()
        try:
            text = probe(name, cfg[name])
            v, c = parse_probe(text)
            v["disks"] = json.dumps(v["disks"])
            conn.execute(f"INSERT OR REPLACE INTO vitals (sync_id, name, ok, {', '.join(VITAL_COLS)}) "
                         f"VALUES (?, ?, 1, {', '.join('?' * len(VITAL_COLS))})", (sid, name, *[v.get(k) for k in VITAL_COLS]))
            conn.execute("INSERT OR REPLACE INTO checks VALUES (?,?,?)", (sid, name, json.dumps(c)))
            conn.execute("INSERT OR REPLACE INTO raw VALUES (?,?,?)", (sid, f"probe.{name}", text))
            mem = 100 * (1 - v["mem_available"] / v["mem_total"]) if v.get("mem_total") else 0
            step(f"SSH {name}", "ok", f"RAM {mem:.0f}% · disk {100 * v['disk_used'] / v['disk_total']:.0f}% · {time.time() - t0:.1f}s")
        except Exception as e:
            conn.execute("INSERT OR REPLACE INTO vitals (sync_id, name, ok, error) VALUES (?,?,0,?)", (sid, name, str(e)[:300]))
            step(f"SSH {name}", "fail", e)
        conn.commit()
    close_mux()


# ---------------------------------------------------------------- Websites

def tls_expiry(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {"expires": exp.strftime("%Y-%m-%d"), "days": (exp - dt.datetime.now(dt.timezone.utc)).days,
            "issuer": issuer.get("organizationName", "")}


def http_check(url):
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA, "Accept": "text/html,*/*"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read(200_000)
            code, final, headers = r.status, r.geturl(), r.headers
    except urllib.error.HTTPError as e:
        code, final, headers = e.code, url, e.headers
    except Exception as e:
        return {"url": url, "ok": False, "error": str(e)[:200], "ms": int((time.time() - t0) * 1000)}
    challenged = (headers.get("cf-mitigated") or "").lower() == "challenge"
    # Up = the server answered (< 500). A Cloudflare bot challenge means the site is up but blocks scripts.
    note = "Cloudflare bot check (browsers pass)" if challenged else (
        f"answers HTTP {code}" if code >= 400 else "")
    return {"url": url, "ok": code < 500 or challenged, "status": code, "final": final,
            "ms": int((time.time() - t0) * 1000), "note": note,
            "server": headers.get("Server", ""), "cloudflare": bool(headers.get("CF-RAY"))}


def collect_sites(conn, sid):
    sites = (store.config("sites.json").get("sites") or [])
    bad = 0
    for site in sites:
        checks, tls = [], {}
        for url in site.get("check", []):
            checks.append(http_check(url))
            host = urllib.parse.urlsplit(url).hostname
            if host not in tls:
                try:
                    tls[host] = tls_expiry(host)
                except Exception as e:
                    tls[host] = {"error": str(e)[:200]}
        bad += sum(1 for c in checks if not c["ok"])
        conn.execute("INSERT OR REPLACE INTO sites VALUES (?,?,?,?)",
                     (sid, site["domain"], "http", json.dumps({"checks": checks, "tls": tls})))
    step("Websites up + TLS", "ok" if not bad else "warn", f"{sum(len(s.get('check', [])) for s in sites)} URLs, {bad} failing")


def run_collector(py, script, payload, timeout):
    r = subprocess.run([str(py), str(ROOT / "collectors" / script)], input=json.dumps(payload),
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1])
    return json.loads(r.stdout)


def collect_google(conn, sid):
    if not GSC_PY.exists():
        step("Search Console + GA4", "skip", f"no venv at {GSC_PY}")
        return
    sites = (store.config("sites.json").get("sites") or [])
    g = SETTINGS["google"]
    props = Path(g["ga4_properties"]).expanduser()
    if not props.is_absolute():
        props = store.CONF / props
    data = run_collector(GSC_PY, "gsc_ga4.py", {"sites": sites, "days": 90,
                         "service_account_json": str(Path(g["service_account_json"]).expanduser()),
                         "ga4_properties": str(props)}, 300)
    errors = []
    for site in sites:
        d = data.get(site["domain"], {})
        for src in ("gsc", "ga4"):
            if src not in d:
                continue
            block = d[src]
            if "error" in block:
                errors.append(f"{site['domain']} {src}: {block['error']}")
            else:
                metrics = ["clicks", "impressions", "ctr", "position"] if src == "gsc" else ["users", "sessions", "views"]
                rows = [(site["domain"], row[0], src, m, row[i + 1]) for row in block.get("daily", []) for i, m in enumerate(metrics)]
                conn.executemany("INSERT OR REPLACE INTO site_daily VALUES (?,?,?,?,?)", rows)
                block = {k: v for k, v in block.items() if k != "daily"}
            conn.execute("INSERT OR REPLACE INTO sites VALUES (?,?,?,?)", (sid, site["domain"], src, json.dumps(block)))
    step("Search Console + GA4", "warn" if errors else "ok", "; ".join(errors) or f"{len(sites)} domains, 90 days")


def collect_asc(conn, sid):
    if not ASC_PY.exists():
        step("App Store Connect", "skip", f"no venv at {ASC_PY}")
        return
    apps = store.config("sites.json").get("apps", [])
    if not apps:
        step("App Store Connect", "skip", "no apps in sites.json")
        return
    have = {r[0] for r in conn.execute("SELECT date FROM asc_days WHERE status IN ('ok','none')")}
    today = dt.date.today()
    want = [str(today - dt.timedelta(days=d)) for d in range(1, 91)]
    # Re-ask the last 3 days every time (Apple publishes a day's report late), the rest only once.
    dates = [d for i, d in enumerate(want) if i < 3 or d not in have][:40]
    data = run_collector(ASC_PY, "asc.py", {"apps": [a["id"] for a in apps], "dates": dates,
                         "config": str(Path(SETTINGS["appstore"]["config"]).expanduser())}, 600)
    if "error" in data:
        raise RuntimeError(data["error"])
    for app_id, info in data.get("apps", {}).items():
        conn.execute("INSERT OR REPLACE INTO apps VALUES (?,?,?)", (sid, app_id, json.dumps(info)))
    ok = 0
    for day, rep in data.get("days", {}).items():
        conn.execute("INSERT OR REPLACE INTO asc_days VALUES (?,?,?)", (day, rep["status"], now()))
        if rep["status"] == "ok":
            ok += 1
        for a in apps:
            u = rep.get("units", {}).get(a["id"], {})
            if rep["status"] in ("ok", "none"):
                conn.execute("INSERT OR REPLACE INTO app_daily VALUES (?,?,?,?,?,?)", (
                    a["id"], day, u.get("downloads", 0), u.get("redownloads", 0), u.get("updates", 0), u.get("iap", 0)))
    step("App Store Connect", "ok", f"{len(data.get('apps', {}))} apps, {len(dates)} report days asked ({ok} with sales)")


def cf_get(token, path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    req = urllib.request.Request(CF + path + q, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def cf_graphql(token, query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(CF + "/graphql", data=body, method="POST",
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


CF_DAILY = """query($zone: String!, $since: Date!, $until: Date!) { viewer { zones(filter: {zoneTag: $zone}) {
  httpRequests1dGroups(limit: 40, filter: {date_geq: $since, date_leq: $until}, orderBy: [date_ASC]) {
    dimensions { date } sum { requests cachedRequests bytes cachedBytes threats pageViews
    responseStatusMap { edgeResponseStatus requests } } uniq { uniques } } } } }"""
# Free plans can't use firewallEventsAdaptiveGroups; raw events (last 24 h) are counted here instead.
CF_EVENTS = """query($zone: String!, $since: Time!) { viewer { zones(filter: {zoneTag: $zone}) {
  firewallEventsAdaptive(limit: 1000, filter: {datetime_geq: $since}, orderBy: [datetime_DESC]) {
    action source clientCountryName } } } }"""


def cf_zone_data(token, zone_id):
    """GraphQL data for one zone, or raises."""
    def gql(q, v):
        d = cf_graphql(token, q, v)
        if d.get("errors"):
            raise RuntimeError(d["errors"][0].get("message"))
        return ((d.get("data") or {}).get("viewer") or {}).get("zones") or [{}]
    return gql


def collect_cloudflare(conn, sid, token):
    sites = (store.config("sites.json").get("sites") or [])
    zones = {z["name"]: z for z in cf_get(token, "/zones", {"per_page": 50}).get("result", [])}
    until = dt.date.today()
    since = until - dt.timedelta(days=30)
    done, errors = 0, []
    for site in sites:
        z = zones.get(site.get("cf_zone") or "")
        if not z:
            continue
        out = {"zone_status": z.get("status"), "plan": (z.get("plan") or {}).get("name"), "paused": z.get("paused")}
        gql = cf_zone_data(token, z["id"])
        try:
            settings = {x["id"]: x.get("value") for x in cf_get(token, f"/zones/{z['id']}/settings").get("result", [])}
            out["settings"] = {k: settings.get(k) for k in ("ssl", "min_tls_version", "always_use_https", "security_level",
                                                            "automatic_https_rewrites", "tls_1_3", "browser_check")}
        except Exception as e:
            errors.append(f"{site['domain']} settings: {e}")
        try:
            groups = gql(CF_DAILY, {"zone": z["id"], "since": str(since), "until": str(until)})[0].get("httpRequests1dGroups", [])
            rows = []
            for g in groups:
                day, sm = g["dimensions"]["date"], g["sum"]
                for m in ("requests", "cachedRequests", "bytes", "threats", "pageViews"):
                    rows.append((site["domain"], day, "cf", m, sm.get(m)))
                rows.append((site["domain"], day, "cf", "uniques", g["uniq"]["uniques"]))
                st = sm.get("responseStatusMap") or []
                rows.append((site["domain"], day, "cf", "status4xx", sum(x["requests"] for x in st if 400 <= x["edgeResponseStatus"] < 500)))
                rows.append((site["domain"], day, "cf", "status5xx", sum(x["requests"] for x in st if x["edgeResponseStatus"] >= 500)))
            conn.executemany("INSERT OR REPLACE INTO site_daily VALUES (?,?,?,?,?)", rows)
        except Exception as e:
            errors.append(f"{site['domain']} analytics: {e}")
        try:
            since_t = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            ev = gql(CF_EVENTS, {"zone": z["id"], "since": since_t})[0].get("firewallEventsAdaptive", [])
            count = lambda key: sorted(((k, sum(1 for e in ev if e.get(key) == k)) for k in {e.get(key) for e in ev}), key=lambda x: -x[1])
            out["events_24h"] = {"total": len(ev), "capped": len(ev) >= 1000, "by_action": count("action"),
                                 "by_source": count("source"), "by_country": count("clientCountryName")[:8]}
        except Exception as e:
            errors.append(f"{site['domain']} events: {e}")
        try:
            recs = cf_get(token, f"/zones/{z['id']}/dns_records", {"per_page": 200}).get("result", [])
            out["dns"] = [{"name": r["name"], "type": r["type"], "content": r["content"], "proxied": r.get("proxied")}
                          for r in recs if r["type"] in ("A", "AAAA", "CNAME")]
        except Exception as e:
            errors.append(f"{site['domain']} dns: {e}")
        conn.execute("INSERT OR REPLACE INTO sites VALUES (?,?,?,?)", (sid, site["domain"], "cloudflare", json.dumps(out)))
        done += 1
    step("Cloudflare", "warn" if errors else "ok", "; ".join(errors)[:400] or f"{done} zones, 30 days")


# ---------------------------------------------------------------- Findings

def port_rules(rules, port):
    """Sources of inbound TCP rules covering `port` in a Hetzner firewall."""
    srcs = []
    for r in rules:
        if r["direction"] != "in" or r["protocol"] not in ("tcp", "any"):
            continue
        p = r.get("port")
        if p in (None, "any"):
            hit = True
        elif "-" in str(p):
            a, b = str(p).split("-")
            hit = int(a) <= port <= int(b)
        else:
            hit = int(p) == port
        if hit:
            srcs += r.get("source_ips", [])
    return srcs


# Codes that mean "something is wrong right now" (health). Everything else is setup to tidy (hygiene).
HEALTH_CODES = {"status", "probe-failed", "ram", "swap", "disk", "s3fs-ram", "failed", "pm2", "docker", "site-down",
                "tls", "cf-5xx", "traffic", "world-ports", "no-cloud-fw", "ssh-world"}


PHP_LATEST = {}


def php_latest(branch):
    """Newest release of a PHP branch (e.g. '8.5') from php.net, cached per sync."""
    if branch not in PHP_LATEST:
        try:
            req = urllib.request.Request(f"https://www.php.net/releases/?json&version={branch}", headers={"User-Agent": BROWSER_UA})
            with urllib.request.urlopen(req, timeout=15) as r:
                PHP_LATEST[branch] = json.load(r).get("version")
        except Exception:
            PHP_LATEST[branch] = None
    return PHP_LATEST[branch]


NODE_INDEX = None
NODE_SUPPORTED = {22, 24, 26}   # majors nodejs.org still patches (2026-10); update when a line ends


def node_releases():
    global NODE_INDEX
    if NODE_INDEX is None:
        try:
            with urllib.request.urlopen(urllib.request.Request("https://nodejs.org/dist/index.json", headers={"User-Agent": BROWSER_UA}), timeout=20) as r:
                NODE_INDEX = [{"v": x["version"].lstrip("v"), "security": bool(x.get("security"))} for x in json.load(r)]
        except Exception:
            NODE_INDEX = []
    return NODE_INDEX


PHP_SUPPORTED = {"8.2", "8.3", "8.4", "8.5"}   # branches php.net still patches (2026-10); update when a branch ends


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def compute_findings(conn, sid):
    state = store.latest_state(conn)
    fw_by_id = {f["hetzner_id"]: f for f in state["firewalls"]}
    out = []

    servers_named = {x["name"] for x in state["servers"]}

    def add(key, sev, scope, title, detail, fix, kind=None):
        head, _, rest = key.partition(":")
        code = rest.split(":")[0] if head in servers_named else {"site": "site-down"}.get(head, head)
        if kind is None:
            kind = "health" if code in HEALTH_CODES else "hygiene"
        out.append((key, sev, scope, title, detail, fix, kind, code))

    for s in state["servers"]:
        n, v, c = s["name"], s.get("vitals"), s.get("checks") or {}
        fws = [fw_by_id[i] for i in s["firewall_ids"] if i in fw_by_id]
        rules = [r for f in fws for r in f["rules"]]
        if s["status"] != "running":
            add(f"{n}:status", "high", n, f"Server is {s['status']}", "Hetzner reports the server is not running.", "Check the Hetzner console.")
        hz = bool(s.get("hetzner_id"))   # firewall / backup / protection checks need the Hetzner API
        if hz and s["ipv4"] and not fws:
            add(f"{n}:no-cloud-fw", "high", n, "No Hetzner firewall", "Public IPv4 without a cloud firewall in front.",
                "Attach a Hetzner firewall that allows 22 only from your jump host / office IP, plus the public ports you need.")
        world22 = any(src in ("0.0.0.0/0", "::/0") for src in port_rules(rules, 22))
        if world22 and n not in SSH_WORLD_OK:
            add(f"{n}:ssh-world", "high", n, "SSH open to the whole internet",
                "The Hetzner firewall allows port 22 from 0.0.0.0/0.", "Limit port 22 to your jump host or office IP (a /32 rule).")
        if world22 and n in SSH_WORLD_OK:
            add(f"{n}:ssh-world", "info", n, "SSH open to the internet (expected: listed in ssh_world_ok)",
                "Mitigated by key-only login, ufw rate limit and fail2ban.", "Optional: limit to your home/office IPs.")
        if hz and s["backups"] == 0 and not s["cfg"].get("no_backups_ok"):
            add(f"{n}:no-backups", "medium", n, "Hetzner backups are off",
                "No daily server backups (20% of the server price).", "Enable backups in the console, or confirm another backup covers this box.")
        if hz and s["protect_delete"] == 0:
            add(f"{n}:no-delete-protection", "low", n, "Delete protection is off",
                "The server can be deleted with one click or API call.", "Server → Protection → enable delete + rebuild protection.")
        if s.get("traffic_included") and s.get("traffic_out"):
            pct = 100 * s["traffic_out"] / s["traffic_included"]
            if pct > 80:
                add(f"{n}:traffic", "medium", n, f"Traffic at {pct:.0f}% of included", "Outgoing traffic this billing period.",
                    "Check for unusual downloads; extra traffic is billed per TB.")
        if not v:
            if s["cfg"].get("ssh"):
                add(f"{n}:no-probe", "info", n, "No SSH health check yet", "Run a full sync.", "Click Sync.")
            continue
        if not v["ok"]:
            add(f"{n}:probe-failed", "medium", n, "SSH health check failed", v.get("error") or "", "Check SSH access from this machine (BatchMode, keys in ~/.ssh/config).")
            continue
        if v["mem_total"]:
            avail = v["mem_available"] / v["mem_total"]
            if avail < 0.10:
                add(f"{n}:ram", "high", n, f"RAM {100 * (1 - avail):.0f}% used", "Less than 10% available.", "Find the biggest process (pm2/docker) or resize.")
            elif avail < 0.20:
                add(f"{n}:ram", "medium", n, f"RAM {100 * (1 - avail):.0f}% used", "Less than 20% available.", "Watch the trend; restart leaking processes or resize.")
        s3 = [g for g in c.get("memgroups", []) if g["name"] == "s3fs"]
        if s3 and v.get("mem_total") and (s3[0]["pss"] + s3[0]["swap"]) > 0.2 * v["mem_total"]:
            g = s3[0]
            add(f"{n}:s3fs-ram", "medium", n, f"s3fs bucket mounts use {(g['pss'] + g['swap']) / 2**30:.1f} GB",
                f"{g['procs']} s3fs processes: {g['pss'] / 2**30:.1f} GB RAM + {g['swap'] / 2**30:.1f} GB swap. Their stat caches grow without a limit.",
                "Add `max_stat_cache_size=20000,stat_cache_expire=900` to the s3fs lines in /etc/fstab (applies on remount).")
        if v.get("swap_total") and v["swap_used"] / v["swap_total"] > 0.8:
            add(f"{n}:swap", "medium", n, f"Swap {100 * v['swap_used'] / v['swap_total']:.0f}% full",
                "The box has been short of RAM and pushed memory to disk.", "Restart the process that grew (often the Node API) or add RAM.")
        for d in v["disks"] or []:
            if d["total"] < 1e9:
                continue
            pct = 100 * d["used"] / d["total"]
            if pct > 80:
                add(f"{n}:disk:{d['mount']}", "high" if pct > 90 else "medium", n, f"Disk {d['mount']} {pct:.0f}% full",
                    f"{d['avail'] / 1e9:.0f} GB free.", "Clean logs/old builds or resize the disk.")
        if c.get("apt_last_update"):
            age = (time.time() - c["apt_last_update"]) / 86400
            if age > 7:
                add(f"{n}:apt-stale", "high" if age > 60 else "medium", n, f"No package list update for {age:.0f} days",
                    "The box hasn't fetched updates since " + dt.datetime.fromtimestamp(c["apt_last_update"]).strftime("%Y-%m-%d") +
                    ", so 'updates pending' looks clean but isn't. Private-only boxes can't reach the Ubuntu mirrors.",
                    "Give it a path to the mirrors (a NAT route, or a temporary SSH SOCKS proxy: `ssh -R 1080` + Acquire::http::Proxy) and run apt update.")
        if v.get("security_updates"):
            add(f"{n}:security-updates", "medium", n, f"{v['security_updates']} security updates pending", "",
                "Run `apt update && apt upgrade` (unattended-upgrades normally does this).")
        elif (v.get("updates") or 0) > 50:
            add(f"{n}:updates", "low", n, f"{v['updates']} package updates pending", "No security updates among them.", "Plan an apt upgrade in a quiet hour.")
        if v.get("reboot_required"):
            add(f"{n}:reboot", "low", n, "Reboot required", "A kernel or library update is waiting for a reboot.", "Reboot in a quiet hour.")
        sshd = c.get("sshd", {})
        if sshd.get("passwordauthentication") == "yes":
            add(f"{n}:ssh-password", "medium" if not world22 else "high", n, "SSH password login is on",
                "sshd accepts passwords. The Hetzner firewall limits who can reach port 22, but keys-only is safer.",
                "Set `PasswordAuthentication no` in /etc/ssh/sshd_config.d/, then `systemctl reload ssh`.")
        if sshd.get("permitrootlogin") == "yes":
            add(f"{n}:root-password", "medium", n, "Root may log in with a password", "permitrootlogin yes.",
                "Set `PermitRootLogin prohibit-password` in /etc/ssh/sshd_config.d/.")
        svc = c.get("services", {})
        if "unattended-upgrades" in svc and svc["unattended-upgrades"]["active"] != "active":
            add(f"{n}:unattended", "medium", n, "unattended-upgrades not running", "", "`systemctl enable --now unattended-upgrades`")
        if svc.get("fail2ban", {}).get("active") != "active" and world22:
            add(f"{n}:no-fail2ban", "medium", n, "No fail2ban while SSH is public", "", "Install and enable fail2ban (sshd jail).")
        for unit in c.get("failed_units", []):
            add(f"{n}:failed:{unit}", "low", n, f"Failed unit {unit}", "systemd reports this unit failed.", f"Look at `journalctl -u {unit} -n 50`.")
        for crt in c.get("certs", []):
            if crt["days"] < 0:
                add(f"{n}:cert:{crt['name']}", "low", n, f"Expired certificate on disk: {crt['name']}",
                    f"Expired {crt['expires']}. Fine if nothing serves it anymore.", "If unused: `certbot delete --cert-name " + crt["name"] + "`.")
            elif crt["days"] < 21:
                add(f"{n}:cert:{crt['name']}", "medium", n, f"Certificate {crt['name']} expires in {crt['days']} days",
                    "certbot should renew automatically at 30 days.", "Test with `certbot renew --dry-run`.", kind="health")
        for ph in [x for x in c.get("php", []) if x["kind"] == "fpm" and x["version"] not in ("", "?")]:
            br = ".".join(ph["version"].split(".")[:2])
            if br not in PHP_SUPPORTED:
                add(f"{n}:php-eol:{ph['name']}", "high", n, f"PHP {ph['version']} serves web requests ({ph['name']})",
                    f"PHP {br} gets no security fixes from php.net any more.", "Move the sites to a supported PHP (8.5) and stop this service.", kind="health")
            else:
                latest = php_latest(br)
                if latest and vtuple(ph["version"]) < vtuple(latest):
                    add(f"{n}:php-update:{ph['name']}", "high", n, f"PHP {ph['version']} → {latest} available",
                        f"{ph['name']} runs {ph['version']}; php.net has released {latest} (check its changelog for security fixes).",
                        "Upgrade PHP to " + latest + " (`apt update && apt upgrade`, or rebuild if you compile PHP from php.net source).", kind="health")
        for nd in c.get("node", []):
            try:
                major = int(nd["version"].split(".")[0])
            except ValueError:
                continue
            short = nd["path"].replace("/installation/bin/node", "").replace("/root/.local/share/fnm/node-versions/", "fnm ").replace("/root/.nvm/versions/node/", "nvm ")
            if major not in NODE_SUPPORTED:
                add(f"{n}:node-eol:{nd['path']}", "high", n, f"Node {nd['version']} is running ({nd['procs']} process{'es' if nd['procs'] != 1 else ''}) — end of life",
                    f"{short}: Node {major} gets no security fixes any more.", "Move the apps on it to Node 24 (or 22) and test.", kind="health")
            else:
                newer = [r for r in node_releases() if r["v"].split(".")[0] == str(major) and vtuple(r["v"]) > vtuple(nd["version"])]
                if any(r["security"] for r in newer):
                    latest = max(newer, key=lambda r: vtuple(r["v"]))["v"]
                    add(f"{n}:node-update:{nd['path']}", "high", n, f"Node {nd['version']} → {latest} (security release)",
                        f"{short}, {nd['procs']} process(es).", "Install the fixed version and point the apps at it (pm2 interpreter / fnm default).", kind="health")
        for p in [p for p in c.get("pm2", []) if p["status"] != "online"]:
            add(f"{n}:pm2:{p['name']}", "high", n, f"pm2 process {p['name']} is {p['status']}", "", f"Look at `pm2 logs {p['name']} --lines 50`.")
        for d in [d for d in c.get("docker", []) if not d["status"].startswith("Up")]:
            if d["status"].startswith("Exited (0)"):   # stopped cleanly, e.g. the idle colour of a blue/green deploy
                add(f"{n}:docker:{d['name']}", "info", n, f"Container {d['name']} is stopped (exited cleanly)", d["status"], "")
            else:
                add(f"{n}:docker:{d['name']}", "medium", n, f"Container {d['name']}: {d['status']}", "", f"Look at `docker logs --tail 50 {d['name']}`.")
        # Public listeners vs. the cloud firewall.
        public = sorted({p["port"] for p in c.get("tcp", []) if p["scope"] == "public"})
        if hz and fws and public:
            world, blocked = [], []
            for port in public:
                srcs = port_rules(rules, port)
                if any(x in ("0.0.0.0/0", "::/0") for x in srcs):
                    if port not in EXPECTED_WORLD_PORTS and not (port == 22 and n in SSH_WORLD_OK):
                        world.append(port)
                elif not srcs:
                    blocked.append(port)
            if world:
                add(f"{n}:world-ports", "high", n, f"Ports open to the internet: {', '.join(map(str, world))}",
                    "Listening on all interfaces and allowed from 0.0.0.0/0.", "Restrict in the Hetzner firewall or bind to 127.0.0.1.")
            if blocked:
                add(f"{n}:blocked-listeners", "info", n, f"{len(blocked)} services listen publicly but the firewall blocks them",
                    "Ports " + ", ".join(map(str, blocked)) + " listen on 0.0.0.0; the Hetzner firewall stops outside traffic.",
                    "Fine as is. For defense in depth, bind them to 127.0.0.1 or the private IP.")
        if not s["ipv4"] and c.get("ufw", {}).get("status") != "active":
            add(f"{n}:private-no-ufw", "medium", n, "Private-only box without ufw",
                "Anything on the private network can reach every port.", "Enable ufw and allow only the hosts that need each port.")

    for site in state["sites"]:
        h = site.get("http") or {}
        for chk in h.get("checks", []):
            if not chk["ok"]:
                add(f"site:{chk['url']}", "high", site["domain"], f"{chk['url']} is failing",
                    chk.get("error") or f"HTTP {chk.get('status')}", "Open it in a browser; check nginx / pm2 on the server.")
        for host, t in (h.get("tls") or {}).items():
            if "days" in t and t["days"] < 14:
                add(f"tls:{host}", "high", site["domain"], f"TLS for {host} expires in {t['days']} days", t.get("issuer", ""), "Renew the certificate.")
        for sm in (site.get("gsc") or {}).get("sitemaps", []):
            if sm["errors"]:
                add(f"sitemap:{sm['path']}", "low", site["domain"], f"Sitemap errors: {sm['path']}",
                    f"{sm['errors']} errors in Search Console.", "Open Search Console → Sitemaps.")
        cf = site.get("cloudflare") or {}
        st = (cf.get("settings") or {})
        if st.get("ssl") in ("off", "flexible"):
            add(f"cf-ssl:{site['domain']}", "medium", site["domain"], f"Cloudflare SSL mode is {st['ssl']}",
                "Traffic between Cloudflare and the server is not encrypted/verified.", "Set SSL/TLS to Full (strict).")
        req7 = sum(v for _, v in (site["daily"].get("cf.requests") or [])[-7:])
        e5 = sum(v for _, v in (site["daily"].get("cf.status5xx") or [])[-7:])
        if req7 > 1000 and e5 / req7 > 0.01:
            add(f"cf-5xx:{site['domain']}", "high" if e5 / req7 > 0.05 else "medium", site["domain"],
                f"{100 * e5 / req7:.1f}% server errors (5xx) over 7 days",
                f"{int(e5):,} of {int(req7):,} requests through Cloudflare got a 5xx answer.",
                "Check which paths fail (nginx error log / pm2 logs on the server, or Cloudflare → Analytics → status codes).")
        if st.get("always_use_https") == "off":
            add(f"cf-https:{site['domain']}", "low", site["domain"], "Cloudflare 'Always use HTTPS' is off",
                "Plain http:// requests are not redirected to https:// at the edge.", "Cloudflare → SSL/TLS → Edge Certificates → Always Use HTTPS.")
        ours = {x["ipv4"] for x in state["servers"] if x["ipv4"]}
        # 192.0.2.0/24 (and 100::/64) are placeholder addresses for proxied redirect-only records, not real hosts.
        ext = [r for r in cf.get("dns", []) if r["type"] == "A" and r["content"] not in ours and not r["content"].startswith("192.0.2.")
               and r["content"] not in site["cfg"].get("dns_external_ok", [])]
        if ext:
            add(f"cf-dns-external:{site['domain']}", "low", site["domain"], f"{len(ext)} DNS records point outside your servers",
                ", ".join(f"{r['name']} → {r['content']}" for r in ext[:8]) + (" …" if len(ext) > 8 else "") +
                ". If an old IP is released, whoever gets it next could serve pages under your domain.",
                "Delete records that are no longer used (Cloudflare → DNS).")
        if st.get("min_tls_version") in ("1.0",):
            add(f"cf-tls:{site['domain']}", "low", site["domain"], "Cloudflare allows TLS 1.0", "", "Set minimum TLS to 1.2.")

    for item in (state["resources"].get("status_feed") or []):
        if item["relevant"] and (not item.get("end") or item["end"] > now()):
            add(f"hetzner-status:{item['link']}", "info", "Hetzner", item["title"], item["summary"][:200], "See status.hetzner.com.")

    prev = {r["key"]: r["first_seen"] for r in conn.execute(
        "SELECT key, MIN(first_seen) AS first_seen FROM findings GROUP BY key")}
    conn.execute("DELETE FROM findings WHERE sync_id=?", (sid,))
    conn.executemany("INSERT OR REPLACE INTO findings (sync_id, key, severity, scope, title, detail, fix, first_seen, kind, code) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?)",
                     [(sid, k, sev, scope, t, d, f, prev.get(k, now()), kd, cd) for k, sev, scope, t, d, f, kd, cd in out])
    counts = {sev: sum(1 for x in out if x[1] == sev) for sev in ("high", "medium", "low", "info")}
    step("Security checks", "ok", " · ".join(f"{v} {k}" for k, v in counts.items()))


# ---------------------------------------------------------------- Timeline

def add_event(conn, kind, title, scope="", detail="", severity="info", ts=None, sid=None, source="auto"):
    conn.execute("INSERT INTO events (ts, kind, severity, scope, title, detail, source, sync_id) VALUES (?,?,?,?,?,?,?,?)",
                 (ts or now(), kind, severity, scope, title, detail, source, sid))


def record_events(conn, sid):
    """Compare this sync with the previous one and write what changed to the timeline."""
    n = 0
    prev = conn.execute("SELECT MAX(sync_id) FROM findings WHERE sync_id < ?", (sid,)).fetchone()[0]
    if prev:
        cur = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM findings WHERE sync_id=?", (sid,))}
        old = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM findings WHERE sync_id=?", (prev,))}
        for k in cur.keys() - old.keys():
            f = cur[k]
            if f["severity"] != "info":
                add_event(conn, "finding-new", f["title"], f["scope"], f["detail"] or "", f["severity"], sid=sid); n += 1
        for k in old.keys() - cur.keys():
            f = old[k]
            if f["severity"] != "info":
                add_event(conn, "finding-fixed", f["title"], f["scope"], "No longer found.", "good", sid=sid); n += 1
    for v in conn.execute("SELECT * FROM vitals WHERE sync_id=? AND ok=1", (sid,)).fetchall():
        pv = conn.execute("SELECT * FROM vitals WHERE name=? AND ok=1 AND sync_id<? ORDER BY sync_id DESC LIMIT 1",
                          (v["name"], sid)).fetchone()
        if not pv:
            continue
        rebooted = v["uptime_s"] is not None and pv["uptime_s"] is not None and v["uptime_s"] < pv["uptime_s"]
        if rebooted:
            ts = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=v["uptime_s"])).strftime("%Y-%m-%dT%H:%M:%SZ")
            add_event(conn, "reboot", "Rebooted", v["name"], f"Up again, kernel {v['kernel']}.", ts=ts, sid=sid); n += 1
        if v["kernel"] and pv["kernel"] and v["kernel"] != pv["kernel"]:
            add_event(conn, "kernel", f"Kernel {pv['kernel']} → {v['kernel']}", v["name"], sid=sid); n += 1
        c = conn.execute("SELECT data FROM checks WHERE name=? AND sync_id=?", (v["name"], sid)).fetchone()
        pc = conn.execute("SELECT data FROM checks WHERE name=? AND sync_id=?", (v["name"], pv["sync_id"])).fetchone()
        if c and pc and not rebooted:
            before = {x["name"]: x["restarts"] for x in json.loads(pc["data"]).get("pm2", [])}
            for x in json.loads(c["data"]).get("pm2", []):
                d = x["restarts"] - before.get(x["name"], x["restarts"])
                if d > 0:
                    add_event(conn, "app", f"pm2 app {x['name']} restarted {d}×", v["name"], severity="low", sid=sid); n += 1
    for r in conn.execute("SELECT domain, data FROM sites WHERE sync_id=? AND source='http'", (sid,)).fetchall():
        pr = conn.execute("SELECT data FROM sites WHERE domain=? AND source='http' AND sync_id<? ORDER BY sync_id DESC LIMIT 1",
                          (r["domain"], sid)).fetchone()
        if not pr:
            continue
        was = {c["url"]: c["ok"] for c in json.loads(pr["data"]).get("checks", [])}
        for c in json.loads(r["data"]).get("checks", []):
            if c["url"] in was and was[c["url"]] != c["ok"]:
                if c["ok"]:
                    add_event(conn, "site", f"{c['url']} is back up", r["domain"], severity="good", sid=sid)
                else:
                    add_event(conn, "site", f"{c['url']} is down", r["domain"], c.get("error") or f"HTTP {c.get('status')}", "high", sid=sid)
                n += 1
    for e in LOG:
        if e["state"] == "fail":
            add_event(conn, "sync", f"Sync step failed: {e['step']}", "", e["detail"], "medium", sid=sid); n += 1
    step("Timeline", "ok", f"{n} new events")


# ---------------------------------------------------------------- Main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api-only", action="store_true", help="skip SSH")
    ap.add_argument("--host", help="only SSH this server (name from servers.json)")
    ap.add_argument("--skip", default="", help="comma list: ssh,sites,google,asc,cloudflare,status")
    ap.add_argument("--suggest-servers", action="store_true", help="print a servers.json draft and exit")
    a = ap.parse_args()
    if a.suggest_servers:
        suggest_servers()
        return
    skip = {x.strip() for x in a.skip.split(",") if x.strip()}
    if a.api_only:
        skip.add("ssh")
    if a.host:
        skip |= {"sites", "google", "asc", "cloudflare", "status"}
    mode = "api-only" if a.api_only else (f"host:{a.host}" if a.host else ("full" if not skip else "skip:" + ",".join(sorted(skip))))

    store.DATA.mkdir(exist_ok=True)
    lock = open(store.DATA / ".sync.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        step("Sync", "fail", "another sync is already running")
        sys.exit(2)

    env = store.load_env()
    conn = store.connect()
    sid = conn.execute("INSERT INTO syncs (started_at, mode) VALUES (?, ?)", (now(), mode)).lastrowid
    conn.commit()
    step("Sync", "run", f"#{sid} {mode}")

    def guarded(name, fn, *args):
        try:
            fn(*args)
        except Exception as e:
            step(name, "fail", e)
        conn.commit()

    if env.get("HETZNER_API_TOKEN"):
        guarded("Hetzner API", collect_hetzner, conn, sid, Hetzner(env["HETZNER_API_TOKEN"]))
    else:
        guarded("Servers (servers.json)", collect_static_servers, conn, sid)
    if "status" not in skip and env.get("HETZNER_API_TOKEN"):
        guarded("Hetzner status page", collect_status_feed, conn, sid)
    if "ssh" not in skip:
        guarded("SSH", collect_ssh, conn, sid, a.host)
    if "sites" not in skip:
        guarded("Websites up + TLS", collect_sites, conn, sid)
    if "google" not in skip:
        guarded("Search Console + GA4", collect_google, conn, sid)
    if "asc" not in skip:
        guarded("App Store Connect", collect_asc, conn, sid)
    if "cloudflare" not in skip:
        if env.get("CLOUDFLARE_API_TOKEN"):
            guarded("Cloudflare", collect_cloudflare, conn, sid, env["CLOUDFLARE_API_TOKEN"])
        else:
            step("Cloudflare", "skip", "no CLOUDFLARE_API_TOKEN in .env")
    guarded("Security checks", compute_findings, conn, sid)
    guarded("Timeline", record_events, conn, sid)

    conn.execute("DELETE FROM raw WHERE sync_id IN (SELECT id FROM syncs WHERE started_at < ?)",
                 ((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
    failed = [e for e in LOG if e["state"] == "fail"]
    status = "ok" if not failed else ("failed" if len(failed) == len([e for e in LOG if e["state"] != "skip"]) else "partial")
    conn.execute("UPDATE syncs SET finished_at=?, status=?, log=? WHERE id=?", (now(), status, json.dumps(LOG), sid))
    conn.commit()
    step("Sync", "done", f"#{sid} {status}")


if __name__ == "__main__":
    main()
