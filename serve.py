#!/usr/bin/env python3
"""Local server for the infra dashboard.

    python3 serve.py [--port 8796] [--open]

Binds 127.0.0.1 only. Serves index.html + vendor/, and:
  GET  /api/state            latest data from data/infra.db
  GET  /api/history?server=  RAM/disk/load per sync (trend charts)
  POST /api/sync             start sync.py (body: {"mode": "full" | "api-only" | "host", "host": name})
  POST /api/ack | /api/unack accept / un-accept findings ({"keys": [...], "days": 30 | null, "note": ""})
  POST /api/event            add a timeline note ({"title", "detail", "scope", "kind": note|change|incident})
  GET  /api/sync/status      live step log of the running / last sync
/api/sync only accepts requests from this page (Origin + custom header), so no other website
open in the browser can start SSH runs. .env, data/ and dotfiles are never served.
"""
import argparse
import json
import posixpath
import subprocess
import sys
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import store

ROOT = store.ROOT
PUBLIC = {"index.html", "favicon.svg"}
PUBLIC_DIRS = {"vendor"}

SYNC = {"running": False, "steps": [], "exit": None, "mode": None}
LOCK = threading.Lock()


def run_sync(args):
    cmd = [sys.executable, str(ROOT / "sync.py")] + args
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        try:
            SYNC["steps"].append(json.loads(line))
        except ValueError:
            if line.strip():
                SYNC["steps"].append({"step": "output", "state": "warn", "detail": line.strip()[:300]})
    SYNC["exit"] = proc.wait()
    SYNC["running"] = False


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def log_message(self, *a):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def host_ok(self):
        host = self.headers.get("Host", "")
        return host in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")  # blocks DNS-rebinding

    def do_GET(self):
        if not self.host_ok():
            return self.send_error(403)
        url = urlsplit(self.path)
        path = posixpath.normpath(unquote(url.path))
        if path in ("/", "/."):
            self.path = "/index.html"
            return super().do_GET()
        if path == "/api/state":
            conn = store.connect()
            try:
                state = store.latest_state(conn)
            finally:
                conn.close()
            state["sync_running"] = SYNC["running"]
            return self.send_json(state)
        if path == "/api/history":
            q = parse_qs(url.query)
            conn = store.connect()
            try:
                return self.send_json(store.history(conn, q.get("server", [""])[0], int(q.get("days", ["30"])[0])))
            finally:
                conn.close()
        if path == "/api/sync/status":
            return self.send_json(SYNC)
        parts = [p for p in path.split("/") if p]
        if not parts or any(p.startswith(".") for p in parts):
            return self.send_error(404)
        if not (parts == [parts[0]] and parts[0] in PUBLIC) and parts[0] not in PUBLIC_DIRS:
            return self.send_error(404)
        return super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/sync", "/api/ack", "/api/unack", "/api/event"):
            return self.send_error(404)
        origin = self.headers.get("Origin", "")
        if not self.host_ok() or origin not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}") \
                or self.headers.get("X-Infra-Dashboard") != "1":
            return self.send_json({"error": "forbidden"}, 403)
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
        except ValueError:
            body = {}
        if path != "/api/sync":
            return self.write_api(path, body)
        mode = body.get("mode", "full")
        args = {"full": [], "api-only": ["--api-only"]}.get(mode)
        if mode == "host":
            cfg = (store.config("servers.json").get("servers") or {})
            if body.get("host") not in cfg:
                return self.send_json({"error": "unknown host"}, 400)
            args = ["--host", body["host"]]
        if args is None:
            return self.send_json({"error": "unknown mode"}, 400)
        with LOCK:
            if SYNC["running"]:
                return self.send_json({"error": "a sync is already running"}, 409)
            SYNC.update(running=True, steps=[], exit=None, mode=mode)
            threading.Thread(target=run_sync, args=(args,), daemon=True).start()
        return self.send_json({"started": True, "mode": mode})


    def write_api(self, path, body):
        """Accept / un-accept findings and add timeline notes. Only touches the local DB."""
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        keys = [str(k)[:300] for k in (body.get("keys") or [])][:100]
        conn = store.connect()
        try:
            if path == "/api/ack":
                days = body.get("days")
                until = (now + dt.timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%SZ") if days else None
                note = str(body.get("note") or "")[:500]
                for k in keys:
                    conn.execute("INSERT OR REPLACE INTO acks VALUES (?,?,?,?)", (k, until, note, stamp))
                title = str(body.get("title") or (keys[0] if keys else ""))[:200]
                conn.execute("INSERT INTO events (ts, kind, severity, scope, title, detail, source) VALUES (?,?,?,?,?,?,?)",
                             (stamp, "note", "info", str(body.get("scope") or "")[:200],
                              f"Accepted: {title}" + (f" (for {days} days)" if days else ""), note, "manual"))
            elif path == "/api/unack":
                conn.executemany("DELETE FROM acks WHERE key=?", [(k,) for k in keys])
            elif path == "/api/event":
                title = str(body.get("title") or "").strip()[:300]
                if not title:
                    return self.send_json({"error": "title missing"}, 400)
                kind = body.get("kind") if body.get("kind") in ("note", "change", "incident") else "note"
                conn.execute("INSERT INTO events (ts, kind, severity, scope, title, detail, source) VALUES (?,?,?,?,?,?,?)",
                             (stamp, kind, "high" if kind == "incident" else "info", str(body.get("scope") or "")[:200],
                              title, str(body.get("detail") or "")[:2000], "manual"))
            conn.commit()
        finally:
            conn.close()
        return self.send_json({"ok": True})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--open", action="store_true")
    a = ap.parse_args()
    PORT = a.port or int(store.settings().get("port", 8796))
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}/"
    print(f"{store.settings()['title']}: {url}  (Ctrl+C to stop)")
    if a.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
