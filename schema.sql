-- Infra dashboard store. Applied by sync.py on every run (all IF NOT EXISTS).
-- Per-sync tables keep one row per thing per sync, so history and diffs are possible.
-- *_daily and metrics tables are upserted time series that grow longer with every sync.

CREATE TABLE IF NOT EXISTS syncs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  mode        TEXT NOT NULL,              -- full | api-only | host:<name> | ...
  status      TEXT NOT NULL DEFAULT 'running',  -- running | ok | partial | failed
  log         TEXT                        -- JSON list of steps
);

-- Hetzner API view of each server.
CREATE TABLE IF NOT EXISTS servers (
  sync_id INTEGER NOT NULL, name TEXT NOT NULL, hetzner_id INTEGER,
  status TEXT, type TEXT, cpu_type TEXT, cores INTEGER, memory_gb REAL, disk_gb INTEGER,
  location TEXT, city TEXT, country TEXT, zone TEXT, lat REAL, lon REAL,
  ipv4 TEXT, ipv6 TEXT, private_ips TEXT,
  traffic_in INTEGER, traffic_out INTEGER, traffic_included INTEGER,
  price_monthly REAL, backups INTEGER, backup_window TEXT,
  protect_delete INTEGER, protect_rebuild INTEGER, firewall_ids TEXT,
  image TEXT, created TEXT,
  PRIMARY KEY (sync_id, name)
);

-- On-box vitals from the SSH probe.
CREATE TABLE IF NOT EXISTS vitals (
  sync_id INTEGER NOT NULL, name TEXT NOT NULL, ok INTEGER NOT NULL, error TEXT,
  hostname TEXT, os TEXT, kernel TEXT, uptime_s INTEGER, cpus INTEGER,
  load1 REAL, load5 REAL, load15 REAL,
  mem_total INTEGER, mem_used INTEGER, mem_available INTEGER, swap_total INTEGER, swap_used INTEGER,
  disk_total INTEGER, disk_used INTEGER, disks TEXT,
  updates INTEGER, security_updates INTEGER, reboot_required INTEGER,
  PRIMARY KEY (sync_id, name)
);

-- On-box security / service detail (ufw, fail2ban, sshd, ports, certs, services, pm2, docker) as JSON.
CREATE TABLE IF NOT EXISTS checks (
  sync_id INTEGER NOT NULL, name TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (sync_id, name)
);

-- Hetzner metrics, 30-minute steps.
CREATE TABLE IF NOT EXISTS metrics (
  server TEXT NOT NULL, ts INTEGER NOT NULL,
  cpu REAL, disk_read REAL, disk_write REAL, net_in REAL, net_out REAL,
  PRIMARY KEY (server, ts)
);

CREATE TABLE IF NOT EXISTS firewalls (
  sync_id INTEGER NOT NULL, hetzner_id INTEGER NOT NULL, name TEXT,
  applied_to TEXT, rules TEXT,
  PRIMARY KEY (sync_id, hetzner_id)
);

-- Other Hetzner resources and feeds, one JSON blob per kind per sync
-- (networks, volumes, snapshots, backups, primary_ips, ssh_keys, load_balancers, status_feed).
CREATE TABLE IF NOT EXISTS resources (
  sync_id INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (sync_id, kind)
);

CREATE TABLE IF NOT EXISTS findings (
  sync_id INTEGER NOT NULL, key TEXT NOT NULL,
  severity TEXT NOT NULL,                 -- high | medium | low | info
  scope TEXT, title TEXT, detail TEXT, fix TEXT,
  first_seen TEXT NOT NULL,
  kind TEXT,                              -- health (a problem now) | hygiene (setup to tidy)
  code TEXT,                              -- groups the same issue across servers, e.g. no-backups
  PRIMARY KEY (sync_id, key)
);

-- Findings the owner accepted / snoozed. until NULL = for good.
CREATE TABLE IF NOT EXISTS acks (
  key TEXT PRIMARY KEY, until TEXT, note TEXT, created TEXT NOT NULL
);

-- Timeline: things that happened. source = auto (sync noticed it) | manual (a note).
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, kind TEXT NOT NULL,   -- reboot | kernel | incident | change | site | app | finding-new | finding-fixed | sync | note
  severity TEXT, scope TEXT, title TEXT NOT NULL, detail TEXT,
  source TEXT NOT NULL DEFAULT 'auto', sync_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

-- Websites: uptime/TLS checks, Search Console, GA4, Cloudflare. One JSON per source per domain per sync.
CREATE TABLE IF NOT EXISTS sites (
  sync_id INTEGER NOT NULL, domain TEXT NOT NULL, source TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (sync_id, domain, source)
);

CREATE TABLE IF NOT EXISTS site_daily (
  domain TEXT NOT NULL, date TEXT NOT NULL, source TEXT NOT NULL, metric TEXT NOT NULL, value REAL,
  PRIMARY KEY (domain, date, source, metric)
);

-- App Store: versions/state per app per sync, daily units from the sales reports.
CREATE TABLE IF NOT EXISTS apps (
  sync_id INTEGER NOT NULL, app_id TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (sync_id, app_id)
);

CREATE TABLE IF NOT EXISTS app_daily (
  app_id TEXT NOT NULL, date TEXT NOT NULL,
  downloads INTEGER DEFAULT 0, redownloads INTEGER DEFAULT 0, updates INTEGER DEFAULT 0, iap INTEGER DEFAULT 0,
  PRIMARY KEY (app_id, date)
);

-- Which sales-report days were fetched (so a sync only asks Apple for new days).
CREATE TABLE IF NOT EXISTS asc_days (
  date TEXT PRIMARY KEY, status TEXT NOT NULL, fetched_at TEXT NOT NULL
);

-- Raw source output for debugging; pruned after 30 days.
CREATE TABLE IF NOT EXISTS raw (
  sync_id INTEGER NOT NULL, source TEXT NOT NULL, body TEXT,
  PRIMARY KEY (sync_id, source)
);

CREATE INDEX IF NOT EXISTS idx_vitals_name ON vitals(name, sync_id);
CREATE INDEX IF NOT EXISTS idx_checks_name ON checks(name, sync_id);
CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites(domain, source, sync_id);
