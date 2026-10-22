# Infra Dashboard

A local, read-only dashboard for a small fleet: your Linux servers, the websites they serve and your mobile apps, on one page. Click **Sync** and a script on your own machine collects fresh data; nothing is hosted, nothing runs on the servers except a short read-only SSH check.

Built for a one-person / small-team setup (a handful of VPSs, a few domains, an app or two) that wants to answer *"is everything OK, and what needs my attention?"* in one glance.

![tabs](https://img.shields.io/badge/stack-Python%203%20stdlib%20%2B%20one%20HTML%20file-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## What you get

- **A one-line verdict** at the top: *All good* / *N things to watch* / *N problems need you now*, plus what happened since your last visit.
- **Servers**: CPU (7-day chart), RAM, swap, disk per mount, load, uptime, pending updates, reboot needed, RAM per app (pm2 apps, Docker containers, systemd services), listening ports, firewall (ufw, fail2ban), SSH settings, TLS certificates on disk, PHP and Node.js versions.
- **Hetzner Cloud** (optional): server types, locations, traffic, list-price cost, cloud firewalls, private networks, backups, snapshots, IPs, Hetzner status page notices.
- **Websites**: up/down and response time from your machine, TLS expiry, Google Search Console clicks and impressions (90 days), GA4 visitors, Cloudflare requests / cache rate / 5xx errors / firewall events / SSL settings / DNS records.
- **Apps**: App Store Connect daily downloads, in-app purchases and latest version.
- **Findings**, grouped per issue across servers and split into *Problems now* and *Setup to tidy*. Each finding has a one-line fix and an **Accept…** button (30 days or for good, with a note).
- **Timeline**: every sync records what changed (reboots, kernel updates, sites going down/up, app restarts, findings opened/fixed); you can add notes.
- Map of server locations, a connection diagram, light/dark theme, works on a phone.

## How it works

```
your machine                                              your servers / services
┌──────────────────────────────────────┐
│ serve.py  (127.0.0.1 only)           │   SSH, read-only probe (collect.sh), one box at a time
│   └ index.html  ← /api/state         │ ──────────────────────────────────────────────►  Linux servers
│ sync.py   (runs on "Sync")           │   HTTPS GET                                       Hetzner API, Cloudflare API,
│   ├ collect.sh  (piped over SSH)     │ ──────────────────────────────────────────────►  websites, php.net, nodejs.org
│   ├ collectors/gsc_ga4.py (own venv) │                                                   Google Search Console + GA4
│   └ collectors/asc.py     (own venv) │                                                   App Store Connect
│ data/infra.db  (SQLite, history)     │
└──────────────────────────────────────┘
```

- **Python 3 standard library only** for the dashboard itself. The two optional collectors (Google, Apple) run in their own small virtualenvs.
- **Read-only everywhere.** The SSH probe only reads (`free`, `df`, `ss`, `ufw status`, `pm2 jlist` filtered on the box so no environment variables leave it, …). Cloud APIs are called with GET only. The dashboard never changes anything; findings tell *you* what to fix.
- **Every sync is stored** in SQLite, so trends (RAM/disk per sync, Search Console, downloads, Hetzner metrics beyond 7 days) build up over time.
- `serve.py` binds to `127.0.0.1` only, refuses requests with a foreign `Host`/`Origin` (DNS-rebinding/CSRF safe), and never serves `.env`, `data/` or the scripts.

## Quick start

Requirements: macOS or Linux with `python3` (3.10+) and `ssh`; servers running a Debian/Ubuntu-style Linux you can reach with `ssh <alias>` (key-based, non-interactive).

```bash
git clone https://github.com/dvdcodez/infra-dashboard.git
cd infra-dashboard
cp .env.example .env && chmod 600 .env        # add tokens (all optional)
python3 sync.py --suggest-servers             # draft for servers.json from the Hetzner API + ~/.ssh/config
# edit servers.json, sites.json, settings.json
python3 sync.py --api-only                    # first sync without SSH
python3 sync.py --host <one-server>           # then one box over SSH
python3 serve.py --open                       # http://127.0.0.1:8796
```

From then on, use the **Sync** button (full sync, without SSH, or re-check one server). On macOS, `open-dashboard.command` starts it with a double-click.

**Easiest:** let Claude Code set it up for you: see [SETUP-WITH-CLAUDE.md](SETUP-WITH-CLAUDE.md).

## Configuration

All config is plain JSON next to the code. The repo ships with examples (`example.com`, documentation IP ranges); replace them.

### `settings.json`

| Key | Meaning |
|---|---|
| `title`, `subtitle`, `port` | Page title, subtitle, local port (default 8796). |
| `jump_host` | SSH alias of a bastion/jump host, or `null`. Servers with `"jump": "<alias>"` are reached through it, and **all hops share one SSH connection** to it (a jump host with a ufw `LIMIT` rule refuses the 6th new connection in 30 s). |
| `ssh_world_ok` | Server names allowed to expose SSH to the whole internet (e.g. the jump host). Others get a high finding if their cloud firewall allows `22` from `0.0.0.0/0`. |
| `expected_public_ports` | Ports that may be open to the internet without a finding (default `[80, 443]`). |
| `google.python`, `google.service_account_json`, `google.ga4_properties` | Venv Python for the Google collector, service-account key file, optional map of names → GA4 property ids. |
| `appstore.python`, `appstore.config` | Venv Python for the App Store collector, path to `appstore.json` (key id, issuer id, `.p8` key file, vendor number). |

### `servers.json`

```json
{
  "servers": {
    "web-1": {"ssh": "web-1", "role": "Website + API", "product": "My app", "order": 1,
              "ipv4": "203.0.113.10", "city": "Frankfurt", "country": "DE", "lat": 50.11, "lon": 8.68},
    "db-1":  {"ssh": "web-1", "via_host": "10.0.0.3", "via_key": "/root/.ssh/id_ed25519", "role": "Database", "order": 2}
  },
  "links": [["you", "web-1", "SSH"], ["web-1", "db-1", "private 10.0.0.0/16"]]
}
```

- The key is the server name; with the Hetzner API it must match the name in the Hetzner console (type, location, IPs, price then come from the API). Without it, give `ipv4`, `city`, `country`, `lat`, `lon`, `type`, `price_eur` yourself (any provider works).
- `ssh`: an alias from `~/.ssh/config`. `jump`: reach it through `settings.jump_host` over the shared connection. `via_host` + `via_key`: a private-only box reached **from** the `ssh` box.
- `runs`: hand-written list of what runs on the box (`name`, `kind`, `what`, `domains`, `port`), shown under *What runs where*.
- `price_eur`: what you actually pay (the Hetzner API only knows today's list price; older servers often pay less).
- `no_backups_ok: true` silences the "backups off" finding for a box.
- `links`: arrows for the connection diagram (`"you"` = the machine running the dashboard). Without links, the diagram shows *you → each server*.

### `sites.json`

```json
{
  "sites": [{"domain": "example.com", "product": "My app", "server": "web-1",
             "gsc": "sc-domain:example.com", "ga4": "properties/123456789", "cf_zone": "example.com",
             "check": ["https://example.com/"]}],
  "apps": [{"id": "1234567890", "name": "My App"}]
}
```

`check` URLs are fetched once per sync with a browser user agent. Keep them to normal pages: some apps rate-limit or ban clients that hit API endpoints anonymously.

### `.env` (never committed)

| Variable | Where to get it | Scope |
|---|---|---|
| `HETZNER_API_TOKEN` | Hetzner Console → your project → Security → API tokens | **Read** is enough |
| `CLOUDFLARE_API_TOKEN` | dash.cloudflare.com → My Profile → API Tokens → Custom | Zone · Zone, Zone · Zone Settings, Zone · Analytics, Zone · DNS — all **Read**; all zones |

### Optional collectors

**Search Console + GA4**
```bash
python3 -m venv ~/.config/infra-dashboard/google-venv
~/.config/infra-dashboard/google-venv/bin/pip install -r requirements-google.txt
```
Create a Google Cloud service account, enable the *Search Console API* and *Google Analytics Data API*, download its JSON key to `~/.config/infra-dashboard/google-service-account.json` (chmod 600), then add the service-account e-mail as a user to each Search Console property and each GA4 property (Viewer).

**App Store Connect**
```bash
python3 -m venv ~/.config/infra-dashboard/asc-venv
~/.config/infra-dashboard/asc-venv/bin/pip install -r requirements-appstore.txt
```
Create an App Store Connect API key (Users and Access → Integrations, role *Sales and Reports* or higher), save the `.p8`, and write `~/.config/infra-dashboard/appstore.json`:
```json
{"key_id": "ABC123XYZ9", "issuer_id": "00000000-0000-0000-0000-000000000000", "key_file": "~/.config/infra-dashboard/AuthKey_ABC123XYZ9.p8", "vendor_number": "12345678"}
```

## What the checks look for

**Problems now** (colour a server's dot): server not running, SSH probe failed, RAM > 80 %, swap > 80 %, disk > 80 %, a pm2 app or container down, failed systemd units (low), a website failing, TLS < 14 days, Cloudflare 5xx > 1 % over 7 days, a port other than `expected_public_ports` open to the internet, SSH open to the internet, end-of-life PHP or Node.js serving requests, PHP/Node.js with a newer security release (checked against php.net and nodejs.org).

**Setup to tidy**: SSH password login, root password login, pending (security) updates, reboot required, unattended-upgrades off, a box that hasn't fetched package lists for a week, Hetzner backups / delete protection off, services listening publicly behind the cloud firewall, DNS records pointing outside your servers, Cloudflare TLS 1.0 / *Always use HTTPS* off, expired certificate files.

The lists of supported PHP branches and Node.js majors are constants at the top of the checks in `sync.py` (`PHP_SUPPORTED`, `NODE_SUPPORTED`); update them when a branch reaches end of life.

## Files

| File | What |
|---|---|
| `serve.py` | Local web server + JSON API (`/api/state`, `/api/history`, `/api/sync`, accept/notes). |
| `sync.py` | The collector: Hetzner, SSH probe, websites, Google, App Store, Cloudflare, findings, timeline. |
| `collect.sh` | The read-only shell probe, piped to each server over SSH. |
| `collectors/` | Google and Apple collectors (run in their own venvs). |
| `store.py`, `schema.sql` | SQLite access and tables. |
| `index.html`, `vendor/` | The page (one file) and bundled d3 / topojson / world map. |

## Troubleshooting

- **SSH step fails**: test `ssh -o BatchMode=yes <alias> true`. The probe never asks for passwords.
- **"Connection refused" on a jump host**: its ufw rate limit. Keep `jump_host` set so hops share one connection; wait 30 s.
- **A site shows a Cloudflare bot check**: counted as up; browsers pass the challenge.
- **Search Console numbers end 2 days ago**: normal, final data lags.
- **Port in use**: change `port` in `settings.json`.

## License

MIT, see [LICENSE](LICENSE). Bundled third-party files: see [vendor/LICENSES.md](vendor/LICENSES.md).
