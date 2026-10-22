# Infra dashboard: rules for AI agents

A local, read-only dashboard: `serve.py` (127.0.0.1) shows `index.html`; `sync.py` collects from cloud APIs, websites and a read-only SSH probe (`collect.sh`) into `data/infra.db` (SQLite). Setup playbook: `SETUP-WITH-CLAUDE.md`.

## Hard rules

1. **Read-only.** Cloud APIs: GET only (a Hetzner token can often write; never call anything else). SSH: only the commands in `collect.sh`, plus `true` to test a connection. The dashboard reports; it never fixes.
2. **SSH one box at a time.** Never run SSH commands in parallel. Servers may use fail2ban or ufw `LIMIT` and ban the source IP. On "Connection refused" or a timeout: stop, tell the owner, don't retry in a loop. Keep `settings.jump_host` set when there is a bastion so hops share one connection.
3. **Secrets never leave their files.** Tokens live in `.env` (chmod 600); Google/Apple keys in `~/.config/infra-dashboard/`. Never `cat` them, never echo a token, never put one in a command line, a log, `data/`, a commit or the page. `/api/state` only says whether a token is set.
4. **Ask first** before changing anything on a server, a firewall, DNS, a cloud setting, or `~/.ssh/config`. A finding is not permission to fix it.
5. **Don't publish the owner's copy.** Their `servers.json`, `sites.json` and `data/` describe their infrastructure. Keep it in a private repo or none.

## Working on the code

- Python 3 stdlib only for `serve.py`, `sync.py`, `store.py`. Google and Apple collectors run in their own venvs (paths in `settings.json`) and talk to `sync.py` via JSON on stdin/stdout.
- `collect.sh` must stay read-only and must not send environment variables or secrets off the box (pm2 output is filtered on the box for this reason).
- `serve.py` keeps its Host/Origin checks and the `X-Infra-Dashboard: 1` header on POSTs, and serves only `index.html` and `vendor/`.
- New findings: add them in `sync.py` with a stable `key`, a `code` (used to group the same issue across servers), `kind` (`health` = problem now, `hygiene` = setup to tidy), severity and a one-line fix.
- The schema migrates itself in `store.connect()`; add columns there with `ALTER TABLE … ADD COLUMN` when needed.
- Test with `python3 sync.py --api-only`, then `--host <one box>`, then open the page and check the browser console.
