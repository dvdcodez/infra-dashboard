# Set it up with Claude Code

This repo is meant to be set up by an AI coding agent (Claude Code or similar) together with you. The agent does the tedious parts: reading your `~/.ssh/config`, drafting `servers.json`, testing each SSH hop, running the first syncs and filling in *what runs where*. You make the decisions and paste the tokens.

## 1. Paste this prompt

Clone the repo, `cd` into it, start `claude`, and paste:

```text
Set up this infra dashboard for my servers. Follow SETUP-WITH-CLAUDE.md and the
rules in CLAUDE.md step by step. Interview me first, then do the setup one step at
a time and show me what you found after each step. Everything must stay read-only
on my servers and cloud accounts. Never print, echo or commit my tokens or keys.
```

That's it. The rest of this file is the playbook the agent follows.

---

## 2. Playbook for the agent

### Step 0: Read first
Read `README.md`, `CLAUDE.md`, `settings.json`, `servers.json`, `sites.json` and the top of `sync.py`, so you know the config format and what each collector needs.

### Step 1: Interview the owner
Ask, in one go (use a multiple-choice question tool if you have one):

1. **Servers**: which boxes should be on the dashboard? Are they on Hetzner Cloud (then the API fills in type, location, price, firewalls), or another provider (then you'll enter location and price by hand)?
2. **SSH**: do they reach the boxes with `ssh <alias>`? Is there a **jump host / bastion**? Are any boxes **private-only**, reached from another box?
3. **Rate limits**: is there fail2ban or a ufw `LIMIT` rule that could ban them for too many SSH connections? (Assume yes; the probe is serial anyway.)
4. **Websites**: which domains, which server serves each, and which URL is safe to fetch as a health check (a normal page, not an API)?
5. **Optional sources**: Hetzner token? Cloudflare token? Google Search Console / GA4? App Store Connect? Skip any they don't want.
6. **Title**: what should the page be called?

Don't ask for anything you can look up yourself (`~/.ssh/config`, the Hetzner API once a token exists).

### Step 2: Tokens into `.env`
```bash
cp .env.example .env && chmod 600 .env
```
Ask the owner to paste the tokens **into the file themselves**, or, if they paste them in chat, write them into `.env` without printing them back. Never `cat .env`, never put a token in a command line that ends up in shell history or logs. Check only that the variables are set:
```bash
grep -c '^HETZNER_API_TOKEN=.\+' .env; grep -c '^CLOUDFLARE_API_TOKEN=.\+' .env
```
Recommend **read-only** tokens (Hetzner: *Read*; Cloudflare: Zone / Zone Settings / Analytics / DNS, all *Read*). The code only ever sends GET requests, but a read-only token makes that a guarantee.

### Step 3: `settings.json`
Set `title`, `subtitle`, `jump_host` (the SSH alias, or `null`), `ssh_world_ok` (normally just the jump host's server name), and `expected_public_ports` if they serve more than 80/443 on purpose.

### Step 4: `servers.json`
With a Hetzner token:
```bash
python3 sync.py --suggest-servers
```
This prints a draft that matches Hetzner server names to `~/.ssh/config` aliases by IP. Without a token, build it from `~/.ssh/config` and the interview, and add `ipv4`, `city`, `country`, `lat`, `lon`, `type`, `price_eur` by hand.

- Servers behind the jump host get `"jump": "<jump alias>"`.
- Private-only boxes: `"ssh": "<box that can reach it>"`, `"via_host": "<private ip>"`, `"via_key": "<key path on that box>"`. Check with the owner that such a key exists on that box; don't create one.
- Add `links` for the connection diagram (`["you", "<jump>", "SSH"]`, `["<jump>", "<box>", "SSH"]`, `["<box>", "<db>", "private …"]`).
- Ask what they really pay per box if it differs from the list price (`price_eur`).

### Step 5: Test SSH, one box at a time
For each alias, **serially, never in parallel**:
```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 <alias> true && echo ok
```
If one fails, stop and tell the owner what failed. Don't retry in a loop (that is what gets IPs banned). Don't edit `~/.ssh/config`, `authorized_keys` or anything on the servers without asking.

### Step 6: `sites.json`
One entry per domain with `product`, `server`, `check` URLs, and, if those collectors are set up, `gsc` (`sc-domain:example.com` or `https://example.com/`), `ga4` (`properties/<id>`) and `cf_zone`. Apps: `{"id": "<App Store id>", "name": "…"}`.

### Step 7: Optional collectors
Only those the owner wants. Follow *Optional collectors* in the README: create the venv under `~/.config/infra-dashboard/`, install the requirements file, have the owner put the key files there (chmod 600). Keys live **outside** the repo.

For Google, the service account's e-mail must be added as a user in each Search Console property and each GA4 property. The owner has to do that in the Google UIs; tell them exactly which properties.

### Step 8: First syncs, smallest first
```bash
python3 sync.py --api-only          # APIs and websites, no SSH
python3 sync.py --host <one-box>    # one SSH probe
python3 sync.py                     # everything
```
Read the step log after each one. Fix config mistakes, not the servers.

### Step 9: Fill in *what runs where*
For each box, look at what the probe found (`pm2` apps, Docker containers, systemd services, listening ports, nginx/Apache server names). Write a `runs` list into `servers.json`:
```json
"runs": [{"name": "shop-api", "kind": "pm2", "what": "Shop backend", "domains": ["api.example.com"], "port": 9000}]
```
Ask the owner when you can't tell what something is. Then re-run `python3 sync.py --api-only` (config is read on every request, so a page reload is enough).

### Step 10: Open it and walk through the findings
```bash
python3 serve.py --open
```
Go through *Problems now* and *Setup to tidy* with the owner. **Report; don't fix.** If they want something fixed on a server, that is a separate task: describe the change, get a clear yes, back up first, change one box at a time, and re-sync afterwards to confirm.

### Step 11: Keep it private
The owner's copy now contains their infrastructure map. Before any `git push`, confirm `.env`, `data/` and real config are not going to a public remote. Suggest a private repo or no remote for their own copy.

---

## Ground rules (also in CLAUDE.md)

- Read-only: GET requests to cloud APIs, read-only commands over SSH.
- SSH one box at a time. On "Connection refused" or a timeout: stop, report, wait.
- Never print, log or commit secrets. Keys and tokens stay in `.env` (chmod 600) or `~/.config/infra-dashboard/`.
- Ask before anything that changes a server, a firewall, DNS or a cloud setting.
