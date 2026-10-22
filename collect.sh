# Read-only health probe. Piped over SSH: ssh <host> 'bash -s' < collect.sh
# Prints sections marked "@@name"; sync.py parses them. Never changes anything on the box.
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
sec() { echo "@@$1"; }

sec host;    hostname; uname -r; . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"
sec uptime;  cat /proc/uptime
sec load;    cat /proc/loadavg; nproc
sec mem;     free -b
sec disk;    df -B1 -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x fuse.s3fs 2>/dev/null
sec reboot;  [ -f /var/run/reboot-required ] && echo yes || echo no
sec updates
if command -v apt-get >/dev/null; then
  apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | awk '/^Inst /{n++; if ($0 ~ /-security/) s++} END{print n+0, s+0}'
fi
sec aptstamp; stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %Y /var/lib/apt/lists/partial 2>/dev/null
sec services
for s in ssh sshd nginx apache2 docker mongod elasticsearch mariadb mysql postgresql redis-server rabbitmq-server fail2ban ufw unattended-upgrades cron php8.3-fpm php8.1-fpm; do
  st=$(systemctl is-active "$s" 2>/dev/null); en=$(systemctl is-enabled "$s" 2>/dev/null)
  [ -n "$en" ] && [ "$en" != "not-found" ] && echo "$s $st $en"
done
sec failed;  systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
sec ufw;     ufw status verbose 2>/dev/null
sec f2b
if command -v fail2ban-client >/dev/null; then
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do
    fail2ban-client status "$j" 2>/dev/null | awk -v j="$j" '/Currently banned/{c=$NF} /Total banned/{t=$NF} END{print j, c+0, t+0}'
  done
fi
sec sshd;    sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|permitrootlogin|pubkeyauthentication|kbdinteractiveauthentication|port|maxauthtries) '
sec ports;   ss -tlnpH 2>/dev/null | awk '{print $4, $6}'
sec udp;     ss -ulnpH 2>/dev/null | awk '{print $4, $6}'
sec certs
for c in /etc/letsencrypt/live/*/cert.pem; do
  [ -f "$c" ] && echo "$(basename "$(dirname "$c")") $(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)"
done
sec docker;  command -v docker >/dev/null && docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null
sec pm2
# pm2 jlist contains every process env (secrets), so it is reduced on the box and only these fields leave.
for d in /root/.local/share/fnm /root/.fnm; do [ -d "$d" ] && export PATH="$d:$PATH" && eval "$(fnm env 2>/dev/null)" >/dev/null 2>&1; done
[ -s /root/.nvm/nvm.sh ] && . /root/.nvm/nvm.sh >/dev/null 2>&1
if command -v pm2 >/dev/null; then
  pm2 jlist 2>/dev/null | python3 -c '
import json, sys, time
try: procs = json.load(sys.stdin)
except Exception: sys.exit()
for p in procs:
    e = p.get("pm2_env", {}); m = p.get("monit", {})
    up = int(time.time() - e.get("pm_uptime", 0) / 1000) if e.get("status") == "online" else 0
    print("|".join(str(x) for x in (p.get("name"), e.get("status"), m.get("memory", 0), m.get("cpu", 0), e.get("restart_time", 0), up)))
' 2>/dev/null
fi
sec php
# PHP versions serving web requests (fpm services) and installed CLIs. Read-only.
for u in $(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '$1 ~ /^php.*fpm/ {print $1}'); do
  bin=$(systemctl show -p ExecStart --value $u 2>/dev/null | grep -oE '/[^ ;]*php-fpm[0-9.]*' | head -1)
  v=$($bin -v 2>/dev/null | head -1 | awk '{print $2}')
  echo "fpm|$u|${v:-?}"
done
for b in /usr/bin/php[0-9]* /opt/php-*/bin/php; do [ -x "$b" ] && echo "cli|$b|$($b -r 'echo PHP_VERSION;' 2>/dev/null)"; done
sec node
# Node.js binaries that are running right now (any process), with their versions. Read-only.
for e in $(for p in $(pgrep -f 'node' 2>/dev/null); do readlink -f /proc/$p/exe 2>/dev/null; done | grep -E '/node$' | sort -u); do
  n=$(for p in $(pgrep -f 'node' 2>/dev/null); do [ "$(readlink -f /proc/$p/exe 2>/dev/null)" = "$e" ] && echo $p; done | wc -l)
  echo "$e|$($e -v 2>/dev/null)|$n"
done
sec memgroups
# RAM per app: every process's PSS (shared pages split fairly) and swap, grouped by
# pm2 app (incl. its child processes), Docker container, or systemd service. Read-only.
python3 - <<'PY' 2>/dev/null
import os, re, json, subprocess
def run(cmd):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception: return ""
pm2 = {}
out = run(["pm2", "jlist"])
try:
    for p in json.loads(out[out.index("["):]):
        if p.get("pid"): pm2[int(p["pid"])] = "pm2:" + p.get("name", "?")
except Exception: pass
docker = {}
for line in run(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"]).splitlines():
    if " " in line:
        cid, name = line.split(" ", 1); docker[cid] = "docker:" + name
procs = {}
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        st = open(f"/proc/{pid}/stat").read()
        ppid = int(st[st.rindex(")") + 2:].split()[1]); comm = st[st.index("(") + 1:st.rindex(")")]
        pss = swap = 0
        for l in open(f"/proc/{pid}/smaps_rollup"):
            if l.startswith("Pss:"): pss = int(l.split()[1])
            elif l.startswith("Swap:"): swap = int(l.split()[1])
        cg = open(f"/proc/{pid}/cgroup").read()
        procs[int(pid)] = (ppid, comm, pss, swap, cg)
    except Exception: pass
def group(pid):
    seen, p = 0, pid
    while p in procs and seen < 50:
        if p in pm2: return pm2[p]
        p = procs[p][0]; seen += 1
    ppid, comm, pss, swap, cg = procs[pid]
    m = re.search(r"(?:docker[-/])([0-9a-f]{64})", cg)
    if m: return docker.get(m.group(1), "docker:" + m.group(1)[:12])
    m = re.search(r"/([^/]+)\.service", cg)
    if m: return "service:" + m.group(1)
    if "user.slice" in cg: return "user session:" + comm
    return "other:" + comm
tot = {}
for pid, (ppid, comm, pss, swap, cg) in procs.items():
    if not pss and not swap: continue
    g = group(pid); t = tot.setdefault(g, [0, 0, 0]); t[0] += pss; t[1] += swap; t[2] += 1
for g, (pss, swap, n) in sorted(tot.items(), key=lambda x: -(x[1][0] + x[1][1]))[:40]:
    print(f"{g}|{pss}|{swap}|{n}")
PY
sec lastlogin; last -n 5 -w -F 2>/dev/null | grep -v -e '^$' -e '^wtmp' -e 'reboot' | awk '{print $1, $3, $5, $6, $7, $8}'
sec end
