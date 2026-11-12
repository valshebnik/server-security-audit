# server-security-audit

A single-file, read-only security audit for Linux servers. No dependencies, no
installation, no changes to the host: it reads configuration, sockets, container
metadata and logs, then prints a prioritised report with a risk score.

Built after a real incident: a Redis container published to the internet with a
dictionary password was compromised, a Monero miner and a scanning worm were
installed, and the host started scanning other networks within hours. Every
check in this tool exists because something like it was missed.

```
$ sudo ./server-security-audit.sh

server-security-audit 1.0.0
host: web-01   date: 2026-11-08T18:20:04Z   user: root

== System, patching and kernel hardening
[PASS] SYS-01    info     Host inventory
[WARN] SYS-03    high     Running kernel is older than the installed kernel
        running: 6.8.0-79
        installed: 6.8.0-149
        fix: reboot to load the patched kernel
...
[FAIL] DOCK-07   critical Container port published on all interfaces
        redis: 0.0.0.0:6379->6379/tcp
        fix: bind to 127.0.0.1 in docker-compose: "127.0.0.1:6379:6379"
...

== Summary

  critical  2
  high      5
  medium    3
  low       1
  info      9
  passed    34
  skipped    2

  risk score 31/100

VERDICT: 2 critical and 5 high severity findings require action
```

## Quick start

```bash
git clone https://github.com/OWNER/server-security-audit.git
cd server-security-audit
sudo ./server-security-audit.sh
```

Without cloning, download and run in two steps:

```bash
curl -fsSLO https://raw.githubusercontent.com/OWNER/server-security-audit/main/server-security-audit.sh
sudo bash server-security-audit.sh
```

The script is not meant to be piped straight from `curl` into a shell. Download
it, read it, then run it.

Requirements: bash 4 or newer and coreutils. Everything else is optional and
detected at runtime: `docker`, `ss` or `netstat`, `nginx`, `openssl`,
`fail2ban-client`, `journalctl`, `apt-get`, `dnf` or `yum`. Missing tools produce
`SKIP` lines, never errors.

## Options

| Option | Description |
| --- | --- |
| `-f, --format text\|json` | Output format. `json` is machine readable and suitable for CI |
| `-s, --min-severity <sev>` | Show only `info`, `low`, `medium`, `high` or `critical` and above |
| `-o, --only <ids>` | Run only these sections or checks: `--only SSH,NET,DOCK-07` |
| `-k, --skip <ids>` | Skip sections or checks |
| `--no-pass`, `-q` | Hide `PASS` lines, show only problems |
| `--fast` | Skip slow checks: package updates and log analysis |
| `--color auto\|always\|never` | Colour control, `NO_COLOR` is respected |
| `-V, --version` | Print version |
| `-h, --help` | Print help |

Exit codes: `0` no critical or high findings, `1` at least one high, `2` at least
one critical, `64` for a bad command line.

## What it checks

### SYS - system and kernel hardening

| ID | Severity | Check |
| --- | --- | --- |
| SYS-01 | info | Host inventory: OS, kernel, architecture, uptime |
| SYS-02 | medium | Whether the audit runs as root |
| SYS-03 | high | Running kernel versus the newest installed kernel |
| SYS-04 | high | Pending reboot flag from the package manager |
| SYS-05 | high | Pending package and security updates |
| SYS-06 | medium | Automatic security updates enabled |
| SYS-07 | medium | AppArmor or SELinux active, count of unconfined processes |
| SYS-08 | low | Clock synchronisation |
| SYS-09 | medium | Filesystems above 85% usage |
| SYS-10 | medium | `rp_filter` reverse path filtering |
| SYS-11 | medium | SYN cookies |
| SYS-12 | low | ICMP redirects ignored |
| SYS-13 | low | Source routed packets rejected |
| SYS-14 | low | `dmesg_restrict` |
| SYS-15 | low | `kptr_restrict` |
| SYS-16 | low | `fs.protected_hardlinks` |
| SYS-17 | low | `fs.protected_symlinks` |
| SYS-18 | critical | Accounts with UID 0 other than root |
| SYS-19 | critical | Accounts with an empty password |
| SYS-20 | medium | Passwordless sudo entries |
| SYS-21 | low | Core dumps written to disk |
| SYS-22 | low | auditd running |

### SSH - remote access

| ID | Severity | Check |
| --- | --- | --- |
| SSH-01 | high | sshd present, effective configuration readable |
| SSH-02 | critical | `PermitRootLogin` |
| SSH-03 | critical | `PasswordAuthentication` |
| SSH-04 | high | `PermitEmptyPasswords` |
| SSH-05 | medium | `MaxAuthTries` |
| SSH-06 | low | `LoginGraceTime` |
| SSH-07 | low | Access limited by `AllowUsers` or `AllowGroups` |
| SSH-08 | low | X11 forwarding |
| SSH-09 | high | `authorized_keys` inventory, owners and permissions |
| SSH-10 | medium | Number of authorised keys |
| SSH-11 | medium | fail2ban running, jail list |

Effective values come from `sshd -T` when the script runs as root, and fall back
to parsing `sshd_config` and `sshd_config.d/*.conf` otherwise.

### FW - host firewall

| ID | Severity | Check |
| --- | --- | --- |
| FW-01 | critical | Any firewall enforcing drop or reject rules |
| FW-02 | critical | Default inbound policy is deny |
| FW-03 | high | Outbound traffic to Redis ports 6379, 6380, 6381, 16379 restricted |
| FW-04 | medium | Outbound SMTP ports restricted |
| FW-05 | medium | Rules persist across reboot |
| FW-06 | medium | IPv6 filtered with the same policy |

FW-03 is the check that would have stopped the incident that inspired this tool:
a compromised container scanning and infecting other Redis instances is the
standard behaviour of Redis worms, and blocking egress costs one iptables rule.

### NET - network exposure

| ID | Severity | Check |
| --- | --- | --- |
| NET-01 | info | Count of public and loopback listeners |
| NET-02 | critical | Database or cache service reachable from the network |
| NET-03 | medium | Inventory of ports bound to all interfaces |
| NET-04 | critical | Established outbound connections to mining or database ports |

Port 6379 and friends, 5432, 3306, 27017, 9200, 11211, 2375 and other
infrastructure ports are treated as never-public. Works through `ss`, `netstat`
or a direct `/proc/net` parser, so it also runs on minimal containers.

### DOCK - containers

| ID | Severity | Check |
| --- | --- | --- |
| DOCK-01 | high | Docker available, container count |
| DOCK-02 | critical | Privileged containers |
| DOCK-03 | critical | Docker socket mounted into a container |
| DOCK-04 | high | Containers using host networking |
| DOCK-05 | high | Containers with extra capabilities: SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL |
| DOCK-06 | medium | Containers running as root inside the container |
| DOCK-07 | critical | Ports published on all interfaces, with the dangerous ones singled out |
| DOCK-08 | critical | Weak or default credentials in container environment variables |
| DOCK-09 | low | Images pinned to `:latest` |
| DOCK-10 | medium | Images older than 90 days |
| DOCK-11 | medium | `daemon.json` hardening: no-new-privileges, live-restore, log limits |
| DOCK-12 | medium | Users in the `docker` group, socket permissions |

DOCK-08 reports the variable name and the reason, never the value.

### SEC - secrets and permissions

| ID | Severity | Check |
| --- | --- | --- |
| SEC-01 | high | `.env` files readable by other users |
| SEC-02 | critical | Dictionary or short passwords in env and compose files |
| SEC-03 | high | Passwords hardcoded in compose files instead of variables |
| SEC-04 | critical | Secret files tracked by git |
| SEC-05 | high | Private keys world readable |
| SEC-06 | medium | World writable files in `/etc` |
| SEC-07 | critical | `/etc/ld.so.preload` not empty |

SEC-02 compares values against a list of the passwords that appear in every
brute force dictionary. A short random value is still reported, because length
matters more than entropy for online guessing.

### MAL - malware and persistence

| ID | Severity | Check |
| --- | --- | --- |
| MAL-01 | critical | Known miner and worm process names |
| MAL-02 | high | A single process above 80% CPU |
| MAL-03 | high | Executables in `/tmp`, `/var/tmp`, `/dev/shm` |
| MAL-04 | critical | Cron entries that download or decode and execute |
| MAL-05 | critical | Systemd units starting code from temporary paths |
| MAL-06 | medium | Executables created in the last 7 days in `/root` and `/opt` |
| MAL-07 | low | Hidden files in working directories |
| MAL-08 | low | Failed systemd units |

Process name patterns are stored as fragments and joined at runtime, so
antivirus engines and mail gateways do not quarantine the script.

### LOG - authentication history

| ID | Severity | Check |
| --- | --- | --- |
| LOG-01 | medium/high | Failed login attempts in the last 24 hours |
| LOG-02 | medium | Top source addresses of failed logins |
| LOG-03 | medium | Successful logins in the last 24 hours |

Uses persistent journald storage when present, `/var/log/auth.log` otherwise,
and says so when neither exists.

### WEB - reverse proxy and TLS

| ID | Severity | Check |
| --- | --- | --- |
| WEB-01 | low | nginx or apache2 detected |
| WEB-02 | medium | Duplicate `server_name` entries from `nginx -t` |
| WEB-03 | low | `server_tokens off` |
| WEB-04 | medium | HTTP to HTTPS redirect |
| WEB-05 | low | `proxy_pass` pointing at a wildcard address |
| WEB-06 | medium/high | Let's Encrypt certificate expiry |

## Risk score

The score starts at 100 and subtracts 15 per critical, 8 per high, 4 per medium
and 1 per low finding, with a floor of 0. It is a rough indicator for tracking a
single host over time, not a certification.

## Using it in CI

`--format json` is stable enough for automation:

```bash
sudo ./server-security-audit.sh --format json > audit.json
jq -r '.counts.critical, .counts.high' audit.json
jq -r '.findings[] | select(.severity=="critical") | "\(.id) \(.title)"' audit.json
```

Fail a pipeline on any critical finding:

```bash
sudo ./server-security-audit.sh --format json --only SYS,SSH,FW,NET,DOCK > audit.json || true
if [ "$(jq '.counts.critical' audit.json)" -gt 0 ]; then
  echo "critical findings present"
  exit 1
fi
```

## What it does not do

- It does not change anything: no writes, no package installs, no config edits,
  no `sysctl -w`, no firewall changes. Fixes are printed as `fix:` lines only.
- It does not scan the network, does not resolve external names, and does not
  upload anything. Nothing leaves the host.
- It is not a compliance scanner. It covers the mistakes that actually get hosts
  compromised: exposed datastores, weak credentials, missing egress filtering,
  unpatched kernels, no brute force protection.

## Design notes

- One file, no dependencies, safe to copy to a host over SSH.
- Every check reports `PASS`, `WARN`, `FAIL`, `INFO` or `SKIP`. A check that
  cannot run says why instead of failing silently.
- Severity is separate from status, so `--min-severity high` gives a short list.
- `set -u` is disabled while checks run, so one unexpected host layout cannot
  abort the whole audit.
- Colours are off when output is not a terminal or `NO_COLOR` is set.

## Contributing

New checks are welcome if they meet three conditions: read-only, no new
dependencies, and a concrete incident they would have caught. Add the check
function, a row in the table above, and a test fixture if the parsing is
non-trivial.

```bash
bash -n server-security-audit.sh
shellcheck --severity=warning server-security-audit.sh
./test/smoke.sh
sudo ./server-security-audit.sh --color never
```

CI runs the same three commands on every push, plus a JSON validation job.

## License

MIT, see [LICENSE](LICENSE).
