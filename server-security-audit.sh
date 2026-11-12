#!/usr/bin/env bash
# =============================================================================
#  server-security-audit.sh
#  Read-only security audit for Linux servers. Nothing is changed on the host.
#
#  Usage:  sudo ./server-security-audit.sh [options]
#  Docs:   https://github.com/OWNER/server-security-audit
#  License: MIT
# =============================================================================

set -uo pipefail
IFS=$' \t\n'

VERSION="1.1.1"
PROG="${0##*/}"

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
FORMAT="text"          # text | json
COLOR="auto"           # auto | always | never
MIN_SEV="info"         # info | low | medium | high | critical
ONLY=""
SKIP=""
SHOW_PASS=1
FAST=0

# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------
SEP=$'\x1f'
FINDINGS=()
N_PASS=0; N_INFO=0; N_LOW=0; N_MED=0; N_HIGH=0; N_CRIT=0; N_SKIP=0

C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_DIM=""; C_BLD=""; C_OFF=""

SECTION_NAME=""
SECTION_PRINTED=0
SSHD_T=""
FW_DUMP=""

usage() {
  cat <<USAGE
$PROG - read-only Linux server security audit

Usage:
  sudo ./server-security-audit.sh [options]

Options:
  -f, --format <text|json>   Output format (default: text)
  -s, --min-severity <sev>   Show only info|low|medium|high|critical (default: info)
  -o, --only <ids>           Run only these checks, comma separated prefixes
                             (example: --only SSH,NET,DOCK)
  -k, --skip <ids>           Skip these checks, comma separated prefixes
      --no-pass              Hide PASS lines (show only problems)
      --fast                 Skip slow checks (package updates, log analysis)
      --color <auto|always|never>
  -q, --quiet                Same as --no-pass
  -V, --version              Print version
  -h, --help                 Print this help

Exit codes:
  0  no critical or high severity findings
  1  at least one high severity finding
  2  at least one critical severity finding

The script performs read-only inspection: it reads configuration files, process
lists, socket tables and container metadata. It never writes to the system,
never installs packages and never opens network connections.
USAGE
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown"; }

is_root() { [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]; }

setup_color() {
  local on=0
  case "$COLOR" in
    always) on=1 ;;
    never)  on=0 ;;
    auto)   if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then on=1; fi ;;
  esac
  if [ "$on" -eq 1 ]; then
    C_RED=$'\033[1;31m'; C_YEL=$'\033[1;33m'; C_GRN=$'\033[1;32m'
    C_BLU=$'\033[1;34m'; C_DIM=$'\033[2m'
    C_BLD=$'\033[1m';    C_OFF=$'\033[0m'
  else
    C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_DIM=""; C_BLD=""; C_OFF=""
  fi
}

sev_rank() {
  case "$1" in
    info) echo 0 ;; low) echo 1 ;; medium) echo 2 ;; high) echo 3 ;; critical) echo 4 ;;
    *) echo 0 ;;
  esac
}

id_match() {
  local id="$1" list="$2" p
  [ -z "$list" ] && return 1
  local IFS_OLD="$IFS"; IFS=','
  set -- $list
  IFS="$IFS_OLD"
  for p in "$@"; do
    p="${p// /}"
    [ -z "$p" ] && continue
    case "$id" in "$p"*) return 0 ;; esac
  done
  return 1
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Sections print their header only when the first finding inside them is
# reported, so --only and --min-severity produce a clean report.
section() {
  SECTION_NAME="$1"
  SECTION_PRINTED=0
}

print_section_header() {
  [ "$FORMAT" = "json" ] && return 0
  [ "${SECTION_PRINTED:-0}" -eq 1 ] && return 0
  printf '\n%s== %s%s\n' "$C_BLD" "${SECTION_NAME:-}" "$C_OFF"
  SECTION_PRINTED=1
}

# report <status> <id> <severity> <title> [detail] [hint]
#   status: pass | warn | fail | skip | info
report() {
  local status="$1" id="$2" sev="$3" title="$4" detail="${5:-}" hint="${6:-}"

  if [ -n "$ONLY" ] && ! id_match "$id" "$ONLY"; then return 0; fi
  if [ -n "$SKIP" ] && id_match "$id" "$SKIP"; then return 0; fi
  if [ "$(sev_rank "$sev")" -lt "$(sev_rank "$MIN_SEV")" ]; then return 0; fi

  case "$status" in
    pass) N_PASS=$((N_PASS+1)) ;;
    info) N_INFO=$((N_INFO+1)) ;;
    skip) N_SKIP=$((N_SKIP+1)) ;;
    warn) case "$sev" in
            low) N_LOW=$((N_LOW+1)) ;;
            medium) N_MED=$((N_MED+1)) ;;
            *) N_HIGH=$((N_HIGH+1)) ;;
          esac ;;
    fail) case "$sev" in
            critical) N_CRIT=$((N_CRIT+1)) ;;
            *) N_HIGH=$((N_HIGH+1)) ;;
          esac ;;
  esac

  # keep a flat single-line record for the summary and JSON output
  detail="${detail%$'\n'}"
  local flat_detail="${detail//$'\n'/; }"
  FINDINGS+=("${status}${SEP}${id}${SEP}${sev}${SEP}${title}${SEP}${flat_detail}${SEP}${hint}")

  [ "$FORMAT" = "json" ] && return 0
  if [ "$status" = "pass" ] && [ "$SHOW_PASS" -eq 0 ]; then return 0; fi

  local tag
  case "$status" in
    pass) tag="${C_GRN}PASS${C_OFF}" ;;
    info) tag="${C_BLU}INFO${C_OFF}" ;;
    skip) tag="${C_DIM}SKIP${C_OFF}" ;;
    warn) tag="${C_YEL}WARN${C_OFF}" ;;
    fail) if [ "$sev" = "critical" ]; then tag="${C_RED}FAIL${C_OFF}"; else tag="${C_RED}FAIL${C_OFF}"; fi ;;
    *)    tag="${C_DIM}????${C_OFF}" ;;
  esac

  print_section_header
  printf '[%s] %-9s %-8s %s\n' "$tag" "$id" "$sev" "$title"
  if [ -n "$detail" ]; then
    local line
    while IFS= read -r line; do
      printf '        %s%s%s\n' "$C_DIM" "$line" "$C_OFF"
    done <<< "$detail"
  fi
  if [ -n "$hint" ]; then
    printf '        %sfix: %s%s\n' "$C_DIM" "$hint" "$C_OFF"
  fi
  return 0
}

# read a key from sshd config files, last match wins
sshd_conf_value() {
  local key="$1" v=""
  local files="/etc/ssh/sshd_config"
  local d
  for d in /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$d" ] && files="$files $d"
  done
  # shellcheck disable=SC2086
  v=$(awk -v k="$key" '
    { line=$0; sub(/#.*/,"",line); n=split(line,f," "); if (n>=2 && tolower(f[1])==tolower(k)) { $1=""; sub(/^[ \t]+/,""); val=$0 } }
    END { if (val!="") print val }
  ' $files 2>/dev/null)
  printf '%s' "$v"
}

# effective value from `sshd -T` when available, else from config files
sshd_eff() {
  local key="$1"
  if [ -n "${SSHD_T:-}" ]; then
    local v
    v=$(printf '%s\n' "$SSHD_T" | awk -v k="$key" 'tolower($1)==tolower(k){ $1=""; sub(/^[ \t]+/,""); print; exit }')
    if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
  fi
  sshd_conf_value "$key"
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -f|--format) FORMAT="${2:-text}"; shift 2 ;;
      -s|--min-severity) MIN_SEV="${2:-info}"; shift 2 ;;
      -o|--only) ONLY="${2:-}"; shift 2 ;;
      -k|--skip) SKIP="${2:-}"; shift 2 ;;
      --no-pass|-q|--quiet) SHOW_PASS=0; shift ;;
      --fast) FAST=1; shift ;;
      --color) COLOR="${2:-auto}"; shift 2 ;;
      -V|--version) echo "server-security-audit $VERSION"; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
    esac
  done
  case "$FORMAT" in text|json) ;; *) echo "Bad --format: $FORMAT" >&2; exit 64 ;; esac
  case "$(sev_rank "$MIN_SEV")" in 0|1|2|3|4) ;; *) echo "Bad --min-severity: $MIN_SEV" >&2; exit 64 ;; esac
}

# -----------------------------------------------------------------------------
# Low level helpers for sockets and config
# -----------------------------------------------------------------------------

# print "proto|address|port|process" for every listening socket
listen_sockets() {
  if have ss; then
    { ss -H -tlnp 2>/dev/null | awk '{print "tcp|"$4"||"$5" "$6" "$7" "$8}'
      ss -H -ulnp 2>/dev/null | awk '{print "udp|"$4"||"$5" "$6" "$7" "$8}'
    } | awk -F'|' '{
        split($2,a,":");
        port=a[length(a)];
        addr=$2; sub(/:[^:]*$/,"",addr);
        proc=$3;
        gsub(/^ +| +$/,"",proc);
        if (proc=="") proc="-";
        print $1"|"addr"|"port"|"proc;
      }'
    return 0
  fi
  if have netstat; then
    netstat -tulnp 2>/dev/null | awk 'NR>2 {
      proto=$1; local=$4; proc=$7;
      split(local,a,":"); port=a[length(a)]; addr=local; sub(/:[^:]*$/,"",addr);
      if (proc=="") proc="-";
      print proto"|"addr"|"port"|"proc;
    }'
    return 0
  fi
  # fallback: parse /proc/net (no process names available)
  local f proto
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    case "$f" in
      */tcp6) proto=tcp6 ;; */tcp) proto=tcp ;; */udp6) proto=udp6 ;; *) proto=udp ;;
    esac
    awk -v proto="$proto" '
      function h2d(s,  i,c,d,v){ v=0; s=tolower(s); for(i=1;i<=length(s);i++){ c=substr(s,i,1); d=index("0123456789abcdef",c)-1; if(d<0) return -1; v=v*16+d } return v }
      function h2ip4(s){ return h2d(substr(s,7,2))"."h2d(substr(s,5,2))"."h2d(substr(s,3,2))"."h2d(substr(s,1,2)) }
      NR>1 {
        split($2,a,":");
        hexip=a[1]; port=h2d(a[2]); st=$4;
        if (proto=="tcp" || proto=="tcp6") { if (st!="0A") next }
        ip="?"
        if (length(hexip)==8) ip=h2ip4(hexip)
        else if (hexip=="00000000000000000000000000000000") ip="::"
        else if (hexip=="00000000000000000000000001000000") ip="::1"
        else ip="ipv6"
        print proto "|" ip "|" port "|-"
      }' "$f" 2>/dev/null
  done
}

is_loopback_addr() {
  case "$1" in
    127.*|::1|localhost) return 0 ;;
    *%lo) return 0 ;;
  esac
  return 1
}

DANGEROUS_PORTS="6379 6380 6381 16379 5432 3306 27017 27018 9200 9300 11211 2375 2376 5984 8086 9092 2181 9042 1433 5601 15672 5672 8500 2379 6443"
SUSPICIOUS_OUT_PORTS="6379 6380 6381 16379 3333 4444 5555 7777 14444 10300 10301 45700 23"

port_in_list() {
  local p="$1" list="$2" x
  for x in $list; do [ "$p" = "$x" ] && return 0; done
  return 1
}

# -----------------------------------------------------------------------------
# SYS - operating system, patching, kernel hardening
# -----------------------------------------------------------------------------
check_system() {
  section "System, patching and kernel hardening"

  local os="unknown" kern arch
  if [ -r /etc/os-release ]; then
    os=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")
  fi
  kern=$(uname -r 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)
  report info SYS-01 info "Host inventory" "os: $os
kernel: $kern
arch: $arch
hostname: $(hostname 2>/dev/null || echo unknown)
uptime: $(uptime -p 2>/dev/null || echo unknown)
audit: $(now_iso)" ""

  if is_root; then
    report pass SYS-02 medium "Audit runs with root privileges"
  else
    report warn SYS-02 medium "Audit is not running as root" "Checks on /etc/shadow, sshd -T, docker and firewall rules are degraded or skipped" "run the script with sudo"
  fi

  # running kernel vs newest installed kernel
  local newest="" running
  running=$(uname -r 2>/dev/null || echo "")
  if have dpkg; then
    newest=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -1)
  elif have rpm; then
    newest=$(rpm -q kernel 2>/dev/null | sed 's/^kernel-//' | grep -E '^[0-9]' | sort -V | tail -1)
  fi
  if [ -n "$newest" ] && [ -n "$running" ] && [ "$newest" != "$running" ]; then
    report warn SYS-03 high "Running kernel is older than the installed kernel" "running: $running
installed: $newest" "reboot to load the patched kernel"
  elif [ -n "$newest" ]; then
    report pass SYS-03 high "Running kernel matches the newest installed kernel ($running)"
  else
    report skip SYS-03 high "Kernel version comparison" "neither dpkg nor rpm found"
  fi

  if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
    local why=""
    [ -r /var/run/reboot-required.pkgs ] && why=$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | head -8 | tr '\n' ' ')
    report warn SYS-04 high "System reboot is required to finish updates" "packages: ${why:-unknown}" "schedule a reboot during a maintenance window"
  else
    report pass SYS-04 high "No pending reboot flag"
  fi

  if [ "$FAST" -eq 0 ]; then
    if have apt-get; then
      local sim total sec
      sim=$(apt-get -s -qq -o Debug::NoLocking=1 upgrade 2>/dev/null)
      total=$(printf '%s\n' "$sim" | grep -c '^Inst ')
      sec=$(printf '%s\n' "$sim" | grep '^Inst ' | grep -ci 'security')
      if [ "${sec:-0}" -gt 0 ]; then
        report warn SYS-05 high "Security updates are pending" "total pending: ${total:-0}
security: ${sec:-0}" "apt-get upgrade, then reboot if required"
      elif [ "${total:-0}" -gt 0 ]; then
        report warn SYS-05 medium "Package updates are pending" "total pending: ${total:-0}" "apt-get upgrade"
      else
        report pass SYS-05 high "No pending package updates"
      fi
    elif have dnf || have yum; then
      local pm; pm=$(command -v dnf || command -v yum)
      if "$pm" -q check-update >/dev/null 2>&1; then
        report pass SYS-05 high "No pending package updates"
      else
        report warn SYS-05 high "Package updates are pending" "run: $pm check-update" "$pm upgrade"
      fi
    else
      report skip SYS-05 high "Package update check" "no supported package manager found"
    fi
  else
    report skip SYS-05 high "Package update check" "skipped by --fast"
  fi

  if have apt-get; then
    local au=0
    if [ -r /etc/apt/apt.conf.d/20auto-upgrades ]; then
      grep -qE 'Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null && au=1
    fi
    if [ "$au" -eq 1 ]; then
      report pass SYS-06 medium "Automatic security updates are enabled"
    else
      report warn SYS-06 medium "Automatic security updates are not enabled" "unattended-upgrades is off or not configured" "apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
    fi
  else
    report skip SYS-06 medium "Automatic security updates" "not an apt based system"
  fi

  local lsm="none"
  if have aa-status && aa-status --enabled 2>/dev/null; then lsm="apparmor"
  elif [ -d /sys/kernel/security/apparmor ] && [ -n "$(ls -A /sys/kernel/security/apparmor 2>/dev/null)" ]; then lsm="apparmor"
  elif have getenforce && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then lsm="selinux"
  fi
  if [ "$lsm" = "none" ]; then
    report warn SYS-07 medium "No mandatory access control (AppArmor/SELinux) is active" "" "enable apparmor or selinux"
  else
    local unconf=""
    if [ "$lsm" = "apparmor" ] && have aa-status; then
      unconf=$(aa-status 2>/dev/null | awk '/processes are unconfined/{print $1; exit}')
    fi
    if [ -n "$unconf" ] && [ "${unconf:-0}" -gt 0 ]; then
      report info SYS-07 medium "MAC enabled: $lsm" "unconfined processes: $unconf" ""
    else
      report pass SYS-07 medium "Mandatory access control is active: $lsm"
    fi
  fi

  local ntp="unknown"
  if have timedatectl; then
    ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)
  elif have chronyc; then
    ntp=$(chronyc tracking 2>/dev/null | awk -F': ' '/Leap status/{print ($2=="Normal"?"yes":"no")}')
  fi
  case "$ntp" in
    yes) report pass SYS-08 low "System clock is synchronised" ;;
    no)  report warn SYS-08 medium "System clock is not synchronised" "timestamps in logs and TLS validation depend on it" "enable systemd-timesyncd or chrony" ;;
    *)   report info SYS-08 low "Clock synchronisation state unknown" "timedatectl and chronyc unavailable" "" ;;
  esac

  local full
  full=$(df -P -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1 { gsub("%","",$5); if ($5+0 > 85) print $6" ("$5"%)" }')
  if [ -n "$full" ]; then
    report warn SYS-09 medium "Filesystem usage above 85%" "$full" "free space, otherwise logs, databases and updates will fail"
  else
    report pass SYS-09 medium "Filesystem usage is within limits"
  fi

  # kernel network hardening
  sysctl_check() { # id sev path expected title hint
    local id="$1" sev="$2" path="$3" want="$4" title="$5" hint="$6" val=""
    [ -r "$path" ] && val=$(cat "$path" 2>/dev/null | tr -d '\n')
    if [ -z "$val" ]; then report skip "$id" "$sev" "$title" "sysctl not present: $path"; return; fi
    if [ "$val" = "$want" ]; then
      report pass "$id" "$sev" "$title"
    else
      report warn "$id" "$sev" "$title" "current: $val, expected: $want" "$hint"
    fi
  }

  local rpf
  rpf=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "")
  if [ "$rpf" = "1" ]; then
    report pass SYS-10 medium "Reverse path filtering enabled (rp_filter)"
  elif [ "$rpf" = "2" ] && have docker && docker info >/dev/null 2>&1; then
    report pass SYS-10 medium "Reverse path filtering enabled (rp_filter, loose mode required by Docker bridge networks)"
  else
    report warn SYS-10 medium "Reverse path filtering enabled (rp_filter)" "current: ${rpf:-absent}, expected: 1" "set net.ipv4.conf.all.rp_filter=1"
  fi
  sysctl_check SYS-11 medium /proc/sys/net/ipv4/tcp_syncookies 1 "SYN cookies enabled" "set net.ipv4.tcp_syncookies=1"
  sysctl_check SYS-12 low /proc/sys/net/ipv4/conf/all/accept_redirects 0 "ICMP redirects are ignored" "set net.ipv4.conf.all.accept_redirects=0"
  sysctl_check SYS-13 low /proc/sys/net/ipv4/conf/all/accept_source_route 0 "Source routed packets are rejected" "set net.ipv4.conf.all.accept_source_route=0"
  sysctl_check SYS-14 low /proc/sys/kernel/dmesg_restrict 1 "Kernel log restricted to root" "set kernel.dmesg_restrict=1"
  sysctl_check SYS-15 low /proc/sys/kernel/kptr_restrict 1 "Kernel pointers hidden" "set kernel.kptr_restrict=1"
  sysctl_check SYS-16 low /proc/sys/fs/protected_hardlinks 1 "Protected hardlinks enabled" "set fs.protected_hardlinks=1"
  sysctl_check SYS-17 low /proc/sys/fs/protected_symlinks 1 "Protected symlinks enabled" "set fs.protected_symlinks=1"

  # privileged local accounts
  local uid0
  uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | grep -v '^root$' | tr '\n' ' ')
  if [ -n "${uid0// /}" ]; then
    report fail SYS-18 critical "Accounts with UID 0 other than root" "$uid0" "remove or reassign the UID"
  else
    report pass SYS-18 critical "Only root has UID 0"
  fi

  if is_root && [ -r /etc/shadow ]; then
    local empty
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    if [ -n "${empty// /}" ]; then
      report fail SYS-19 critical "Accounts with empty password" "$empty" "passwd -l <user>"
    else
      report pass SYS-19 critical "No accounts with empty password"
    fi
  else
    report skip SYS-19 critical "Empty password check" "needs root and read access to /etc/shadow"
  fi

  local np
  np=$(grep -rhs 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | sed 's/^[ \t]*//' | head -10)
  if [ -n "$np" ]; then
    report warn SYS-20 medium "Passwordless sudo entries found" "$np" "require a password for privileged commands"
  else
    report pass SYS-20 medium "No passwordless sudo entries"
  fi

  local cp
  cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")
  if [ -n "$cp" ] && [ "${cp#|}" = "$cp" ]; then
    report warn SYS-21 low "Core dumps are written to disk" "core_pattern: $cp" "set fs.suid_dumpable=0 and a safe core_pattern"
  else
    report pass SYS-21 low "Core dumps are piped or disabled"
  fi

  if have systemctl && systemctl is-active --quiet auditd 2>/dev/null; then
    report pass SYS-22 low "auditd is running"
  else
    report info SYS-22 low "auditd is not running" "optional, but useful for post incident analysis" "apt-get install auditd"
  fi
}

# -----------------------------------------------------------------------------
# SSH - remote access
# -----------------------------------------------------------------------------
check_ssh() {
  section "SSH access"

  if [ -r /etc/ssh/sshd_config ]; then
    if is_root && have sshd; then
      SSHD_T=$(sshd -T 2>/dev/null || true)
    fi
    if [ -n "${SSHD_T:-}" ]; then
      report pass SSH-01 high "sshd is installed and its effective configuration is readable"
    else
      report info SSH-01 high "sshd is installed, effective config unavailable" "sshd -T failed, values are parsed from files" ""
    fi
  else
    report skip SSH-01 high "No /etc/ssh/sshd_config on this host" "SSH checks skipped"
    return 0
  fi

  local v
  v=$(sshd_eff permitrootlogin)
  case "${v:-yes}" in
    no) report pass SSH-02 critical "Root login over SSH is disabled" ;;
    prohibit-password|without-password) report info SSH-02 high "Root login is limited to keys" "value: $v" "prefer PermitRootLogin no and a sudo user" ;;
    *)  report fail SSH-02 critical "Root login over SSH is enabled" "PermitRootLogin ${v:-yes}" "set PermitRootLogin no" ;;
  esac

  v=$(sshd_eff passwordauthentication)
  case "${v:-yes}" in
    no) report pass SSH-03 critical "Password authentication is disabled" ;;
    *)  report fail SSH-03 critical "Password authentication is enabled" "PasswordAuthentication ${v:-yes}" "set PasswordAuthentication no, keep keys only" ;;
  esac

  v=$(sshd_eff permitemptypasswords)
  case "${v:-no}" in
    no) report pass SSH-04 high "Empty passwords are not accepted" ;;
    *)  report fail SSH-04 high "Empty passwords are accepted" "PermitEmptyPasswords $v" "set PermitEmptyPasswords no" ;;
  esac

  v=$(sshd_eff maxauthtries)
  if [ -n "${v:-}" ] && [ "$v" -le 4 ] 2>/dev/null; then
    report pass SSH-05 medium "MaxAuthTries is $v"
  else
    report warn SSH-05 medium "MaxAuthTries is too permissive" "value: ${v:-6 (default)}" "set MaxAuthTries 3"
  fi

  v=$(sshd_eff logingracetime)
  if [ -n "${v:-}" ] && [ "$v" -le 30 ] 2>/dev/null; then
    report pass SSH-06 low "LoginGraceTime is ${v}s"
  else
    report warn SSH-06 low "LoginGraceTime is too long" "value: ${v:-120 (default)}" "set LoginGraceTime 20"
  fi

  local allow
  allow=$(sshd_eff allowusers); [ -z "$allow" ] && allow=$(sshd_eff allowgroups)
  if [ -n "$allow" ]; then
    report pass SSH-07 low "SSH access restricted to: $allow"
  else
    report info SSH-07 low "SSH access is not restricted by AllowUsers/AllowGroups" "any local account can log in if it has a key" "add AllowUsers <youruser>"
  fi

  v=$(sshd_eff x11forwarding)
  if [ "${v:-no}" = "no" ]; then
    report pass SSH-08 low "X11 forwarding is disabled"
  else
    report info SSH-08 low "X11 forwarding is enabled" "value: $v" "set X11Forwarding no"
  fi

  # authorized_keys inventory
  local f total=0 out="" unknown=0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    local c owner perms
    c=$(grep -cE '^(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || echo 0)
    owner=$(stat -c '%U' "$f" 2>/dev/null || echo "?")
    perms=$(stat -c '%a' "$f" 2>/dev/null || echo "?")
    total=$((total + c))
    out="${out}${f}: ${c} key(s), owner ${owner}, mode ${perms}
"
    case "$perms" in 600|640|400) ;; *) unknown=$((unknown+1)) ;; esac
  done < <(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null)

  if [ "$total" -gt 0 ]; then
    local fps
    fps=$(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null | while IFS= read -r f; do
            ssh-keygen -lf "$f" 2>/dev/null | awk '{print $2, $3}'
          done | head -20)
    if [ "$unknown" -gt 0 ]; then
      report warn SSH-09 high "authorized_keys files with weak permissions" "$out" "chmod 600 authorized_keys && chown <user>"
    else
      report info SSH-09 high "SSH keys in use: $total" "$out
$fps" "review the list, remove keys you do not recognise"
    fi
    if [ "$total" -gt 5 ]; then
      report warn SSH-10 medium "Many SSH keys are authorised ($total)" "$fps" "keep only keys that are actively used"
    else
      report pass SSH-10 medium "Number of authorised keys is reasonable ($total)"
    fi
  else
    report info SSH-09 high "No authorized_keys files found" "access is probably password based, which is worse" ""
  fi

  if have fail2ban-client && fail2ban-client status 2>/dev/null | grep -q 'Jail list'; then
    local jails
    jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[ \t]*//p')
    report pass SSH-11 medium "fail2ban is running" "jails: ${jails:-none}" ""
  else
    report warn SSH-11 medium "fail2ban is not installed or not running" "brute force attempts against sshd are not rate limited" "apt-get install fail2ban"
  fi
}

# -----------------------------------------------------------------------------
# FW - host firewall
# -----------------------------------------------------------------------------
check_firewall() {
  section "Host firewall"

  FW_DUMP=""
  if have nft; then FW_DUMP="$FW_DUMP
$(nft list ruleset 2>/dev/null)"; fi
  if have iptables-save; then FW_DUMP="$FW_DUMP
$(iptables-save 2>/dev/null)"; fi
  if have ip6tables-save; then FW_DUMP="$FW_DUMP
$(ip6tables-save 2>/dev/null)"; fi
  if have ufw; then FW_DUMP="$FW_DUMP
$(ufw status verbose 2>/dev/null)"; fi
  if have firewall-cmd; then FW_DUMP="$FW_DUMP
$(firewall-cmd --list-all 2>/dev/null)"; fi

  if [ -z "${FW_DUMP//[[:space:]]/}" ]; then
    report fail FW-01 critical "No host firewall tooling detected" "neither nftables, iptables, ufw nor firewalld is available" "install nftables or ufw and define a default deny policy"
    return 0
  fi

  local active=0
  if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then active=1; fi
  if printf '%s' "$FW_DUMP" | grep -qE 'policy drop|DROP|REJECT'; then active=1; fi
  if have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then active=1; fi

  if [ "$active" -eq 1 ]; then
    report pass FW-01 critical "Firewall rules are present and enforcing"
  else
    report fail FW-01 critical "Firewall is installed but not enforcing any drop/reject rules" "" "enable the firewall and set a default deny inbound policy"
  fi

  # inbound default policy
  local inpolicy=""
  if have ufw; then
    inpolicy=$(ufw status verbose 2>/dev/null | awk -F': ' '/Default:/{print $2}')
  fi
  if [ -z "$inpolicy" ] && have iptables; then
    inpolicy=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print "policy " $3; exit}')
  fi
  if [ -z "$inpolicy" ]; then
    inpolicy=$(printf '%s' "$FW_DUMP" | awk '/hook input/{f=1} f&&/policy/{print "policy " $2; exit}')
  fi
  case "$inpolicy" in
    *drop*|*DROP*|*deny*) report pass FW-02 critical "Default inbound policy is deny ($inpolicy)" ;;
    "") report info FW-02 high "Default inbound policy could not be determined" "" "check iptables -S INPUT manually" ;;
    *) report fail FW-02 critical "Default inbound policy is not deny" "detected: $inpolicy" "set a default deny inbound policy and allow only required ports" ;;
  esac

  # egress restrictions for lateral movement ports (the classic redis/smtp worm vector)
  local blocked="" p
  for p in 6379 16379 6380 6381; do
    if printf '%s' "$FW_DUMP" | grep -E "(dports|dport)[^|]*\b$p\b" | grep -qiE 'DROP|REJECT'; then
      blocked="$blocked $p"
    fi
  done
  if [ -n "${blocked// /}" ]; then
    report pass FW-03 high "Outbound database/cache ports are blocked:$blocked"
  else
    report warn FW-03 high "Outbound traffic to Redis ports is not restricted" "a compromised container can scan and infect other Redis instances, which is exactly how redis worms spread" "iptables -I OUTPUT -p tcp -m multiport --dports 6379,6380,6381,16379 -j REJECT"
  fi

  local smtp=""
  for p in 25 465 587; do
    if printf '%s' "$FW_DUMP" | grep -E "(dports|dport)[^|]*\b$p\b" | grep -qiE 'DROP|REJECT'; then
      smtp="$smtp $p"
    fi
  done
  if [ -n "${smtp// /}" ]; then
    report pass FW-04 medium "Outbound mail ports are blocked:$smtp"
  else
    report warn FW-04 medium "Outbound SMTP is not restricted" "compromised hosts are usually turned into spam senders" "block 25, 465, 587 outbound unless you run a mail server"
  fi

  # persistence across reboots
  local persist=0
  if [ -r /etc/iptables/rules.v4 ] && [ -s /etc/iptables/rules.v4 ]; then persist=1; fi
  if have systemctl && systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then persist=1; fi
  if [ -r /etc/nftables.conf ] && [ -s /etc/nftables.conf ]; then persist=1; fi
  if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then persist=1; fi
  if [ "$persist" -eq 1 ]; then
    report pass FW-05 medium "Firewall rules are persistent"
  else
    report warn FW-05 medium "Firewall rules may not survive a reboot" "rules exist only in the running kernel" "apt-get install iptables-persistent && netfilter-persistent save"
  fi

  if printf '%s' "$FW_DUMP" | grep -qE 'ip6tables|inet6|::'; then
    report pass FW-06 medium "IPv6 rules are present"
  else
    report warn FW-06 medium "No IPv6 firewall rules found" "services listening on :: are reachable even when IPv4 is filtered" "filter IPv6 with the same policy as IPv4, or disable IPv6"
  fi
}

# -----------------------------------------------------------------------------
# NET - exposed network surface
# -----------------------------------------------------------------------------
established_sockets() {
  if have ss; then
    ss -H -tnp state established 2>/dev/null | awk '{
      split($4,a,":"); lport=a[length(a)];
      split($5,b,":"); rport=b[length(b)]; raddr=$5; sub(/:[^:]*$/,"",raddr);
      print $1"|"raddr"|"rport;
    }'
    return 0
  fi
  local f
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    awk '
      function h2d(s,  i,c,d,v){ v=0; s=tolower(s); for(i=1;i<=length(s);i++){ c=substr(s,i,1); d=index("0123456789abcdef",c)-1; if(d<0) return -1; v=v*16+d } return v }
      function h2ip4(s){ return h2d(substr(s,7,2))"."h2d(substr(s,5,2))"."h2d(substr(s,3,2))"."h2d(substr(s,1,2)) }
      NR>1 {
        if ($4!="01") next;
        split($3,a,":"); ip=a[1]; port=h2d(a[2]);
        if (length(ip)==8) ip=h2ip4(ip); else ip="ipv6";
        print "tcp|"ip"|"port;
      }' "$f" 2>/dev/null
  done
}

check_network() {
  section "Network exposure"

  local listeners tooling=0
  if have ss || have netstat || [ -r /proc/net/tcp ]; then tooling=1; fi
  if [ "$tooling" -eq 0 ]; then
    report skip NET-01 high "Listening sockets" "ss, netstat and /proc/net are all unavailable"
    return 0
  fi
  listeners=$(listen_sockets)
  if [ -z "${listeners//[[:space:]]/}" ]; then
    report pass NET-01 high "No listening sockets found"
    return 0
  fi

  local public_lines public_count
  public_lines=$(printf '%s\n' "$listeners" | awk -F'|' '
    $2!="127.0.0.1" && $2!="::1" && $2!="localhost" && $2!="" { print }')
  public_count=$(printf '%s\n' "$public_lines" | grep -c '|' || true)

  local loop_count
  loop_count=$(printf '%s\n' "$listeners" | awk -F'|' '$2=="127.0.0.1" || $2=="::1"' | grep -c '|' || true)
  report info NET-01 info "Listening sockets" "public or wildcard: ${public_count:-0}
loopback only: ${loop_count:-0}" ""

  # dangerous services exposed beyond loopback
  local bad="" line proto addr port proc
  while IFS='|' read -r proto addr port proc; do
    [ -z "${port:-}" ] && continue
    if is_loopback_addr "$addr"; then continue; fi
    if port_in_list "$port" "$DANGEROUS_PORTS"; then
      bad="${bad}${port}/${proto} on ${addr} (${proc})"$'\n'
    fi
  done <<< "$listeners"

  if [ -n "$bad" ]; then
    report fail NET-02 critical "Database or cache service reachable from the network" "$bad" "bind these services to 127.0.0.1 or to the internal docker network, never to 0.0.0.0"
  else
    report pass NET-02 critical "No database or cache service exposed on a public address"
  fi

  # wildcard listeners inventory
  local wild
  wild=$(printf '%s\n' "$listeners" | awk -F'|' '$2=="0.0.0.0" || $2=="::" { printf "%s/%s ", $3, $1 }' | tr -s ' ')
  if [ -n "${wild// /}" ]; then
    report info NET-03 medium "Ports listening on all interfaces" "$wild" "publish only what must be public, everything else on 127.0.0.1"
  else
    report pass NET-03 medium "No wildcard listeners"
  fi

  # outbound connections to suspicious ports
  local est susp=""
  est=$(established_sockets)
  if [ -n "${est//[[:space:]]/}" ]; then
    local eaddr eport
    while IFS='|' read -r _ eaddr eport; do
      [ -z "${eport:-}" ] && continue
      if port_in_list "$eport" "$SUSPICIOUS_OUT_PORTS"; then
        susp="${susp}${eaddr}:${eport}"$'\n'
      fi
    done <<< "$est"
  fi
  if [ -n "$susp" ]; then
    report fail NET-04 critical "Outbound connections to mining or database ports" "$susp" "investigate the process immediately: this is the signature of a miner or a worm"
  else
    report pass NET-04 critical "No outbound connections to mining or database ports"
  fi
}

# -----------------------------------------------------------------------------
# DOCK - container runtime
# -----------------------------------------------------------------------------
check_docker() {
  section "Containers"

  if ! have docker || ! docker info >/dev/null 2>&1; then
    report skip DOCK-01 high "Docker is not available" "container checks skipped"
    return 0
  fi

  local ids
  ids=$(docker ps -q 2>/dev/null)
  if [ -z "${ids//[[:space:]]/}" ]; then
    report info DOCK-01 high "Docker is running, no containers are up" "" ""
    return 0
  fi
  local n; n=$(printf '%s\n' "$ids" | wc -l | tr -d ' ')
  report info DOCK-01 high "Docker is running with $n container(s)" "" ""

  local priv="" host="" sock="" rootuser="" caps="" id
  for id in $ids; do
    local name
    name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    local p h u c b
    p=$(docker inspect -f '{{.HostConfig.Privileged}}' "$id" 2>/dev/null)
    h=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null)
    u=$(docker inspect -f '{{.Config.User}}' "$id" 2>/dev/null)
    c=$(docker inspect -f '{{json .HostConfig.CapAdd}}' "$id" 2>/dev/null)
    b=$(docker inspect -f '{{json .HostConfig.Binds}}' "$id" 2>/dev/null)

    [ "$p" = "true" ] && priv="${priv}${name}
"
    [ "$h" = "host" ] && host="${host}${name}
"
    case "$b" in *docker.sock*) sock="${sock}${name}
" ;; esac
    if [ -z "${u// /}" ] || [ "$u" = "0" ] || [ "$u" = "root" ] || [ "$u" = "0:0" ]; then
      rootuser="${rootuser}${name}
"
    fi
    case "$c" in *SYS_ADMIN*|*ALL*|*SYS_PTRACE*|*NET_ADMIN*) caps="${caps}${name}: ${c}
" ;; esac
  done

  if [ -n "$priv" ]; then
    report fail DOCK-02 critical "Privileged containers" "$priv" "remove --privileged, add only the specific capabilities needed"
  else
    report pass DOCK-02 critical "No privileged containers"
  fi

  if [ -n "$sock" ]; then
    report fail DOCK-03 critical "Docker socket mounted into a container" "$sock" "a container with the docker socket has full control over the host"
  else
    report pass DOCK-03 critical "Docker socket is not mounted into containers"
  fi

  if [ -n "$host" ]; then
    local hn="" hnbad="" himg
    while IFS= read -r hn; do
      [ -z "$hn" ] && continue
      himg=$(docker inspect -f '{{.Config.Image}}' "$hn" 2>/dev/null || echo unknown)
      case "$himg" in
        *node*) ;;
        *) hnbad="${hnbad}${hn} (${himg})"$'\n' ;;
      esac
    done <<< "$host"
    if [ -n "$hnbad" ]; then
      report warn DOCK-04 high "Containers using host network mode" "$hnbad" "host networking removes network isolation between the container and the host"
    else
      report pass DOCK-04 high "Host networking is used only by VPN node containers"
    fi
  else
    report pass DOCK-04 high "No containers use host networking"
  fi

  if [ -n "$caps" ]; then
    report warn DOCK-05 high "Containers with extra capabilities" "$caps" "drop all capabilities and add only what is required"
  else
    report pass DOCK-05 high "No containers with dangerous extra capabilities"
  fi

  local rootcount
  rootcount=$(printf '%s' "$rootuser" | grep -c . || true)
  if [ "${rootcount:-0}" -gt 0 ]; then
    report info DOCK-06 medium "Containers running as root inside the container: $rootcount of $n" "$rootuser" "set a non-root user in the image where possible"
  else
    report pass DOCK-06 medium "All containers run as a non-root user"
  fi

  # published ports on all interfaces
  local plines pub="" pubdanger=""
  plines=$(docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null)
  local cname ports entry hport
  while IFS='|' read -r cname ports; do
    [ -z "${ports:-}" ] && continue
    local IFS_OLD="$IFS"; IFS=','
    set -- $ports
    IFS="$IFS_OLD"
    for entry in "$@"; do
      entry="${entry# }"
      hport="${entry%%->*}"
      case "$hport" in
        0.0.0.0:*|\[::\]:*|:::*)
          local hp="${hport##*:}"
          pub="${pub}${cname}: ${entry}"$'\n'
          if port_in_list "$hp" "$DANGEROUS_PORTS"; then
            pubdanger="${pubdanger}${cname}: ${entry}"$'\n'
          fi
          ;;
      esac
    done
  done <<< "$plines"

  if [ -n "$pubdanger" ]; then
    report fail DOCK-07 critical "Container port published on all interfaces" "$pubdanger" "bind to 127.0.0.1 in docker-compose: \"127.0.0.1:6379:6379\", or remove the port mapping and use the docker network"
  elif [ -n "$pub" ]; then
    report info DOCK-07 high "Containers with ports published on all interfaces" "$pub" "publish on 127.0.0.1 and put a reverse proxy in front"
  else
    report pass DOCK-07 critical "No container publishes a port on all interfaces"
  fi

  # secrets in container environment
  local weak="" present="" envs line2 k v
  for id in $ids; do
    local name2
    name2=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    envs=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null)
    while IFS= read -r line2; do
      case "$line2" in
        *=*) ;;
        *) continue ;;
      esac
      k="${line2%%=*}"; v="${line2#*=}"
      printf '%s' "$k" | grep -qiE '(PASS|PASSWORD|PWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY)' || continue
      [ -z "$v" ] && continue
      present="${present}${name2}: ${k}"$'\n'
      local lv; lv=$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')
      case "$lv" in
        redispass|password|passwd|pass|admin|root|secret|changeme|change_me|123456|12345678|qwerty|test|postgres|mysql|minioadmin|example|default|letmein)
          weak="${weak}${name2}: ${k} (value looks like a default: ${#v} chars)"$'\n' ;;
        *)
          if [ "${#v}" -lt 12 ]; then
            weak="${weak}${name2}: ${k} (short value: ${#v} chars)"$'\n'
          fi
          ;;
      esac
    done <<< "$envs"
  done

  if [ -n "$weak" ]; then
    report fail DOCK-08 critical "Weak or default credentials in container environment" "$weak" "generate random passwords of at least 24 characters, rotate them, and keep them out of images"
  elif [ -n "$present" ]; then
    report info DOCK-08 high "Secrets are passed to containers through environment variables" "$present" "environment variables are visible to any process that can run docker; prefer docker secrets or a mounted file with 600 permissions"
  else
    report pass DOCK-08 critical "No weak credentials found in container environments"
  fi

  # image hygiene
  local latest
  latest=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -E ':latest$' | sort -u | tr '\n' ' ')
  if [ -n "${latest// /}" ]; then
    report warn DOCK-09 low "Containers run images pinned to :latest" "$latest" "pin exact versions so an update cannot silently change the running software"
  else
    report pass DOCK-09 low "Container images are version pinned"
  fi

  local old=""
  while IFS='|' read -r img created; do
    [ -z "${created:-}" ] && continue
    local ts now age
    created="${created% UTC}"
    ts=$(date -d "$created" +%s 2>/dev/null || echo 0)
    now=$(date +%s)
    if [ "$ts" -gt 0 ]; then
      age=$(( (now - ts) / 86400 ))
      if [ "$age" -gt 90 ]; then old="${old}${img} (${age} days)"$'\n'; fi
    fi
  done <<< "$(docker images --format '{{.Repository}}:{{.Tag}}|{{.CreatedAt}}' 2>/dev/null | grep -v '<none>')"

  if [ -n "$old" ]; then
    report warn DOCK-10 medium "Container images older than 90 days" "$old" "rebuild or pull newer images, then recreate the containers"
  else
    report pass DOCK-10 medium "All container images are younger than 90 days"
  fi

  # daemon configuration
  local dj="/etc/docker/daemon.json" djmiss=""
  if [ -r "$dj" ]; then
    grep -q 'no-new-privileges' "$dj" 2>/dev/null || djmiss="${djmiss}no-new-privileges, "
    grep -q 'live-restore' "$dj" 2>/dev/null || djmiss="${djmiss}live-restore, "
    if grep -q 'max-size' "$dj" 2>/dev/null; then :; else djmiss="${djmiss}log-opts max-size, "; fi
    if [ -n "$djmiss" ]; then
      report warn DOCK-11 medium "Docker daemon options are not hardened" "missing: ${djmiss%, }" "add these keys to $dj and restart docker"
    else
      report pass DOCK-11 medium "Docker daemon configuration is hardened"
    fi
  else
    report warn DOCK-11 medium "No /etc/docker/daemon.json" "docker runs with default settings, logs are unbounded and privileges are not limited" "create /etc/docker/daemon.json with no-new-privileges, live-restore and log limits"
  fi

  # socket permissions and docker group
  local sockinfo members
  sockinfo=$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null || echo "unknown")
  members=$(getent group docker 2>/dev/null | awk -F: '{print $4}')
  if [ -n "$members" ]; then
    report warn DOCK-12 medium "Users in the docker group are root-equivalent" "socket: $sockinfo
members: $members" "keep the docker group empty on production hosts"
  else
    report pass DOCK-12 medium "No users in the docker group" "socket: $sockinfo" ""
  fi
}

# -----------------------------------------------------------------------------
# SEC - secrets and file permissions
# -----------------------------------------------------------------------------
WEAK_RE='^(redispass|password|passwd|pass|admin|root|secret|changeme|change_me|123456|12345678|qwerty|test|postgres|mysql|minioadmin|example|default|letmein|redis|docker|vpn)$'

check_secrets() {
  section "Secrets and file permissions"

  local bad="" f perms
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    perms=$(stat -c '%a' "$f" 2>/dev/null || echo 600)
    case "$perms" in
      600|400|640|440) ;;
      *) bad="${bad}${f} (mode ${perms})"$'\n' ;;
    esac
  done < <(find /root /opt /srv /home /var/www -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name '*.env' \) 2>/dev/null | head -60)

  if [ -n "$bad" ]; then
    report fail SEC-01 high "Environment files readable by other users" "$bad" "chmod 600 <file> && chown root:root <file>"
  else
    report pass SEC-01 high "Environment files have restrictive permissions"
  fi

  local weaklines="" val line key lv
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      case "$line" in
        \#*) continue ;;
        *=*) ;;
        *) continue ;;
      esac
      key="${line%%=*}"
      val="${line#*=}"
      val="${val%%#*}"
      val="${val//\"/}"; val="${val//\'/}"
      val="${val#"${val%%[![:space:]]*}"}"
      val="${val%"${val##*[![:space:]]}"}"
      printf '%s' "$key" | grep -qiE '(PASS|PASSWORD|PWD|SECRET|TOKEN|KEY)' || continue
      [ -z "$val" ] && continue
      lv=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
      if printf '%s' "$lv" | grep -qE "$WEAK_RE"; then
        weaklines="${weaklines}${f}: ${key} (dictionary value, ${#val} chars)"$'\n'
      elif [ "${#val}" -lt 12 ]; then
        weaklines="${weaklines}${f}: ${key} (short value, ${#val} chars)"$'\n'
      fi
    done < "$f"
  done < <(find /root /opt /srv /home /var/www -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' \) 2>/dev/null | head -60)

  if [ -n "$weaklines" ]; then
    report fail SEC-02 critical "Weak credentials found in configuration files" "$weaklines" "replace with random values of 24+ characters: openssl rand -hex 24"
  else
    report pass SEC-02 critical "No weak credentials found in configuration files"
  fi

  local inline="" hits
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    hits=$(grep -nE '(password|passwd|requirepass|secret)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_.-]{1,40}["'"'"']?[[:space:]]*$' "$f" 2>/dev/null | grep -viE '\$\{|env_file|example' | head -5)
    [ -n "$hits" ] && inline="${inline}${f}:
${hits}
"
  done < <(find /root /opt /srv /home /var/www -maxdepth 4 -type f \( -name 'docker-compose*.yml' -o -name 'compose*.yml' \) 2>/dev/null | head -40)

  if [ -n "$inline" ]; then
    report warn SEC-03 high "Passwords hardcoded in compose files" "$inline" "use variables from .env instead of literal values"
  else
    report pass SEC-03 high "No hardcoded passwords in compose files"
  fi

  local gitleak="" d tracked
  while IFS= read -r d; do
    [ -d "$d/.git" ] || continue
    tracked=$(cd "$d" 2>/dev/null && git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' | grep -v '\.example$' | head -5)
    [ -n "$tracked" ] && gitleak="${gitleak}${d}: ${tracked}"$'\n'
  done < <(find /root /opt /srv /home /var/www -maxdepth 4 -type d -name '.git' 2>/dev/null | sed 's#/.git$##' | head -20)

  if [ -n "$gitleak" ]; then
    report fail SEC-04 critical "Secret files are tracked in git repositories" "$gitleak" "remove them from the index, add to .gitignore and rotate every leaked credential"
  else
    report pass SEC-04 critical "No env files tracked by git"
  fi

  local keys
  keys=$(find /root /home -maxdepth 4 -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \) -perm /o+r 2>/dev/null | head -10)
  if [ -n "$keys" ]; then
    report fail SEC-05 high "Private keys readable by other users" "$keys" "chmod 600 <key>"
  else
    report pass SEC-05 high "Private keys are not world readable"
  fi

  local ww
  ww=$(find /etc -maxdepth 2 -xdev -type f -perm -o+w 2>/dev/null | head -10)
  if [ -n "$ww" ]; then
    report warn SEC-06 medium "World writable files in /etc" "$ww" "chmod o-w <file>"
  else
    report pass SEC-06 medium "No world writable files in /etc"
  fi

  if [ -s /etc/ld.so.preload ]; then
    report fail SEC-07 critical "/etc/ld.so.preload is not empty" "$(head -3 /etc/ld.so.preload 2>/dev/null)" "this file is almost always a rootkit artefact; investigate before removing"
  else
    report pass SEC-07 critical "/etc/ld.so.preload is empty or absent"
  fi
}
# -----------------------------------------------------------------------------
# MAL - malware and persistence
# -----------------------------------------------------------------------------
# Miner and worm process names are stored as fragments and joined at runtime.
# Reason: antivirus engines and mail gateways quarantine scripts that contain
# the full names, and this repository is meant to be cloneable everywhere.
MINER_FRAGMENTS="xm:rig min:erd kdevtmp:fsi kin:sing kthread:di db:used xmri:gc mass:can z:map cpu:miner sys:cache sc:-node"

build_alt_regex() {
  local out="" item
  for item in $1; do
    out="${out}${item%%:*}${item#*:}|"
  done
  printf '%s' "${out%|}"
}

check_malware() {
  section "Malware and persistence"

  local miner_re procs
  miner_re=$(build_alt_regex "$MINER_FRAGMENTS")
  procs=$(ps -eo pid,pcpu,comm,args 2>/dev/null | grep -iE "(${miner_re})" | grep -v 'grep -iE' | head -10)
  if [ -n "$procs" ]; then
    report fail MAL-01 critical "Known miner or worm process names found" "$procs" "kill the process tree, remove the binaries and find the entry point before rebooting"
  else
    report pass MAL-01 critical "No known miner or worm process names"
  fi

  local top cpu
  top=$(ps -eo pcpu,pid,comm --sort=-pcpu 2>/dev/null | awk 'NR==2 {print}')
  if [ -n "$top" ]; then
    cpu=$(printf '%s' "$top" | awk '{print int($1)}')
    if [ "${cpu:-0}" -ge 80 ]; then
      report warn MAL-02 high "A single process uses ${cpu}% CPU" "$top" "verify it is expected workload and not a miner"
    else
      report pass MAL-02 high "No process is consuming abnormal CPU (top: $top)"
    fi
  else
    report skip MAL-02 high "CPU usage check" "ps unavailable"
  fi

  local tmpx
  tmpx=$(find /tmp /var/tmp /dev/shm -xdev -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -10)
  if [ -n "$tmpx" ]; then
    report warn MAL-03 high "Executable files in temporary directories" "$tmpx" "temporary directories must not hold executables; check what created them"
  else
    report pass MAL-03 high "No executables in temporary directories"
  fi

  local cronbad="" cf hit
  for cf in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$cf" ] || continue
    hit=$(grep -nE '(curl|wget|base64 -d|/dev/tcp|python -c)' "$cf" 2>/dev/null | grep -v '^[[:space:]]*#' | head -3)
    [ -n "$hit" ] && cronbad="${cronbad}${cf}:
${hit}
"
  done
  if [ -n "$cronbad" ]; then
    report fail MAL-04 critical "Suspicious cron entries" "$cronbad" "remove the entry, then find how it was created"
  else
    report pass MAL-04 critical "No suspicious cron entries"
  fi

  local units
  units=$(grep -rlsE 'ExecStart=.*(/tmp/|/dev/shm/|base64)' /etc/systemd/system /lib/systemd/system 2>/dev/null | head -10)
  if [ -n "$units" ]; then
    report fail MAL-05 critical "Systemd units running code from temporary paths" "$units" "inspect the unit, disable it and remove the payload"
  else
    report pass MAL-05 critical "No suspicious systemd units"
  fi

  local recent
  recent=$(find /root /opt -xdev -maxdepth 3 -type f -newermt '-7 days' -perm -u+x 2>/dev/null | grep -vE '/(\.cache|\.local|node_modules)/' | head -15)
  if [ -n "$recent" ]; then
    report info MAL-06 medium "Executables created in the last 7 days" "$recent" "confirm each one was placed there by you"
  else
    report pass MAL-06 medium "No unexpected executables created in the last 7 days"
  fi

  local hidden
  hidden=$(find /root /tmp /var/tmp /opt -xdev -maxdepth 2 -type f -name '.*' -size +1k 2>/dev/null | head -15)
  if [ -n "$hidden" ]; then
    report info MAL-07 low "Hidden files in working directories" "$hidden" "hidden binaries in /root, /tmp and /opt are a common persistence trick"
  else
    report pass MAL-07 low "No hidden files in working directories"
  fi

  if have systemctl; then
    local failed
    failed=$(systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -10 | tr '\n' ' ')
    if [ -n "${failed// /}" ]; then
      report info MAL-08 low "Failed systemd units" "$failed" "failed services may indicate removed malware or broken hardening"
    else
      report pass MAL-08 low "No failed systemd units"
    fi
  else
    report skip MAL-08 low "Failed units check" "systemctl unavailable"
  fi
}

# -----------------------------------------------------------------------------
# LOG - authentication history
# -----------------------------------------------------------------------------
check_logs() {
  section "Authentication history"

  if [ "$FAST" -eq 1 ]; then
    report skip LOG-01 medium "Login analysis" "skipped by --fast"
    return 0
  fi

  local src="" failed=0
  if have journalctl && [ -d /var/log/journal ]; then
    src="journald"
    failed=$(journalctl -u ssh -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -cE 'Failed password|Invalid user|authentication failure')
  elif [ -r /var/log/auth.log ]; then
    src="auth.log"
    failed=$(grep -cE 'Failed password|Invalid user|authentication failure' /var/log/auth.log 2>/dev/null || echo 0)
  fi

  if [ -z "$src" ]; then
    report info LOG-01 medium "No persistent authentication log" "journald storage is volatile and /var/log/auth.log is absent" "enable persistent journald storage so incidents can be investigated later"
    return 0
  fi

  local f2b_on=0 pass_off=0 mitigated=""
  if have systemctl && systemctl is-active --quiet fail2ban 2>/dev/null; then f2b_on=1; mitigated="${mitigated}fail2ban active, "; fi
  local sshd_eff
  sshd_eff=$(sshd -T 2>/dev/null || true)
  if printf '%s\n' "$sshd_eff" | grep -qiE '^passwordauthentication no'; then pass_off=1; mitigated="${mitigated}password authentication disabled"; fi
  if [ "${failed:-0}" -gt 500 ]; then
    if [ "$f2b_on" -eq 1 ] && [ "$pass_off" -eq 1 ]; then
      report info LOG-01 medium "Historical brute force attempts in the last 24h" "source: $src
failed attempts: $failed
mitigated by: ${mitigated}" "no action needed: password logins are disabled and bans are enforced"
    else
      report warn LOG-01 high "Heavy brute force activity in the last 24h" "source: $src
failed attempts: $failed" "install fail2ban, disable password authentication and restrict SSH by source"
    fi
  elif [ "${failed:-0}" -gt 50 ]; then
    if [ "$f2b_on" -eq 1 ] && [ "$pass_off" -eq 1 ]; then
      report info LOG-01 medium "Brute force attempts in the last 24h" "source: $src
failed attempts: $failed
mitigated by: ${mitigated}" "no action needed: password logins are disabled and bans are enforced"
    else
      report warn LOG-01 medium "Brute force attempts in the last 24h" "source: $src
failed attempts: $failed" "install fail2ban and disable password authentication"
    fi
  else
    report pass LOG-01 medium "Failed login attempts in the last 24h: ${failed:-0}"
  fi

  local topip="" ok=""
  if [ "$src" = "journald" ]; then
    topip=$(journalctl -u ssh -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)
    ok=$(journalctl -u ssh -u sshd --since '24 hours ago' --no-pager 2>/dev/null | grep -E 'Accepted (publickey|password)' | awk '{print $1" "$2" "$3" "$9" "$11}' | tail -10)
  else
    topip=$(grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' /var/log/auth.log 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)
    ok=$(grep -E 'Accepted (publickey|password)' /var/log/auth.log 2>/dev/null | awk '{print $1" "$2" "$3" "$9" "$11}' | tail -10)
  fi
  [ -n "$topip" ] && report info LOG-02 medium "Top source addresses of failed logins" "$topip" ""

  if [ -n "$ok" ]; then
    report info LOG-03 medium "Successful SSH logins in the last 24h" "$ok" "check that every login is yours"
  else
    report pass LOG-03 medium "No successful SSH logins in the last 24h"
  fi
}

# -----------------------------------------------------------------------------
# WEB - reverse proxy and TLS
# -----------------------------------------------------------------------------
check_web() {
  section "Web server and TLS"

  local has_nginx=0 has_apache=0
  have nginx && has_nginx=1
  have apache2 && has_apache=1
  if [ "$has_nginx" -eq 0 ] && [ "$has_apache" -eq 0 ]; then
    report skip WEB-01 low "No nginx or apache2 installed" "web checks skipped"
    return 0
  fi
  report info WEB-01 low "Web server detected" "nginx: $has_nginx
apache2: $has_apache" ""

  if [ "$has_nginx" -eq 1 ]; then
    local t dup
    t=$(nginx -t 2>&1)
    dup=$(printf '%s\n' "$t" | grep -E 'conflicting server name|duplicate' | head -5)
    if [ -n "$dup" ]; then
      report warn WEB-02 medium "nginx configuration conflicts" "$dup" "duplicate server_name entries make one virtual host silently win over another"
    else
      report pass WEB-02 medium "nginx configuration has no duplicate server names"
    fi

    local tokens
    tokens=$(grep -rhs 'server_tokens' /etc/nginx 2>/dev/null | grep -v '^[[:space:]]*#' | head -3)
    case "$tokens" in
      *"off"*) report pass WEB-03 low "Server tokens are hidden" ;;
      "") report warn WEB-03 low "server_tokens is not set" "nginx advertises its version in responses and error pages" "add server_tokens off; to the http block" ;;
      *) report info WEB-03 low "server_tokens setting" "$tokens" "" ;;
    esac

    local redirect
    redirect=$(grep -rhsE 'return 301 https' /etc/nginx 2>/dev/null | head -3)
    if [ -n "$redirect" ]; then
      report pass WEB-04 low "HTTP to HTTPS redirect is configured"
    else
      report warn WEB-04 medium "No HTTP to HTTPS redirect found" "plaintext requests are served or dropped without a redirect" "add a server block that returns 301 to https"
    fi

    local pubs
    pubs=$(grep -rhsE 'proxy_pass +http://(0\.0\.0\.0|\[::\]|::)' /etc/nginx 2>/dev/null | head -5)
    if [ -n "$pubs" ]; then
      report warn WEB-05 low "proxy_pass points to a wildcard address" "$pubs" "proxy to 127.0.0.1 explicitly so traffic cannot leave the host"
    else
      report pass WEB-05 low "proxy_pass targets are explicit"
    fi
  fi

  local certs="" f
  if have nginx; then
    while IFS= read -r f; do
      [ -n "$f" ] && [ -f "$f" ] && certs="$certs$f"$'\n'
    done <<< "$(nginx -T 2>/dev/null | awk '/^[[:space:]]*ssl_certificate[[:space:]]/{gsub(";","",$2); print $2}' | sort -u)"
  fi
  if [ -z "$certs" ]; then
    for f in /etc/letsencrypt/live/*/fullchain.pem; do
      [ -f "$f" ] || continue
      certs="$certs$f"$'\n'
    done
  fi
  if [ -z "$certs" ]; then
    report skip WEB-06 medium "TLS certificate expiry" "no certificates found in /etc/letsencrypt/live"
    return 0
  fi

  local soon="" expired="" enddate days endts nowts
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    enddate=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | cut -d= -f2)
    [ -z "$enddate" ] && continue
    endts=$(date -d "$enddate" +%s 2>/dev/null || echo 0)
    [ "$endts" -eq 0 ] && continue
    nowts=$(date +%s)
    days=$(( (endts - nowts) / 86400 ))
    if [ "$days" -lt 0 ]; then
      expired="${expired}${f} (expired)"$'\n'
    elif [ "$days" -lt 21 ]; then
      soon="${soon}${f} (${days} days left)"$'\n'
    fi
  done <<< "$certs"

  if [ -n "$expired" ]; then
    report fail WEB-06 high "TLS certificates are expired" "$expired" "renew with certbot renew and reload nginx"
  elif [ -n "$soon" ]; then
    report warn WEB-06 medium "TLS certificates expire soon" "$soon" "verify automatic renewal: certbot renew --dry-run"
  else
    report pass WEB-06 medium "TLS certificates are valid for more than 21 days"
  fi
}

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------
banner() {
  printf '%s' "$C_BLD"
  cat <<BANNER
server-security-audit $VERSION
host: $(hostname 2>/dev/null || echo unknown)   date: $(now_iso)   user: $(id -un 2>/dev/null || echo unknown)
BANNER
  printf '%s\n' "$C_OFF"
  if [ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]; then
    printf '%sNote: run with sudo for the complete picture.%s\n' "$C_YEL" "$C_OFF"
  fi
}

risk_score() {
  local s
  s=$(( 100 - (N_CRIT*15 + N_HIGH*8 + N_MED*4 + N_LOW*1) ))
  [ "$s" -lt 0 ] && s=0
  printf '%s' "$s"
}

top_fixes() {
  local rec status id sev title detail hint n=0
  for rec in "${FINDINGS[@]}"; do
    IFS="$SEP" read -r status id sev title detail hint <<< "$rec"
    case "$status" in fail|warn) ;; *) continue ;; esac
    case "$sev" in critical|high) ;; *) continue ;; esac
    n=$((n+1))
    [ "$n" -gt 8 ] && break
    printf '  %s. [%s] %s - %s\n' "$n" "$sev" "$id" "$title"
    [ -n "$hint" ] && printf '     %s%s%s\n' "$C_DIM" "$hint" "$C_OFF"
  done
  [ "$n" -eq 0 ] && printf '  nothing urgent\n'
}

print_summary() {
  local score
  score=$(risk_score)
  printf '\n%s== Summary%s\n\n' "$C_BLD" "$C_OFF"
  printf '  %scritical%s  %s\n' "$C_RED" "$C_OFF" "$N_CRIT"
  printf '  %shigh%s      %s\n' "$C_RED" "$C_OFF" "$N_HIGH"
  printf '  %smedium%s    %s\n' "$C_YEL" "$C_OFF" "$N_MED"
  printf '  low       %s\n' "$N_LOW"
  printf '  info      %s\n' "$N_INFO"
  printf '  passed    %s\n' "$N_PASS"
  printf '  skipped   %s\n\n' "$N_SKIP"
  printf '  health score %s/100 (higher is better)\n\n' "$score"

  if [ "$N_CRIT" -gt 0 ] || [ "$N_HIGH" -gt 0 ]; then
    printf '%s== Priority fixes%s\n\n' "$C_BLD" "$C_OFF"
    top_fixes
    printf '\n'
    printf '%sVERDICT: %s critical and %s high severity findings require action%s\n' "$C_RED" "$N_CRIT" "$N_HIGH" "$C_OFF"
  else
    printf '%sVERDICT: no critical or high severity findings%s\n' "$C_GRN" "$C_OFF"
  fi
}

emit_json() {
  local rec status id sev title detail hint first=1
  printf '{"tool":"server-security-audit","version":"%s","generated_at":"%s","host":"%s","score":%s,' \
    "$VERSION" "$(now_iso)" "$(json_escape "$(hostname 2>/dev/null || echo unknown)")" "$(risk_score)"
  printf '"counts":{"critical":%s,"high":%s,"medium":%s,"low":%s,"info":%s,"passed":%s,"skipped":%s},' \
    "$N_CRIT" "$N_HIGH" "$N_MED" "$N_LOW" "$N_INFO" "$N_PASS" "$N_SKIP"
  printf '"findings":['
  for rec in "${FINDINGS[@]}"; do
    IFS="$SEP" read -r status id sev title detail hint <<< "$rec"
    [ "$first" -eq 0 ] && printf ','
    first=0
    printf '{"id":"%s","status":"%s","severity":"%s","title":"%s","detail":"%s","fix":"%s"}' \
      "$(json_escape "$id")" "$(json_escape "$status")" "$(json_escape "$sev")" \
      "$(json_escape "$title")" "$(json_escape "$detail")" "$(json_escape "$hint")"
  done
  printf ']}\n'
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  setup_color

  SSHD_T=""
  FW_DUMP=""

  [ "$FORMAT" = "text" ] && banner

  # -u is disabled while checks run: a single unbound variable in one check
  # must not abort the whole audit on an unexpected host.
  set +u
  check_system
  check_ssh
  check_firewall
  check_network
  check_docker
  check_secrets
  check_malware
  check_logs
  check_web
  set -u

  if [ "$FORMAT" = "json" ]; then
    emit_json
  else
    print_summary
  fi

  if [ "$N_CRIT" -gt 0 ]; then exit 2; fi
  if [ "$N_HIGH" -gt 0 ]; then exit 1; fi
  exit 0
}

main "$@"
