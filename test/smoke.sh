#!/usr/bin/env bash
# Minimal self-test: no root required, no network, no fixtures on the host.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fails=0
ok()   { printf 'ok   - %s\n' "$1"; }
bad()  { printf 'FAIL - %s\n' "$1"; fails=$((fails+1)); }

bash -n server-security-audit.sh && ok "syntax" || bad "syntax"

bash server-security-audit.sh --help >/dev/null 2>&1 && ok "--help exits 0" || bad "--help"
bash server-security-audit.sh --version | grep -qE '^server-security-audit [0-9]' && ok "--version" || bad "--version"

out=$(bash server-security-audit.sh --color never --only SYS-01 2>&1)
printf '%s' "$out" | grep -q 'SYS-01' && ok "filter --only" || bad "filter --only"
printf '%s' "$out" | grep -q 'SSH-02' && bad "--only leaked other checks" || ok "--only isolation"

out=$(bash server-security-audit.sh --color never --skip SYS 2>&1)
printf '%s' "$out" | grep -q 'SYS-01' && bad "--skip ignored" || ok "filter --skip"

bash server-security-audit.sh --color never --no-pass >/dev/null 2>&1
code=$?
[ "$code" -le 2 ] && ok "--no-pass exit code ($code)" || bad "--no-pass exit code ($code)"

bash server-security-audit.sh --format json --color never > /tmp/ssa-test.json 2>/dev/null
if command -v jq >/dev/null 2>&1; then
  jq -e '.tool == "server-security-audit"' /tmp/ssa-test.json >/dev/null 2>&1 && ok "json tool field" || bad "json tool field"
  jq -e '.findings | type == "array"' /tmp/ssa-test.json >/dev/null 2>&1 && ok "json findings array" || bad "json findings array"
  jq -e '.counts and (.score | type == "number")' /tmp/ssa-test.json >/dev/null 2>&1 && ok "json counts and score" || bad "json counts and score"
else
  printf 'skip - jq not installed\n'
fi

bash server-security-audit.sh --format xml >/dev/null 2>&1
[ "$?" -eq 64 ] && ok "bad argument exit code" || bad "bad argument exit code"

bash server-security-audit.sh --color never --min-severity critical --no-pass >/tmp/ssa-crit.txt 2>&1
if grep -qE '\[(WARN|INFO|PASS)\]' /tmp/ssa-crit.txt; then
  bad "--min-severity filtering"
else
  ok "--min-severity filtering"
fi

printf '\n%s failure(s)\n' "$fails"
[ "$fails" -eq 0 ]
