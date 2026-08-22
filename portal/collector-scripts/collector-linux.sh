#!/usr/bin/env bash
#
# ai-guard endpoint collector (Linux)
# -----------------------------------
# Scans a developer workstation for AI tooling across four surfaces:
#   cli      - tools that store an account identity in a config file
#   ide      - AI extensions in VS Code / Cursor
#   desktop  - AI desktop apps, local runtimes and their binaries
#   mcp      - MCP server definitions in AI tool configs
#
# The identifiers for all four come from the receiver's /registry/collector
# at runtime. Nothing tool-specific is hardcoded: adding a new AI tool is a
# registry merge request, not a script edit plus a re-push through the RMM.
#
# Delivery: any mechanism that can run this as root on a schedule - an RMM
# (Level, NinjaOne, Action1...), an Ansible cron/systemd-timer role, or plain
# cron. It is the Linux sibling of the macOS (Jamf) and Windows (Intune)
# collectors: same finding schema, same receiver, same design rules.
#
# Config arrives as environment variables (set them in your RMM's script
# variables, or export them from a wrapper):
#   AIGUARD_RECEIVER_BASE   receiver base URL, e.g. https://ai-guard.example.com
#   AIGUARD_TOKEN           receiver bearer token. Either the shared token, or
#                           an enrollment token (aige_...) from a managed-mode
#                           receiver: on first run the machine enrolls, stores
#                           its own device credential in /var/lib/ai-guard,
#                           and uses that from then on. Swapping the shared
#                           token for an enrollment token in the RMM is the
#                           whole migration.
#   AIGUARD_CORP_DOMAINS    comma-separated corporate domains, e.g. example.com.
#                           A receiver that serves config.corp_domains in
#                           /registry/collector overrides this at runtime; the
#                           variable is the fallback.
# If AIGUARD_RECEIVER_BASE is unset, findings print to stdout instead of
# POSTing, which is the local-test mode.
#
# Local test:
#   AIGUARD_REGISTRY_FILE=registry/dist/collector.json ./ai-guard-collector.sh
#
# Design rules learned on the macOS and Windows collectors and kept here:
#   * Resolve the real user's home. RMM agents run as root, whose HOME is
#     /root and contains nothing - the Linux form of the /var/root and
#     SYSTEM-profile traps that silently produced empty pilots elsewhere.
#   * Fail loudly. A collector that reports nothing looks identical to a
#     clean machine; across a fleet that is false confidence.
#   * The account_domain field carries the domain only. The console username
#     is sent in the user field (already known to IT).

set -u

# ------------------------------------------------------------------ config --
RECEIVER_BASE="${AIGUARD_RECEIVER_BASE:-}"
TOKEN="${AIGUARD_TOKEN:-}"
CORP_DOMAINS="${AIGUARD_CORP_DOMAINS:-}"

ENDPOINT=""
[ -n "$RECEIVER_BASE" ] && ENDPOINT="${RECEIVER_BASE%/}/report"

STATE_DIR="/var/lib/ai-guard"
STATE_FILE="$STATE_DIR/reported.state"
# This machine's own credential, once enrolled with a managed-mode receiver.
# Root-only: it is this device's identity.
CRED_FILE="$STATE_DIR/device.cred"
# Reported at enrollment and on every report, so the receiver's inventory can
# answer "which script version does the fleet actually run".
COLLECTOR_VERSION="2.0.0"
SUMMARY_DIR="$STATE_DIR"
SUMMARY_FILE="$SUMMARY_DIR/last_scan.txt"
INFO_INTERVAL=$((24 * 3600))
# warn findings (personal accounts) are a persistent state, not an event, so
# repeating them at every run adds volume without adding information. The
# first report already said it. New keys bypass the throttle entirely, so an
# account switch still surfaces on the next run.
WARN_INTERVAL=$((3600))

PY=$(command -v python3 || true)

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NOW_EPOCH=$(date -u +%s)

# ------------------------------------------------- resolve the real user --
# RMM agents run as root ($HOME=/root). The AI tool configs live in the
# developer's home under /home. Resolve the human account: an entry in /home
# that is a directory, not owned by root, and not a package cache like
# linuxbrew. On a single-user workstation there is exactly one.
resolve_user() {
  local d owner
  for d in /home/*/; do
    [ -d "$d" ] || continue
    owner=$(stat -c '%U' "$d" 2>/dev/null)
    [ -z "$owner" ] && continue
    [ "$owner" = "root" ] && continue
    case "$(basename "$d")" in linuxbrew|lost+found) continue ;; esac
    CONSOLE_USER="$owner"
    HOME_DIR="${d%/}"
    return 0
  done
  return 1
}

if ! resolve_user; then
  echo "[ai-guard] no human user home found under /home, skipping"
  exit 0
fi

# The home directory with every symlink already resolved, so the containment
# check below compares like with like. Doing it once here rather than per path
# keeps it to one subshell for the whole run.
HOME_REAL=$(cd "$HOME_DIR" 2>/dev/null && pwd -P) || HOME_REAL="$HOME_DIR"

# device carries the most stable identifier available: the DMI product serial
# (root can read it), then machine-id, then hostname. That is what Jamf,
# Intune, SentinelOne and most RMMs key on. device_name carries the hostname,
# which is what a human recognises and what platforms with no serial can join
# on. The dashboard prefers device_name and falls back to device, so a
# collector sending only the serial shows a serial where scanners show a name.
DEVICE_NAME=$(hostname 2>/dev/null || echo "")

DEVICE=""
if [ -r /sys/class/dmi/id/product_serial ]; then
  DEVICE=$(tr -d ' \n' < /sys/class/dmi/id/product_serial 2>/dev/null)
fi
[ -z "$DEVICE" ] && [ -r /etc/machine-id ] && DEVICE=$(cat /etc/machine-id 2>/dev/null)
# Said out loud. Falling back to the hostname changes what every finding from
# this machine is keyed on, and a hostname is mutable where a serial is not.
# Silence would make it indistinguishable from a machine that reported a real
# serial, which is how one device becomes two on a dashboard that groups by it.
if [ -z "$DEVICE" ]; then
  echo "[ai-guard] no DMI serial or machine-id readable, using hostname for device"
  DEVICE="$DEVICE_NAME"
fi

# --------------------------------------------------------------- helpers ---
# domain_of <email> - strip local-part, lowercase. Never reports local-part.
domain_of() {
  case "$1" in
    *@*) printf '%s' "${1##*@}" | tr '[:upper:]' '[:lower:]' ;;
    *) : ;;
  esac
}

# is_corp <domain> - is this one of the configured corporate domains?
is_corp() {
  local d="$1" c old
  [ -n "$d" ] || return 1
  old="$IFS"; IFS=','
  for c in $CORP_DOMAINS; do
    c=$(printf '%s' "$c" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    [ -n "$c" ] && [ "$c" = "$d" ] && { IFS="$old"; return 0; }
  done
  IFS="$old"; return 1
}

# ------------------------------------------------------------- json tools --
# python3 is present on developer machines. These mirror the macOS collector's
# json_get / json_keys (which use JXA there) with the same contract, so the
# scan bodies below are identical to the macOS ones.

# json_get <file> <key...> - walk a JSON path, print string value or "".
# Tolerant of the .claude.json duplicate-key problem (json.load keeps last).
json_get() {
  local f="$1"; shift
  [ -n "$PY" ] || { json_get_fallback "$f" "$@"; return; }
  "$PY" - "$f" "$@" <<'PYEOF' 2>/dev/null
import json, sys
f, keys = sys.argv[1], sys.argv[2:]
try:
    with open(f) as fh:
        cur = json.load(fh)
    for k in keys:
        cur = cur[k]
    print(cur if isinstance(cur, str) else "")
except Exception:
    print("")
PYEOF
}

# json_keys <file> <key> - comma-separated sorted keys of the object at <key>.
json_keys() {
  local f="$1" key="$2"
  [ -n "$PY" ] || { json_keys_fallback "$f" "$key"; return; }
  "$PY" - "$f" "$key" <<'PYEOF' 2>/dev/null
import json, sys
f, key = sys.argv[1], sys.argv[2]
try:
    with open(f) as fh:
        obj = json.load(fh).get(key) or {}
    print(",".join(sorted(obj.keys())) if isinstance(obj, dict) else "")
except Exception:
    print("")
PYEOF
}

# Fallbacks for the (unexpected) no-python3 case: line-wise extraction, the
# same approach the Windows collector uses. Handles only the leaf field, which
# is all the cli scan needs.
json_get_fallback() {
  local f="$1"; shift
  local leaf="" k
  for k in "$@"; do leaf="$k"; done
  grep -oE "\"$leaf\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$f" 2>/dev/null \
    | head -1 | sed -E "s/.*:[[:space:]]*\"([^\"]*)\"/\1/"
}
json_keys_fallback() {
  local f="$1" key="$2"
  awk -v key="\"$key\"" '
    index($0,key){cap=1; next}
    cap && /}/{cap=0}
    cap && match($0,/"[^"]+"[[:space:]]*:/){
      s=substr($0,RSTART+1); sub(/".*/,"",s); print s
    }' "$f" 2>/dev/null | sort | paste -sd, -
}

# decode a JWT claim (codex-cli stores identity in an id_token)
jwt_claim() {
  local jwt="$1" claim="$2" payload
  payload=$(printf '%s' "$jwt" | cut -d. -f2)
  case $(( ${#payload} % 4 )) in 2) payload="${payload}==";; 3) payload="${payload}=";; esac
  printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null \
    | grep -oE "\"$claim\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 \
    | sed -E "s/.*:[[:space:]]*\"([^\"]*)\"/\1/"
}

# ------------------------------------------------------------- reporting ---
# Evidence labels use a literal ~ so a username never lands in a finding.
# A quoted "~" does not expand (SC2088); that is intended here - it is a label.
HOME_LABEL='~'
POSTED=0; SUPPRESSED=0; POST_FAILURES=0; WARN_COUNT=0; PARSE_FAILURES=0
SUMMARY=""
SEEN=""

# throttle state: key "surface|tool|domain" -> last-reported epoch
declare_state() { :; }
state_get() {
  [ -f "$STATE_FILE" ] || return 1
  grep -F "$1 " "$STATE_FILE" 2>/dev/null | tail -1 | awk '{print $2}'
}

# json_escape <string> - escape a value for use inside a JSON string.
# Findings carry values the script does not control: device names, usernames,
# and evidence built from registry data. A quote or a backslash in any of them
# turns the payload into invalid JSON, the receiver rejects it, and the finding
# is lost with nothing to say so. Order matters: backslash first, or the
# escapes added afterwards get escaped again. Remaining control characters are
# dropped rather than emitted raw, since raw ones are invalid JSON and these
# values are labels, not data anyone parses.
json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//[[:cntrl:]]/}
  printf '%s' "$s"
}

# report <surface> <tool> <account> <evidence>
report() {
  local surface="$1" tool="$2" acct="$3" evidence="$4"
  local severity="info" key prev interval

  if [ -n "$acct" ] && ! is_corp "$acct"; then
    severity="warn"; WARN_COUNT=$((WARN_COUNT + 1))
  fi

  if [ -n "$acct" ]; then SUMMARY="$SUMMARY $tool($acct);"; else SUMMARY="$SUMMARY $tool;"; fi

  # Throttle by severity: info daily, warn hourly. A key with no previous
  # timestamp falls through regardless, so new findings are never delayed.
  key="$surface|$tool|$acct"
  interval="$INFO_INTERVAL"
  [ "$severity" = "warn" ] && interval="$WARN_INTERVAL"

  prev=$(state_get "$key")
  if [ -n "$prev" ] && [ $((NOW_EPOCH - prev)) -lt "$interval" ]; then
    printf '%s %s\n' "$key" "$prev" >> "$STATE_NEW"
    SUPPRESSED=$((SUPPRESSED + 1))
    return
  fi

  # severity and reported_at are generated here, so they need no escaping.
  # Everything else came from the registry, the machine or a config file.
  local payload
  payload=$(printf '{"tool":"%s","surface":"%s","os":"linux","account_domain":"%s","device":"%s","device_name":"%s","user":"%s","evidence":"%s","severity":"%s","reported_at":"%s","source":"collector-linux"}' \
    "$(json_escape "$tool")" "$(json_escape "$surface")" "$(json_escape "$acct")" \
    "$(json_escape "$DEVICE")" "$(json_escape "$DEVICE_NAME")" \
    "$(json_escape "$CONSOLE_USER")" "$(json_escape "$evidence")" \
    "$severity" "$NOW")
  if [ -z "$ENDPOINT" ]; then
    echo "[ai-guard] FLAG (no endpoint set): $payload"
    # Print-only: preserve old timestamp if one exists, but don't advance it.
    local old_ts
    old_ts=$(state_get "$key")
    [ -n "$old_ts" ] && printf '%s %s\n' "$key" "$old_ts" >> "$STATE_NEW"
    return
  fi
  local code
  code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $TOKEN" \
    -H "X-AiGuard-Agent-Version: $COLLECTOR_VERSION" \
    -H 'Content-Type: application/json' \
    --data "$payload" "$ENDPOINT" 2>/dev/null || echo 000)
  if [ "$code" = "200" ] || [ "$code" = "204" ]; then
    POSTED=$((POSTED + 1))
    printf '%s %s\n' "$key" "$NOW_EPOCH" >> "$STATE_NEW"
  else
    echo "[ai-guard] POST failed: HTTP $code for $tool -> $ENDPOINT"
    POST_FAILURES=$((POST_FAILURES + 1))
    # Keep the old timestamp so the finding retries next run.
    local old_ts
    old_ts=$(state_get "$key")
    [ -n "$old_ts" ] && printf '%s %s\n' "$key" "$old_ts" >> "$STATE_NEW"
  fi
}

# report_once <surface> <tool> <account> <evidence> - one finding per
# surface+tool per run (a tool can match several identifiers).
report_once() {
  local k="$1|$2"
  case "$SEEN" in *"[$k]"*) return 0 ;; esac
  SEEN="${SEEN}[$k]"
  report "$@"
}

# ---------------------------------------------------------------- registry --
SEP=$(printf '\x1f')
REG_FILE=""; REG_TMP=""
cleanup() { [ -n "$REG_TMP" ] && rm -f "$REG_TMP"; }
trap cleanup EXIT

fetch_registry() {
  if [ -n "${AIGUARD_REGISTRY_FILE:-}" ]; then
    REG_FILE="$AIGUARD_REGISTRY_FILE"; [ -f "$REG_FILE" ]; return $?
  fi
  [ -n "$RECEIVER_BASE" ] || return 1
  REG_TMP=$(mktemp /tmp/ai-guard-reg.XXXXXX) || return 1
  REG_FILE="$REG_TMP"
  local code
  code=$(curl -s -m 15 -o "$REG_FILE" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "${RECEIVER_BASE%/}/registry/collector" 2>/dev/null || echo 000)
  [ "$code" = "200" ]
}

# registry_tsv <file> - flatten collector registry to \x1f-separated rows.
# Same shape as the macOS collector's JXA version, built with python3.
registry_tsv() {
  [ -n "$PY" ] || { registry_tsv_fallback "$1"; return; }
  "$PY" - "$1" <<'PYEOF' 2>/dev/null
import json, sys
U = "\x1f"
try:
    r = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
out = []
for t in r.get("ide", []):
    e = t.get("extension_ids") or {}
    # linux VS Code / Cursor use the same extension IDs as elsewhere.
    # chrome/edge IDs are browser extensions: matched against installed
    # extension folders in Chrome-family browser profiles below.
    for x in e.get("vscode", []):
        out.append(U.join(["ide", x, t["tool"]]))
    for x in e.get("chrome", []):
        out.append(U.join(["bext", "chrome", x, t["tool"]]))
    for x in e.get("edge", []):
        out.append(U.join(["bext", "edge", x, t["tool"]]))
for t in r.get("desktop", []):
    for a in (t.get("app_names") or []):
        out.append(U.join(["app", a, t["tool"]]))
for t in r.get("cli", []):
    out.append(U.join(["cli", t["tool"], t.get("account_json_path",""),
                        ",".join(t.get("account_json_keys") or []),
                        ",".join(t.get("account_jwt_path") or []),
                        t.get("account_jwt_claim",""),
                        ",".join(t.get("config_paths") or []),
                        ",".join(t.get("binaries") or [])]))
for m in r.get("mcp", []):
    out.append(U.join(["mcp", m["tool"], m["path"], m.get("os","any")]))
print("\n".join(out))
PYEOF
}

# No-python fallback: minimal grep-based extraction of the fields the scans use.
registry_tsv_fallback() {
  # Without a JSON parser we cannot reliably flatten nested arrays; emit the
  # cli rows only (the highest-value account findings) via python-free jq-less
  # parsing is not attempted. Better to fail loud than half-scan.
  echo "[ai-guard] python3 unavailable and no fallback registry parse; refusing" >&2
  return 1
}

# ------------------------------------------------------------- enrollment --
# Managed mode. A stored device credential wins; an enrollment token
# (aige_...) is exchanged for one on first run; anything else is today's
# behaviour exactly. The prefix is the whole switch: the operator changes one
# RMM variable from the shared token to an enrollment token when ready.
if [ -f "$CRED_FILE" ]; then
  STORED_CRED=$(cat "$CRED_FILE" 2>/dev/null)
  case "$STORED_CRED" in aigd_*) TOKEN="$STORED_CRED" ;; esac
fi
case "$TOKEN" in
  aige_*)
    if [ -n "$RECEIVER_BASE" ]; then
      mkdir -p "$STATE_DIR"
      ENROLL_BODY=$(printf '{"platform":"linux","serial":"%s","hostname":"%s","agent_version":"%s"}' \
        "$(json_escape "$DEVICE")" "$(json_escape "$DEVICE_NAME")" "$COLLECTOR_VERSION")
      ENROLL_RESP=$(mktemp /tmp/ai-guard-enroll.XXXXXX)
      ENROLL_CODE=$(curl -s -m 15 -o "$ENROLL_RESP" -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        --data "$ENROLL_BODY" "${RECEIVER_BASE%/}/enroll" 2>/dev/null || echo 000)
      if [ "$ENROLL_CODE" = "200" ]; then
        if [ -n "$PY" ]; then
          CRED=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("device_token",""))' "$ENROLL_RESP" 2>/dev/null)
        else
          # Our own compact JSON, and the credential is URL-safe base64:
          # sed is sufficient where a general parser is not available.
          CRED=$(sed -n 's/.*"device_token":"\([^"]*\)".*/\1/p' "$ENROLL_RESP")
        fi
        if [ -n "$CRED" ]; then
          if ( umask 077; printf '%s' "$CRED" > "$CRED_FILE" ) 2>/dev/null; then
            chmod 600 "$CRED_FILE" 2>/dev/null
            TOKEN="$CRED"
            echo "[ai-guard] enrolled: device credential stored in $CRED_FILE"
          else
            # Loud and fatal, like an enrollment refusal: the receiver just
            # minted this device a credential, and losing it here means every
            # future run enrolls again - device churn in the fleet view and,
            # once a run reports, a 409 that blocks the fix for an hour.
            # Exiting before the scan keeps this device silent, so a correctly
            # privileged run supersedes it immediately.
            echo "[ai-guard] enrolled, but cannot write $CRED_FILE (run as root?)"
            echo "[ai-guard] refusing to scan: the credential would be lost and every run would re-enroll"
            rm -f "$ENROLL_RESP"
            exit 1
          fi
        fi
      else
        # Loud and fatal: an enrollment token cannot report findings, so
        # carrying on would 401 every POST and look like a clean machine.
        # A 409 here means a device with this serial is actively reporting -
        # revoke it on the receiver first. A 401 usually means the token
        # expired: mint a fresh one and update the RMM variable.
        echo "[ai-guard] enrollment failed: HTTP $ENROLL_CODE from ${RECEIVER_BASE%/}/enroll"
        echo "[ai-guard] refusing to scan: an enrollment token cannot report findings"
        rm -f "$ENROLL_RESP"
        exit 1
      fi
      rm -f "$ENROLL_RESP"
    fi
    ;;
esac

if ! fetch_registry; then
  echo "[ai-guard] registry fetch failed: ${RECEIVER_BASE%/}/registry/collector"
  echo "[ai-guard] refusing to scan without an identifier list - an empty scan looks like a clean machine"
  case "$TOKEN" in aigd_*)
    echo "[ai-guard] this machine's device credential may have been revoked;"
    echo "[ai-guard] delete $CRED_FILE and supply a valid enrollment token to re-enroll"
  ;; esac
  exit 1
fi
REG_TSV=$(registry_tsv "$REG_FILE")
if [ -z "$REG_TSV" ]; then
  echo "[ai-guard] registry parse failed: $REG_FILE"
  exit 1
fi

# Corporate domains can arrive with the registry: the receiver serves
# config.corp_domains in the payload just fetched when it has CORP_DOMAINS
# set. The served list wins over AIGUARD_CORP_DOMAINS, because a list changed
# once on the receiver reaches the fleet on its next run rather than waiting
# on an RMM variable edit per platform; the variable stays as the fallback,
# so a receiver serving nothing changes nothing. Guarded on $PY, though a
# registry parse without python3 already refused above.
if [ -n "$PY" ]; then
  CENTRAL_DOMAINS=$("$PY" - "$REG_FILE" <<'PYEOF' 2>/dev/null
import json, sys
try:
    r = json.load(open(sys.argv[1]))
    print(",".join((r.get("config") or {}).get("corp_domains") or []))
except Exception:
    pass
PYEOF
)
  if [ -n "$CENTRAL_DOMAINS" ]; then
    echo "[ai-guard] corporate domains from receiver: $CENTRAL_DOMAINS"
    CORP_DOMAINS="$CENTRAL_DOMAINS"
  fi
fi

STATE_NEW=$(mktemp /tmp/ai-guard-state.XXXXXX)
trap 'cleanup; rm -f "$STATE_NEW"' EXIT

# json_get_csv <file> <comma-separated-key-path>
json_get_csv() {
  local f="$1" keys="$2" old="$IFS"
  IFS=','; set -- $keys; IFS="$old"
  json_get "$f" "$@"
}

# safe_rel_path <path> - true if a registry-supplied path is safe to join to
# a home directory. The collector runs as root and the registry arrives over
# the network, so the value is treated as input rather than configuration:
# absolute paths, drive letters, parent traversal and control characters are
# refused. Symlinks are not resolved. The threat here is a tampered registry,
# and a symlink the user made inside their own home is not that.
#
# A bad entry is skipped rather than fatal. Aborting the scan would mean one
# poisoned path could switch off detection everywhere, which is a better
# outcome for an attacker than being ignored.
safe_rel_path() {
  case "$1" in
    "" ) return 1 ;;
    /* | \\* ) return 1 ;;
    [A-Za-z]:* ) return 1 ;;
    *..* ) return 1 ;;
  esac
  [ "${#1}" -le 256 ] || return 1
  case "$1" in *[[:cntrl:]]* ) return 1 ;; esac
  return 0
}

# resolve_under_home <absolute-path> - print the real path if it stays inside
# the home directory, fail if it does not.
#
# safe_rel_path above rejects a registry value that tries to escape. This
# catches the other half: a path that looks fine but resolves somewhere else,
# because a symlink on the machine points out of the home directory. The
# collector runs as root, so following one reads a file the user could not.
#
# Symlinks are resolved rather than rejected. Dotfiles are commonly managed
# by symlinking them into a checkout, and those are exactly the machines that
# have AI CLIs on them; refusing to follow any link would drop real findings
# to prevent an unlikely one.
#
# No realpath or readlink -f: neither is dependable on macOS. The loop walks
# links one at a time, and pwd -P canonicalises the directory chain.
resolve_under_home() {
  local p="$1" hops=0 target dir base
  [ -e "$p" ] || return 1
  while [ -L "$p" ]; do
    hops=$((hops + 1))
    [ "$hops" -le 16 ] || return 1        # a symlink loop, or someone being clever
    target=$(readlink "$p") || return 1
    case "$target" in
      /*) p="$target" ;;
      *)  p="$(dirname "$p")/$target" ;;
    esac
    [ -e "$p" ] || return 1
  done
  dir=$(dirname "$p")
  base=$(basename "$p")
  dir=$(cd "$dir" 2>/dev/null && pwd -P) || return 1
  case "$dir/$base" in
    "$HOME_REAL"/*) printf '%s' "$dir/$base"; return 0 ;;
  esac
  return 1
}

# first_existing <base> <comma-paths> - print first path that exists
first_existing() {
  local base="$1" list="$2" old="$IFS" c
  IFS=','; set -- $list; IFS="$old"
  for c in "$@"; do
    [ -n "$c" ] || continue
    safe_rel_path "$c" || continue
    resolve_under_home "$base/$c" >/dev/null 2>&1 || continue
    [ -e "$base/$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# first_binary <comma-names> - print first found on PATH or common bins
first_binary() {
  local list="$1" old="$IFS" b
  IFS=','; set -- $list; IFS="$old"
  for b in "$@"; do
    [ -n "$b" ] || continue
    if command -v "$b" >/dev/null 2>&1 \
       || [ -x "/usr/local/bin/$b" ] \
       || [ -x "$HOME_DIR/.local/bin/$b" ] \
       || [ -x "/home/linuxbrew/.linuxbrew/bin/$b" ]; then
      printf '%s' "$b"; return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------- cli -------
# Tools that store an account identity in a config file. The registry says
# where the file is and how to read it.
while IFS="$SEP" read -r _kind tool acct_path keys jwt_path jwt_claim cfg_paths _bins; do
  [ -n "$acct_path" ] || continue
  if ! safe_rel_path "$acct_path"; then
    echo "[ai-guard] refusing registry path for $tool: not relative to home" >&2
    continue
  fi
  f=$(resolve_under_home "$HOME_DIR/$acct_path") || f=""
  if [ -f "$f" ]; then
    email=""
    if [ -n "$keys" ]; then
      email=$(json_get_csv "$f" "$keys")
    elif [ -n "$jwt_path" ]; then
      idt=$(json_get_csv "$f" "$jwt_path")
      [ -n "$idt" ] && email=$(jwt_claim "$idt" "$jwt_claim")
    fi
    report_once "cli" "$tool" "$(domain_of "$email")" "$HOME_LABEL/$acct_path"
  else
    hit=$(first_existing "$HOME_DIR" "$cfg_paths") \
      && report_once "cli" "$tool" "" "$HOME_LABEL/$hit"
  fi
done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^cli${SEP}")
EOF

# ---------------------------------------------------------------- ide -------
# VS Code / Cursor extensions live in ~/.vscode/extensions and
# ~/.cursor/extensions on Linux, same as macOS.
scan_ext_dir() {
  local dir="$1" label="$2" d base
  [ -d "$dir" ] || return 0
  for d in "$dir"/*/; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    while IFS="$SEP" read -r _k ext tool; do
      case "$base" in "$ext"-*) report_once "ide" "$tool" "" "$label/$base" ;; esac
    done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^ide${SEP}")
EOF
  done
}
scan_ext_dir "$HOME_DIR/.vscode/extensions" ".vscode/extensions"
scan_ext_dir "$HOME_DIR/.vscode-server/extensions" ".vscode-server/extensions"
scan_ext_dir "$HOME_DIR/.cursor/extensions" ".cursor/extensions"

# ------------------------------------------------- browser extensions -------
# Installed browser extensions, matched by extension id against the registry.
# Presence is the finding: an AI extension reads pages without anything being
# pasted. Chrome, Chromium and Brave install from the Chrome store, so all
# match chrome ids; Edge installs from both stores, so it matches both sets.
# Snap Chromium keeps profiles under ~/snap and is not covered.
scan_browser_extensions() {
  local root="$1" label="$2" idkinds="$3" pdir profile extdir ext
  [ -d "$root" ] || return 0
  for pdir in "$root/Default" "$root"/Profile\ *; do
    [ -d "$pdir/Extensions" ] || continue
    profile=$(basename "$pdir")
    for extdir in "$pdir/Extensions"/*/; do
      [ -d "$extdir" ] || continue
      ext=$(basename "$extdir")
      while IFS="$SEP" read -r _k bkind id tool; do
        case ",$idkinds," in *",$bkind,"*) ;; *) continue ;; esac
        [ "$ext" = "$id" ] && report_once "browser" "$tool" "" "$label/$profile extension $id"
      done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^bext${SEP}")
EOF
    done
  done
}
scan_browser_extensions "$HOME_DIR/.config/google-chrome"               "Chrome"   "chrome"
scan_browser_extensions "$HOME_DIR/.config/chromium"                    "Chromium" "chrome"
scan_browser_extensions "$HOME_DIR/.config/BraveSoftware/Brave-Browser" "Brave"    "chrome"
scan_browser_extensions "$HOME_DIR/.config/microsoft-edge"              "Edge"     "chrome,edge"
# Flatpak installs keep browser profiles under ~/.var/app/<app-id>/config.
scan_browser_extensions "$HOME_DIR/.var/app/com.google.Chrome/config/google-chrome" "Chrome (flatpak)" "chrome"
scan_browser_extensions "$HOME_DIR/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser" "Brave (flatpak)" "chrome"

# ---------------------------------------------------------------- desktop ---
# Linux desktop apps: registry app_names may carry a macOS ".app" suffix, so
# match on the basename without it against .desktop files and binaries.
while IFS="$SEP" read -r _kind app tool; do
  name="${app%.app}"
  # .desktop entries (system + per-user), and a same-named binary
  if ls "$HOME_DIR/.local/share/applications/"*"$name"* >/dev/null 2>&1 \
     || ls "/usr/share/applications/"*"$name"* >/dev/null 2>&1 \
     || command -v "$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" >/dev/null 2>&1; then
    report_once "desktop" "$tool" "" "$name"
  fi
done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^app${SEP}")
EOF

# Local runtimes / editors with no account file: presence via config dir or
# binary. Tools WITH an account file are handled by the cli scan above.
while IFS="$SEP" read -r _kind tool acct_path _keys _jwt _claim cfg_paths bins; do
  [ -n "$acct_path" ] && continue
  hit=$(first_existing "$HOME_DIR" "$cfg_paths") \
    && { report_once "desktop" "$tool" "" "$HOME_LABEL/$hit"; continue; }
  bin=$(first_binary "$bins") \
    && report_once "desktop" "$tool" "" "$bin binary"
done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^cli${SEP}")
EOF

# ---------------------------------------------------------------- mcp -------
while IFS="$SEP" read -r _kind tool path os; do
  # skip rows scoped to another OS; Linux uses the "any" rows (and Claude
  # Desktop on Linux uses the same ~/.config path as the "any" default).
  case "$os" in any|linux) ;; *) continue ;; esac
  if ! safe_rel_path "$path"; then
    echo "[ai-guard] refusing registry path for $tool: not relative to home" >&2
    continue
  fi
  f=$(resolve_under_home "$HOME_DIR/$path") || continue
  [ -f "$f" ] || continue
  servers=$(json_keys "$f" mcpServers)
  # The tool is the tool. The server list is evidence, not identity: folding it
  # into the name made every distinct combination of servers a separate tool,
  # so a machine with figma and context7 looked unrelated to a machine with
  # figma alone. About twenty two near-identical rows where there should have
  # been three.
  [ -n "$servers" ] && report_once "mcp" "${tool}-mcp" "" "$path mcpServers: $servers"
done <<EOF
$(printf '%s\n' "$REG_TSV" | grep "^mcp${SEP}")
EOF

# ---------------------------------------------------------------- summary ---
mkdir -p "$STATE_DIR" 2>/dev/null
sort -u "$STATE_NEW" > "$STATE_FILE" 2>/dev/null || cp "$STATE_NEW" "$STATE_FILE"

post_status="posted=$POSTED suppressed=$SUPPRESSED"
[ "$POST_FAILURES" -gt 0 ] && post_status="POST-FAILED=$POST_FAILURES $post_status"
[ "$PARSE_FAILURES" -gt 0 ] && post_status="PARSE-FAILED=$PARSE_FAILURES $post_status"
[ -z "$ENDPOINT" ] && post_status="print-only"
[ -z "$SUMMARY" ] && SUMMARY=" none"
echo "${SUMMARY# } [$post_status] ($NOW)" > "$SUMMARY_FILE" 2>/dev/null
echo "[ai-guard]${SUMMARY} [$post_status]"

if [ "$POST_FAILURES" -gt 0 ] || [ "$WARN_COUNT" -gt 0 ] || [ "$PARSE_FAILURES" -gt 0 ]; then
  exit 1
fi
exit 0