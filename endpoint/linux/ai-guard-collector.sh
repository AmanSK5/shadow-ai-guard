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
#   AIGUARD_TOKEN           receiver bearer token
#   AIGUARD_CORP_DOMAINS    comma-separated corporate domains, e.g. example.com
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
SUMMARY_DIR="$STATE_DIR"
SUMMARY_FILE="$SUMMARY_DIR/last_scan.txt"
INFO_INTERVAL=$((24 * 3600))

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

# Stable device identifier. Prefer the DMI product serial (root can read it),
# fall back to machine-id, then hostname. Never blank.
DEVICE=""
if [ -r /sys/class/dmi/id/product_serial ]; then
  DEVICE=$(tr -d ' \n' < /sys/class/dmi/id/product_serial 2>/dev/null)
fi
[ -z "$DEVICE" ] && [ -r /etc/machine-id ] && DEVICE=$(cat /etc/machine-id 2>/dev/null)
[ -z "$DEVICE" ] && DEVICE=$(hostname)

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

# report <surface> <tool> <account> <evidence>
report() {
  local surface="$1" tool="$2" acct="$3" evidence="$4"
  local severity="info" key prev

  if [ -n "$acct" ] && ! is_corp "$acct"; then
    severity="warn"; WARN_COUNT=$((WARN_COUNT + 1))
  fi

  if [ -n "$acct" ]; then SUMMARY="$SUMMARY $tool($acct);"; else SUMMARY="$SUMMARY $tool;"; fi

  key="$surface|$tool|$acct"
  if [ "$severity" = "info" ]; then
    prev=$(state_get "$key")
    if [ -n "$prev" ] && [ $((NOW_EPOCH - prev)) -lt "$INFO_INTERVAL" ]; then
      printf '%s %s\n' "$key" "$prev" >> "$STATE_NEW"
      SUPPRESSED=$((SUPPRESSED + 1))
      return
    fi
  fi

  local payload
  payload=$(cat <<JSON
{"tool":"$tool","surface":"$surface","os":"linux","account_domain":"$acct","device":"$DEVICE","user":"$CONSOLE_USER","evidence":"$evidence","severity":"$severity","reported_at":"$NOW","source":"collector-linux"}
JSON
)
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
    # chrome/edge IDs in the registry are browser extensions, not IDE.
    for x in e.get("vscode", []):
        out.append(U.join(["ide", x, t["tool"]]))
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

if ! fetch_registry; then
  echo "[ai-guard] registry fetch failed: ${RECEIVER_BASE%/}/registry/collector"
  echo "[ai-guard] refusing to scan without an identifier list - an empty scan looks like a clean machine"
  exit 1
fi
REG_TSV=$(registry_tsv "$REG_FILE")
if [ -z "$REG_TSV" ]; then
  echo "[ai-guard] registry parse failed: $REG_FILE"
  exit 1
fi

STATE_NEW=$(mktemp /tmp/ai-guard-state.XXXXXX)
trap 'cleanup; rm -f "$STATE_NEW"' EXIT

# json_get_csv <file> <comma-separated-key-path>
json_get_csv() {
  local f="$1" keys="$2" old="$IFS"
  IFS=','; set -- $keys; IFS="$old"
  json_get "$f" "$@"
}

# first_existing <base> <comma-paths> - print first path that exists
first_existing() {
  local base="$1" list="$2" old="$IFS" c
  IFS=','; set -- $list; IFS="$old"
  for c in "$@"; do
    [ -n "$c" ] || continue
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
  f="$HOME_DIR/$acct_path"
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
  f="$HOME_DIR/$path"
  [ -f "$f" ] || continue
  servers=$(json_keys "$f" mcpServers)
  [ -n "$servers" ] && report_once "mcp" "${tool}-mcp:$servers" "" "$path mcpServers"
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