#!/bin/bash
#
# ai-guard endpoint collector (macOS)
# -----------------------------------
# Scans the console user's machine for AI tooling across four surfaces:
#   cli      - tools that store an account identity in a config file
#   ide      - AI extensions in VS Code / Cursor / JetBrains
#   desktop  - AI desktop apps, local runtimes and their binaries
#   mcp      - MCP server definitions in AI tool configs
#
# The identifiers for all four come from the receiver's /registry/collector
# at runtime. Nothing tool-specific is hardcoded in this script: adding a new
# AI tool is a registry merge request, not a script edit plus an MDM re-paste.
#
# Privacy: the account_domain field is the domain only. The console username
# is sent in the user field (already known to IT via MDM).
# Same flag schema as the companion browser extension, plus "surface", "os", "severity".
#
# Deployment: Jamf policy script, recurring check-in (daily).
#   Parameter 4: receiver base URL (e.g. https://ai-guard.example.com)
#   Parameter 5: bearer token
#   Parameter 6: corporate domains, comma-separated (e.g. example.com,example.co.uk).
#                 Accounts on these domains report as work; anything else is a
#                 personal account and escalates severity.
#
# Local test: AIGUARD_REGISTRY_FILE=registry/dist/collector.json ./ai-guard-collector.sh
# with no args - findings are printed instead of POSTed.
#
# Also writes a one-line summary to /Library/Application Support/ai-guard/last_scan.txt
# which the companion Jamf Extension Attribute reads into inventory.

set -u

# Parameter 4 is the receiver base URL (https://host). The report path is
# appended here so a trailing slash in the Jamf parameter can never produce
# //report. An empty parameter leaves ENDPOINT empty: print-only mode.
RECEIVER_BASE="${4:-}"
ENDPOINT=""
[ -n "$RECEIVER_BASE" ] && ENDPOINT="${RECEIVER_BASE%/}/report"
TOKEN="${5:-}"
CORP_DOMAINS="${6:-}"

SUMMARY_DIR="/Library/Application Support/ai-guard"
SUMMARY_FILE="$SUMMARY_DIR/last_scan.txt"

# Report throttling. The policy runs at every recurring check-in (~20 min)
# so personal-account findings surface fast, but unchanged inventory (info)
# findings only need reporting once a day. STATE_FILE holds one line per
# already-reported info finding: "<key> <epoch>". warn findings are never
# throttled. A finding not yet in the state file (new tool, new account)
# reports immediately, so a fresh install surfaces within one check-in.
STATE_FILE="$SUMMARY_DIR/reported.state"
INFO_REPORT_INTERVAL=$(( 24 * 3600 ))
NOW_EPOCH=$(/bin/date +%s)
STATE_OLD=""
[ -f "$STATE_FILE" ] && STATE_OLD=$(/bin/cat "$STATE_FILE" 2>/dev/null)
STATE_NEW=""
SUPPRESSED=0

state_lookup() {  # state_lookup <key> -> prints epoch or nothing
  printf '%s\n' "$STATE_OLD" | /usr/bin/awk -v k="$1" '$1 == k {print $2; exit}'
}

# ---------------------------------------------------------------- context ---

CONSOLE_USER=$(/usr/bin/stat -f%Su /dev/console)
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
  # No one logged in; fall back to the most recently modified real user home
  CONSOLE_USER=$(/bin/ls -t /Users | /usr/bin/grep -v -e '^Shared$' -e '^\.' | /usr/bin/head -1)
fi
HOME_DIR=$(/usr/bin/dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')
[ -z "${HOME_DIR:-}" ] && HOME_DIR="/Users/$CONSOLE_USER"

SERIAL=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | /usr/bin/awk -F'"' '/IOPlatformSerialNumber/{print $4}')
NOW=$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------- helpers ---

# json_get <file> <key> [key...]  - walk a JSON path, print string value or ""
# Uses JXA so there is no dependency on jq or python3.
json_get() {
  /usr/bin/osascript -l JavaScript -e '
    function run(argv) {
      try {
        var s = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js;
        var o = JSON.parse(s);
        for (var i = 1; i < argv.length; i++) {
          o = o[argv[i]];
          if (o === undefined || o === null) return "";
        }
        return String(o);
      } catch (e) { return ""; }
    }' "$@" 2>/dev/null
}

# json_keys <file> <key> - print comma-separated keys of an object at <key>
json_keys() {
  /usr/bin/osascript -l JavaScript -e '
    function run(argv) {
      try {
        var s = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js;
        var o = JSON.parse(s)[argv[1]];
        if (!o || typeof o !== "object") return "";
        return Object.keys(o).join(",");
      } catch (e) { return ""; }
    }' "$@" 2>/dev/null
}

# domain_of <email> - strip local-part, lowercase. Never reports the local-part.
domain_of() {
  local e="$1"
  case "$e" in
    *@*) printf '%s' "${e##*@}" | /usr/bin/tr '[:upper:]' '[:lower:]' ;;
    *)   printf '' ;;
  esac
}

SUMMARY_PARTS=()
POST_OK=0
POST_FAILURES=0

# report <surface> <tool> <account_domain> <evidence>
report() {
  local surface="$1" tool="$2" acct="$3" evidence="$4" severity="info"
  if [ -n "$acct" ]; then
    case ",${CORP_DOMAINS}," in
      *",${acct},"*) ;;          # corporate (any alias) -> info
      *) severity="warn" ;;      # anything else -> personal account
    esac
  fi

  # Throttle: info findings already reported within the interval are
  # suppressed; warns always go. Key includes the account domain, so a
  # tool switching from corporate to personal account is a NEW key and
  # reports immediately even though the tool itself was known.
  local key="${surface}|${tool}|${acct}"
  if [ "$severity" = "info" ]; then
    local last
    last=$(state_lookup "$key")
    if [ -n "$last" ] && [ $(( NOW_EPOCH - last )) -lt "$INFO_REPORT_INTERVAL" ]; then
      STATE_NEW="${STATE_NEW}${key} ${last}
"
      SUPPRESSED=$((SUPPRESSED + 1))
      if [ -n "$acct" ]; then SUMMARY_PARTS+=("$tool($acct)"); else SUMMARY_PARTS+=("$tool"); fi
      return 0
    fi
  fi

  local payload
  payload=$(/usr/bin/printf '{"tool":"%s","surface":"%s","os":"macos","account_domain":"%s","device":"%s","user":"%s","evidence":"%s","severity":"%s","reported_at":"%s"}' \
    "$tool" "$surface" "$acct" "$SERIAL" "$CONSOLE_USER" "$evidence" "$severity" "$NOW")

  local delivered=false
  if [ -n "$ENDPOINT" ]; then
    local http_code
    http_code=$(/usr/bin/curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$payload" || echo "000")
    if [ "$http_code" != "200" ]; then
      # A collector that fails silently across a fleet produces a clean
      # dashboard and false confidence. Fail loudly: Jamf shows this line
      # in the policy log and the script exits non-zero at the end.
      echo "[ai-guard] POST failed: HTTP $http_code for $tool -> $ENDPOINT"
      POST_FAILURES=$((POST_FAILURES + 1))
    else
      POST_OK=$((POST_OK + 1))
      delivered=true
    fi
  else
    echo "[ai-guard] FLAG (no endpoint set): $payload"
  fi

  # Advance the throttle timestamp only after confirmed delivery.
  # On failure, keep the old timestamp (if any) so the finding retries
  # on the next run rather than being suppressed for 24h.
  if [ "$delivered" = true ]; then
    STATE_NEW="${STATE_NEW}${key} ${NOW_EPOCH}
"
  else
    local old_ts
    old_ts=$(state_lookup "$key")
    if [ -n "$old_ts" ]; then
      STATE_NEW="${STATE_NEW}${key} ${old_ts}
"
    fi
  fi

  if [ -n "$acct" ]; then
    SUMMARY_PARTS+=("$tool($acct)")
  else
    SUMMARY_PARTS+=("$tool")
  fi
}

# ---------------------------------------------------------------- registry --

# Which extension IDs, app names, config paths and MCP files belong to which
# tool now comes from the receiver at runtime. It used to be hardcoded here,
# which meant a new AI tool needed a script edit and an MDM re-paste on every
# machine, while the registry that should have owned that list was already
# being maintained by merge request. A new tool is now a registry MR only.
#
# Fields are separated by \x1f (unit separator), not tab: tab is IFS
# whitespace, so `IFS=$'\t' read` silently collapses consecutive empty
# fields and the CLI rows below have several.
SEP=$(printf '\x1f')

REG_FILE=""
REG_TMP=""
cleanup() { [ -n "$REG_TMP" ] && /bin/rm -f "$REG_TMP"; }
trap cleanup EXIT

fetch_registry() {
  # AIGUARD_REGISTRY_FILE points at a checked-out registry/dist/collector.json
  # so the script can be run locally with no receiver.
  if [ -n "${AIGUARD_REGISTRY_FILE:-}" ]; then
    REG_FILE="$AIGUARD_REGISTRY_FILE"
    [ -f "$REG_FILE" ]
    return $?
  fi
  [ -n "$RECEIVER_BASE" ] || return 1
  REG_TMP=$(/usr/bin/mktemp /tmp/ai-guard-reg.XXXXXX) || return 1
  REG_FILE="$REG_TMP"
  local code
  code=$(/usr/bin/curl -s -m 15 -o "$REG_FILE" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "${RECEIVER_BASE%/}/registry/collector" 2>/dev/null || echo "000")
  [ "$code" = "200" ]
}

# registry_tsv <file> - flatten the collector registry into lookup rows.
registry_tsv() {
  /usr/bin/osascript -l JavaScript -e '
    function run(argv) {
      try {
        var s = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js;
        var r = JSON.parse(s);
        var U = String.fromCharCode(31);
        var out = [];
        (r.ide || []).forEach(function (t) {
          var e = t.extension_ids || {};
          // Cursor is a VS Code fork and uses the same extension IDs.
          // chrome/edge IDs are browser extensions, not IDE findings.
          (e.vscode || []).forEach(function (x) { out.push(["ide", x, t.tool].join(U)); });
          (e.jetbrains || []).forEach(function (x) { out.push(["jb", x, t.tool].join(U)); });
        });
        (r.desktop || []).forEach(function (t) {
          (t.app_names || []).forEach(function (a) { out.push(["app", a, t.tool].join(U)); });
        });
        (r.cli || []).forEach(function (t) {
          out.push(["cli", t.tool, t.account_json_path || "",
                    (t.account_json_keys || []).join(","),
                    (t.account_jwt_path || []).join(","),
                    t.account_jwt_claim || "",
                    (t.config_paths || []).join(","),
                    (t.binaries || []).join(",")].join(U));
        });
        (r.mcp || []).forEach(function (m) { out.push(["mcp", m.tool, m.path, m.os || "any"].join(U)); });
        return out.join("\n");
      } catch (e) { return ""; }
    }' "$1" 2>/dev/null
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

# report_once <surface> <tool> <account> <evidence>
# One finding per surface+tool per run. A tool can match several identifiers
# (both Copilot extension IDs, an app name AND a binary) and is still one
# finding on this device.
# Evidence labels stand in for the console user's home with a literal ~ so a
# username never appears in a finding. Kept in a variable because a quoted
# "~/..." is a shellcheck warning (SC2088): a tilde does not expand inside
# quotes, which here is intended.
HOME_LABEL='~'

SEEN=""
report_once() {
  local key="$1|$2"
  case "$SEEN" in *"[$key]"*) return 0 ;; esac
  SEEN="${SEEN}[$key]"
  report "$@"
}

# json_get_csv <file> <comma-separated-key-path>
# json_get with the key path supplied as registry data. `set --` inside a
# function only rebinds that function's positional parameters.
json_get_csv() {
  local f="$1" keys="$2" old="$IFS"
  IFS=','
  set -- $keys
  IFS="$old"
  json_get "$f" "$@"
}

# first_existing <base> <comma-separated-paths> - print the first that exists
first_existing() {
  local base="$1" list="$2" old="$IFS" c
  IFS=','
  set -- $list
  IFS="$old"
  for c in "$@"; do
    [ -n "$c" ] || continue
    if [ -e "$base/$c" ]; then printf '%s' "$c"; return 0; fi
  done
  return 1
}

# first_binary <comma-separated-names> - print the first found in brew paths
first_binary() {
  local list="$1" old="$IFS" b
  IFS=','
  set -- $list
  IFS="$old"
  for b in "$@"; do
    [ -n "$b" ] || continue
    if [ -x "/usr/local/bin/$b" ] || [ -x "/opt/homebrew/bin/$b" ]; then
      printf '%s' "$b"; return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------- cli -------

# Tools that store an account identity in a config file. The registry says
# where the file is and how to read it: account_json_keys for a plain field,
# account_jwt_path + account_jwt_claim when the identity is inside a token.
while IFS="$SEP" read -r _kind tool acct_path keys jwt_path jwt_claim cfg_paths _bins; do
  [ -n "$acct_path" ] || continue   # presence-only tools are handled by the desktop scan
  f="$HOME_DIR/$acct_path"
  if [ -f "$f" ]; then
    email=""
    if [ -n "$keys" ]; then
      email=$(json_get_csv "$f" "$keys")
    elif [ -n "$jwt_path" ]; then
      idt=$(json_get_csv "$f" "$jwt_path")
      if [ -n "$idt" ]; then
        p=$(printf '%s' "$idt" | /usr/bin/cut -d. -f2 | /usr/bin/tr '_-' '/+')
        while [ $(( ${#p} % 4 )) -ne 0 ]; do p="${p}="; done
        email=$(printf '%s' "$p" | /usr/bin/base64 -D 2>/dev/null \
          | /usr/bin/grep -oE "\"${jwt_claim}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
          | /usr/bin/head -1 | /usr/bin/cut -d'"' -f4)
      fi
    fi
    report_once "cli" "$tool" "$(domain_of "$email")" "$HOME_LABEL/$acct_path"
  else
    # Installed but never authenticated: still report presence so the tool
    # appears in the inventory, with no account.
    hit=$(first_existing "$HOME_DIR" "$cfg_paths") \
      && report_once "cli" "$tool" "" "$HOME_LABEL/$hit"
  fi
done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^cli${SEP}")

# ---------------------------------------------------------------- ide -------

scan_extensions_dir() {
  local dir="$1" label="$2" d base _kind ext tool
  [ -d "$dir" ] || return 0
  for d in "$dir"/*/; do
    [ -d "$d" ] || continue
    base=$(/usr/bin/basename "$d")
    while IFS="$SEP" read -r _kind ext tool; do
      case "$base" in
        "$ext"-*) report_once "ide" "$tool" "" "$label/$base" ;;
      esac
    done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^ide${SEP}")
  done
}

scan_extensions_dir "$HOME_DIR/.vscode/extensions" "$HOME_LABEL/.vscode/extensions"
scan_extensions_dir "$HOME_DIR/.cursor/extensions" "$HOME_LABEL/.cursor/extensions"

# JetBrains plugin directories are named after the plugin itself.
while IFS="$SEP" read -r _kind ext tool; do
  if /bin/ls -d "$HOME_DIR/Library/Application Support/JetBrains"/*/plugins/"$ext"* >/dev/null 2>&1; then
    report_once "ide" "$tool" "" "JetBrains plugins dir ($ext)"
  fi
done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^jb${SEP}")

# ---------------------------------------------------------------- desktop ---

# Installed applications.
while IFS="$SEP" read -r _kind app tool; do
  if [ -d "/Applications/$app" ] || [ -d "$HOME_DIR/Applications/$app" ]; then
    report_once "desktop" "$tool" "" "$app"
  fi
done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^app${SEP}")

# Local runtimes and editors with no account file: presence via their config
# directory or their binary. Tools WITH an account file are cli-scanned above.
while IFS="$SEP" read -r _kind tool acct_path _keys _jwt _claim cfg_paths bins; do
  [ -n "$acct_path" ] && continue
  hit=$(first_existing "$HOME_DIR" "$cfg_paths") \
    && { report_once "desktop" "$tool" "" "$HOME_LABEL/$hit"; continue; }
  bin=$(first_binary "$bins") \
    && report_once "desktop" "$tool" "" "$bin binary"
done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^cli${SEP}")

# ---------------------------------------------------------------- mcp -------

while IFS="$SEP" read -r _kind tool path os; do
  # Claude Desktop's config path differs per platform; skip the Windows rows.
  case "$os" in any|macos) ;; *) continue ;; esac
  f="$HOME_DIR/$path"
  [ -f "$f" ] || continue
  servers=$(json_keys "$f" mcpServers)
  [ -n "$servers" ] && report_once "mcp" "${tool}-mcp:$servers" "" "$path mcpServers"
done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^mcp${SEP}")

# ---------------------------------------------------------------- summary ---

/bin/mkdir -p "$SUMMARY_DIR"
printf '%s' "$STATE_NEW" > "$STATE_FILE"
POST_STATUS="posted=$POST_OK suppressed=$SUPPRESSED"
[ "$POST_FAILURES" -gt 0 ] && POST_STATUS="POST-FAILED=$POST_FAILURES posted=$POST_OK"
[ -z "$ENDPOINT" ] && POST_STATUS="print-only"
if [ ${#SUMMARY_PARTS[@]} -eq 0 ]; then
  echo "none [$POST_STATUS] ($NOW)" > "$SUMMARY_FILE"
else
  (IFS='; '; echo "${SUMMARY_PARTS[*]} [$POST_STATUS] ($NOW)") > "$SUMMARY_FILE"
fi

if [ "$POST_FAILURES" -gt 0 ]; then
  echo "[ai-guard] $POST_FAILURES finding(s) failed to POST to $ENDPOINT"
  exit 1
fi
exit 0