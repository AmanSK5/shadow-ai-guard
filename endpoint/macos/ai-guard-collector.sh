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
#                 personal account and escalates severity. A receiver that
#                 serves config.corp_domains in /registry/collector overrides
#                 this at runtime; the parameter is the fallback.
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

# Report throttling. The policy runs at every recurring check-in (~20 min).
# Unchanged inventory (info) findings only need reporting once a day; warn
# findings (personal accounts) report hourly, since a personal account is a
# persistent state rather than an event and the first report already said it.
# STATE_FILE holds one line per already-reported finding: "<key> <epoch>".
# A finding not yet in the state file (new tool, new account) reports
# immediately at any severity, so a fresh install or an account switch
# surfaces within one check-in.
STATE_FILE="$SUMMARY_DIR/reported.state"
INFO_REPORT_INTERVAL=$(( 24 * 3600 ))
WARN_REPORT_INTERVAL=$(( 3600 ))
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

# The home directory with every symlink already resolved, so the containment
# check below compares like with like. Doing it once here rather than per path
# keeps it to one subshell for the whole run.
HOME_REAL=$(cd "$HOME_DIR" 2>/dev/null && pwd -P) || HOME_REAL="$HOME_DIR"

SERIAL=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | /usr/bin/awk -F'"' '/IOPlatformSerialNumber/{print $4}')

# device carries the serial: immutable, and what Jamf, Intune, SentinelOne and
# most RMMs key on. device_name carries the hostname, which is what a human
# recognises and what platforms that have no serial can still join on. The
# dashboard prefers device_name and falls back to device, so a collector that
# sends only the serial shows a serial where the scanners show a name.
DEVICE_NAME=$(/usr/sbin/scutil --get ComputerName 2>/dev/null || /bin/hostname -s 2>/dev/null || echo "")

# Said out loud, because an empty serial changes what every finding from this
# machine is keyed on. Silence here would look identical to a machine with no
# AI tools on it.
if [ -z "$SERIAL" ]; then
  echo "[ai-guard] serial lookup failed via ioreg, falling back to hostname for device"
  SERIAL="$DEVICE_NAME"
fi

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

# report <surface> <tool> <account_domain> <evidence>
report() {
  local surface="$1" tool="$2" acct="$3" evidence="$4" severity="info"
  if [ -n "$acct" ]; then
    case ",${CORP_DOMAINS}," in
      *",${acct},"*) ;;          # corporate (any alias) -> info
      *) severity="warn" ;;      # anything else -> personal account
    esac
  fi

  # Report throttling. The policy runs at every recurring check-in (~20 min).
  # Unchanged inventory (info) findings only need reporting once a day; warn
  # findings (personal accounts) report hourly, since a personal account is a
  # persistent state rather than an event and the first report already told us.
  # Throttle by severity: info daily, warn hourly. A key with no previous
  # timestamp falls through regardless, so new findings are never delayed.
  local key="${surface}|${tool}|${acct}"
  local interval="$INFO_REPORT_INTERVAL"
  [ "$severity" = "warn" ] && interval="$WARN_REPORT_INTERVAL"

  local last
  last=$(state_lookup "$key")
  if [ -n "$last" ] && [ $(( NOW_EPOCH - last )) -lt "$interval" ]; then
    STATE_NEW="${STATE_NEW}${key} ${last}
"
    SUPPRESSED=$((SUPPRESSED + 1))
    if [ -n "$acct" ]; then SUMMARY_PARTS+=("$tool($acct)"); else SUMMARY_PARTS+=("$tool"); fi
    return 0
  fi

  # severity and reported_at are generated here, so they need no escaping.
  # Everything else came from the registry, the machine or a config file.
  local payload
  payload=$(/usr/bin/printf '{"tool":"%s","surface":"%s","os":"macos","account_domain":"%s","device":"%s","device_name":"%s","user":"%s","evidence":"%s","severity":"%s","reported_at":"%s","source":"collector-macos"}' \
    "$(json_escape "$tool")" "$(json_escape "$surface")" "$(json_escape "$acct")" \
    "$(json_escape "$SERIAL")" "$(json_escape "$DEVICE_NAME")" \
    "$(json_escape "$CONSOLE_USER")" "$(json_escape "$evidence")" \
    "$severity" "$NOW")

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
          (e.vscode || []).forEach(function (x) { out.push(["ide", x, t.tool].join(U)); });
          (e.jetbrains || []).forEach(function (x) { out.push(["jb", x, t.tool].join(U)); });
          // chrome/edge IDs are browser extensions: matched against installed
          // extension folders in Chrome-family browser profiles below.
          (e.chrome || []).forEach(function (x) { out.push(["bext", "chrome", x, t.tool].join(U)); });
          (e.edge || []).forEach(function (x) { out.push(["bext", "edge", x, t.tool].join(U)); });
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
  # Distinguish "no receiver configured" from "the receiver did not answer".
  # Both used to print the same line, which reads as a network problem when it
  # is a missing parameter - and prints a URL with no host in front of it,
  # which is the giveaway nobody notices. This script takes its configuration
  # as positional parameters because Jamf passes script parameters, not
  # environment variables; running it by hand needs the same shape.
  if [ -z "$RECEIVER_BASE" ]; then
    echo "[ai-guard] no receiver configured. This script reads its settings as"
    echo "[ai-guard] positional parameters, because that is how Jamf passes"
    echo "[ai-guard] them. Environment variables are ignored."
    echo "[ai-guard]"
    echo "[ai-guard]   Jamf: set parameters 4, 5 and 6 on the policy."
    echo "[ai-guard]   By hand: \$1-\$3 are Jamf's own, so pass three empty"
    echo "[ai-guard]   strings first:"
    echo "[ai-guard]"
    echo "[ai-guard]     sudo ./ai-guard-collector.sh \"\" \"\" \"\" \\"
    echo "[ai-guard]       https://receiver.example.com <token> example.com"
    echo "[ai-guard]"
    echo "[ai-guard] Refusing to scan: an empty scan looks like a clean machine."
    exit 1
  fi
  echo "[ai-guard] registry fetch failed: ${RECEIVER_BASE%/}/registry/collector"
  echo "[ai-guard] refusing to scan without an identifier list - an empty scan looks like a clean machine"
  exit 1
fi
REG_TSV=$(registry_tsv "$REG_FILE")
if [ -z "$REG_TSV" ]; then
  echo "[ai-guard] registry parse failed: $REG_FILE"
  exit 1
fi

# Corporate domains can arrive with the registry: the receiver serves
# config.corp_domains in the payload just fetched when it has CORP_DOMAINS
# set. The served list wins over parameter 6, because a list changed once on
# the receiver reaches the fleet on its next check-in rather than waiting on
# an MDM re-paste per platform; the parameter stays as the fallback, so a
# receiver serving nothing changes nothing. json_get stringifies the array
# comma-joined, which is the exact shape the severity check in report()
# matches against - the receiver serves it trimmed and lowercased for the
# same reason.
CENTRAL_DOMAINS=$(json_get "$REG_FILE" config corp_domains)
if [ -n "$CENTRAL_DOMAINS" ]; then
  echo "[ai-guard] corporate domains from receiver: $CENTRAL_DOMAINS"
  CORP_DOMAINS="$CENTRAL_DOMAINS"
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

# first_existing <base> <comma-separated-paths> - print the first that exists
first_existing() {
  local base="$1" list="$2" old="$IFS" c
  IFS=','
  set -- $list
  IFS="$old"
  for c in "$@"; do
    [ -n "$c" ] || continue
    safe_rel_path "$c" || continue
    resolve_under_home "$base/$c" >/dev/null 2>&1 || continue
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
  if ! safe_rel_path "$acct_path"; then
    echo "[ai-guard] refusing registry path for $tool: not relative to home" >&2
    continue
  fi
  f=$(resolve_under_home "$HOME_DIR/$acct_path") || f=""
  if [ -n "$f" ] && [ -f "$f" ]; then
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

# ------------------------------------------------------- browser extensions --

# Installed browser extensions, matched by extension id against the
# registry. Presence is the finding: an AI extension reads pages without
# anything being pasted. Chrome and Brave install from the Chrome store, so
# both match chrome ids; Edge installs from both stores, so it matches both
# sets. Folder presence in a profile's Extensions dir is the signal;
# evidence names the browser and profile, never the user's home path.
scan_browser_extensions() {
  local root="$1" label="$2" idkinds="$3" profile pdir extdir bkind ext tool
  [ -d "$root" ] || return 0
  for pdir in "$root/Default" "$root"/Profile\ *; do
    [ -d "$pdir/Extensions" ] || continue
    profile=$(/usr/bin/basename "$pdir")
    for extdir in "$pdir/Extensions"/*/; do
      [ -d "$extdir" ] || continue
      ext=$(/usr/bin/basename "$extdir")
      while IFS="$SEP" read -r _kind bkind id tool; do
        case ",$idkinds," in *",$bkind,"*) ;; *) continue ;; esac
        [ "$ext" = "$id" ] && report_once "browser" "$tool" "" "$label/$profile extension $id"
      done < <(printf '%s\n' "$REG_TSV" | /usr/bin/grep "^bext${SEP}")
    done
  done
}

APPSUP="$HOME_DIR/Library/Application Support"
scan_browser_extensions "$APPSUP/Google/Chrome"                "Chrome" "chrome"
scan_browser_extensions "$APPSUP/BraveSoftware/Brave-Browser"  "Brave"  "chrome"
scan_browser_extensions "$APPSUP/Microsoft Edge"               "Edge"   "chrome,edge"

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