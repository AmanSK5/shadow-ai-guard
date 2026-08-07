#!/usr/bin/env bash
# Delivery-state tests for the Linux collector.
#
# What this covers: the throttle state machine in report(). Informational
# findings report at most once per 24h and warns at most once per hour, and
# the throttle timestamp advances only after confirmed delivery. Get that
# wrong in the direction of advancing too eagerly and a finding that never
# reached the receiver is never retried, which is a silent gap in a tool whose
# whole job is not having silent gaps.
#
# The warn interval exists because a personal account is a persistent state,
# not an event: before it, one such finding reported at every check-in and
# outweighed everything else in the platform's counts. The property that
# makes the throttle safe is that a key with no prior timestamp falls through
# at any severity, so a new tool or an account switch is never delayed. That
# is asserted below rather than assumed.
#
# Why end-to-end rather than sourcing the functions: the collector is a system
# script that resolves hardware serials, console users and fetches the registry
# over HTTP. Restructuring it for unit-test sourcing would mean editing code
# that runs as root on every managed machine purely to make it testable.
# Driving the real script from outside costs a container and tests the delivery
# path as it actually runs, curl included.
#
# Must run as root in a disposable container: writes /var/lib/ai-guard and
# creates a home directory under /home.
#
#   docker run --rm -v "$PWD:/w" -w /w python:3.12-slim sh -c \
#     "apt-get update -qq && apt-get install -yqq curl >/dev/null && \
#      endpoint/tests/test_linux_collector.sh"

set -u

COLLECTOR="${COLLECTOR:-endpoint/linux/ai-guard-collector.sh}"
STATE_FILE="/var/lib/ai-guard/reported.state"
PORT="${PORT:-9099}"
BASE="http://127.0.0.1:$PORT"
TEST_USER="aiguardtest"
TEST_HOME="/home/$TEST_USER"
FIXTURE="$TEST_HOME/.claude-aiguard-test.json"
RECEIVER_LOG=$(mktemp)
RECEIVER_PID=""
# A local copy of what the fake receiver serves. Needed by the transport
# failure test: pointing the collector at a dead port would otherwise fail
# the registry fetch first, so report() would never run and the test would
# pass without exercising anything.
REG_FILE=$(mktemp)

PASS=0
FAIL=0

# ------------------------------------------------------------------ setup --

fail() { printf '  FAIL: %s\n' "$1"; FAIL=$((FAIL + 1)); }
pass() { printf '  ok:   %s\n' "$1"; PASS=$((PASS + 1)); }

require_root() {
  [ "$(id -u)" = "0" ] || { echo "must run as root"; exit 2; }
}

# The collector resolves the console user from the first non-root-owned
# directory under /home, so the test needs a real one.
setup_home() {
  id "$TEST_USER" >/dev/null 2>&1 || useradd -m -d "$TEST_HOME" "$TEST_USER" 2>/dev/null || {
    mkdir -p "$TEST_HOME"
    chown 1234:1234 "$TEST_HOME"
  }
  mkdir -p "$TEST_HOME"
  printf '%s\n' '{"oauthAccount":"tester@example.com"}' > "$FIXTURE"
  chown -R "$(stat -c '%u' "$TEST_HOME")" "$TEST_HOME" 2>/dev/null || true
}

# Fake receiver. Serves the collector registry on GET and returns a chosen
# status on POST, logging each one so a test can assert a request was or was
# not attempted.
start_receiver() {
  local status="$1"
  : > "$RECEIVER_LOG"
  python3 - "$PORT" "$status" "$RECEIVER_LOG" <<'PY' &
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

port, status, logpath = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
REGISTRY = (
    b'{"version":1,"cli":[{"tool":"claude-code",'
    b'"config_paths":[".claude-aiguard-test.json"],'
    b'"account_json_path":".claude-aiguard-test.json",'
    b'"account_json_keys":["oauthAccount"],"binaries":["claude"]}],'
    b'"ide":[],"desktop":[],"mcp":[]}'
)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(REGISTRY)))
        self.end_headers()
        self.wfile.write(REGISTRY)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        with open(logpath, "a") as f:
            f.write("POST\n")
        self.send_response(status)
        self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
  RECEIVER_PID=$!
  for _ in $(seq 1 40); do
    curl -sf -m 1 "$BASE/registry/collector" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "fake receiver did not come up"; exit 2
}

stop_receiver() {
  [ -n "$RECEIVER_PID" ] && kill "$RECEIVER_PID" 2>/dev/null
  wait "$RECEIVER_PID" 2>/dev/null
  RECEIVER_PID=""
}

reset_state() { rm -rf /var/lib/ai-guard; }

# run_collector [corp_domains] [receiver_base]
# An empty receiver_base exercises print-only mode.
run_collector() {
  local corp="${1-example.com}" base="${2-$BASE}"
  AIGUARD_RECEIVER_BASE="$base" \
  AIGUARD_TOKEN=test \
  AIGUARD_CORP_DOMAINS="$corp" \
  AIGUARD_REGISTRY_FILE="${AIGUARD_REGISTRY_FILE:-}" \
    bash "$COLLECTOR" >/dev/null 2>&1
  return 0
}

state_ts() { grep -F "$1 " "$STATE_FILE" 2>/dev/null | tail -1 | awk '{print $2}'; }
# awk rather than grep -c: grep exits 1 on no matches, which turns a
# legitimate zero into a shell error under the || fallback.
posts_made() { awk 'END{print NR+0}' "$RECEIVER_LOG" 2>/dev/null; }

KEY="cli|claude-code|example.com"

# ------------------------------------------------------------------ tests --

test_success_writes_current_timestamp() {
  local name="HTTP 200 advances the throttle timestamp"
  reset_state; start_receiver 200
  run_collector
  local ts now
  ts=$(state_ts "$KEY"); now=$(date -u +%s)
  stop_receiver
  if [ -z "$ts" ]; then fail "$name (no state written)"; return; fi
  if [ $((now - ts)) -lt 120 ]; then pass "$name"; else fail "$name (stale: $ts)"; fi
}

test_failure_writes_nothing_when_no_prior_state() {
  local name="HTTP 500 with no prior state leaves the key absent"
  reset_state; start_receiver 500
  run_collector
  local ts; ts=$(state_ts "$KEY")
  local n; n=$(posts_made)
  stop_receiver
  if [ "$n" -lt 1 ]; then fail "$name (no POST attempted)"; return; fi
  if [ -z "$ts" ]; then pass "$name"; else fail "$name (wrote $ts)"; fi
}

test_failure_preserves_expired_timestamp() {
  local name="HTTP 500 preserves an expired timestamp so it retries"
  reset_state; start_receiver 200
  run_collector                       # seed real state
  stop_receiver
  mkdir -p /var/lib/ai-guard
  sed -i "s|^\(${KEY//|/\\|}\) .*|\1 1000000000|" "$STATE_FILE"
  start_receiver 500
  run_collector
  local ts; ts=$(state_ts "$KEY")
  stop_receiver
  if [ "$ts" = "1000000000" ]; then
    pass "$name"
  else
    fail "$name (expected 1000000000, got '${ts:-absent}')"
  fi
}

test_transport_failure_behaves_like_non_2xx() {
  local name="unreachable receiver preserves an expired timestamp"
  reset_state; start_receiver 200
  run_collector
  stop_receiver
  sed -i "s|^\(${KEY//|/\\|}\) .*|\1 1000000000|" "$STATE_FILE"
  # Registry from disk so only the POST fails; otherwise the registry fetch
  # fails first, nothing is scanned, and report() is never reached.
  AIGUARD_REGISTRY_FILE="$REG_FILE" \
    run_collector example.com "http://127.0.0.1:1"   # nothing listening
  local ts; ts=$(state_ts "$KEY")
  if [ "$ts" = "1000000000" ]; then
    pass "$name"
  else
    fail "$name (expected 1000000000, got '${ts:-absent}')"
  fi
}

test_print_only_does_not_advance() {
  local name="print-only mode preserves the old timestamp"
  reset_state; start_receiver 200
  run_collector
  stop_receiver
  sed -i "s|^\(${KEY//|/\\|}\) .*|\1 1000000000|" "$STATE_FILE"
  # Registry from disk: with no receiver base the collector cannot fetch one,
  # so without this nothing is scanned and the test would pass without ever
  # reaching the print-only branch.
  AIGUARD_REGISTRY_FILE="$REG_FILE" \
    run_collector example.com ""      # no endpoint
  local ts; ts=$(state_ts "$KEY")
  if [ "$ts" = "1000000000" ]; then
    pass "$name"
  else
    fail "$name (expected 1000000000, got '${ts:-absent}')"
  fi
}

test_within_window_suppresses_without_posting() {
  local name="a fresh info finding is suppressed and makes no request"
  reset_state; start_receiver 200
  run_collector                       # first run posts
  local first; first=$(state_ts "$KEY")
  stop_receiver
  start_receiver 200                  # clears the POST log
  run_collector                       # second run, still inside 24h
  local n ts; n=$(posts_made); ts=$(state_ts "$KEY")
  stop_receiver
  if [ "$n" -ne 0 ]; then fail "$name (made $n request(s))"; return; fi
  if [ "$ts" = "$first" ]; then pass "$name"; else fail "$name (timestamp moved)"; fi
}

# backdate_state <seconds-ago> - move the key's timestamp into the past so a
# window boundary can be crossed without sleeping through it.
backdate_state() {
  local ago="$1" when
  when=$(( $(date -u +%s) - ago ))
  sed -i "s|^\(${KEY//|/\\|}\) .*|\1 $when|" "$STATE_FILE"
}

test_warn_inside_window_suppresses() {
  local name="a warn inside the hour is suppressed and makes no request"
  reset_state; start_receiver 200
  run_collector notcorp.example        # personal account -> warn, first post
  local first; first=$(state_ts "$KEY")
  stop_receiver
  start_receiver 200                   # clears the POST log
  run_collector notcorp.example        # immediately again
  local n ts; n=$(posts_made); ts=$(state_ts "$KEY")
  stop_receiver
  if [ "$n" -ne 0 ]; then fail "$name (made $n request(s))"; return; fi
  if [ "$ts" = "$first" ]; then pass "$name"; else fail "$name (timestamp moved)"; fi
}

test_warn_outside_window_posts_again() {
  local name="a warn older than an hour posts again"
  reset_state; start_receiver 200
  run_collector notcorp.example        # seed real state
  stop_receiver
  backdate_state 7200                  # two hours ago
  start_receiver 200
  run_collector notcorp.example
  local n; n=$(posts_made)
  stop_receiver
  if [ "$n" -ge 1 ]; then pass "$name"; else fail "$name (still throttled after 2h)"; fi
}

test_warn_with_no_prior_state_posts_immediately() {
  local name="a warn with no prior state posts immediately"
  reset_state; start_receiver 200
  run_collector notcorp.example
  local n; n=$(posts_made)
  stop_receiver
  if [ "$n" -ge 1 ]; then pass "$name"; else fail "$name (suppressed a new key)"; fi
}

test_info_still_throttled_beyond_the_warn_window() {
  # The discriminating test: if both intervals were set to the same value,
  # every other test here would still pass. This one would not.
  local name="an info finding is still suppressed two hours in"
  reset_state; start_receiver 200
  run_collector                        # corporate account -> info
  stop_receiver
  backdate_state 7200                  # past the warn window, inside the info one
  start_receiver 200
  run_collector
  local n; n=$(posts_made)
  stop_receiver
  if [ "$n" -eq 0 ]; then pass "$name"; else fail "$name (made $n request(s))"; fi
}

# ------------------------------------------------------------------- main --

require_root
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }
command -v curl >/dev/null || { echo "curl is required"; exit 2; }

# The collector picks the first non-root-owned directory under /home. If some
# other home sorts ahead of the test user's, the fixture is never found, no
# findings are produced, and every assertion about state passes because
# nothing happened. Fail loudly rather than pass vacuously.
check_home_is_first() {
  local d owner
  for d in /home/*/; do
    [ -d "$d" ] || continue
    owner=$(stat -c '%U' "$d" 2>/dev/null)
    [ -z "$owner" ] && continue
    [ "$owner" = "root" ] && continue
    case "$(basename "$d")" in linuxbrew|lost+found) continue ;; esac
    if [ "${d%/}" != "$TEST_HOME" ]; then
      echo "refusing to run: the collector would resolve ${d%/}, not $TEST_HOME."
      echo "run this in a container with a clean /home."
      exit 2
    fi
    return 0
  done
}

cat > "$REG_FILE" <<'JSON'
{"version":1,"cli":[{"tool":"claude-code",
"config_paths":[".claude-aiguard-test.json"],
"account_json_path":".claude-aiguard-test.json",
"account_json_keys":["oauthAccount"],"binaries":["claude"]}],
"ide":[],"desktop":[],"mcp":[]}
JSON

trap 'stop_receiver; rm -f "$RECEIVER_LOG" "$REG_FILE"' EXIT

setup_home
check_home_is_first
echo "collector delivery-state tests"

test_success_writes_current_timestamp
test_failure_writes_nothing_when_no_prior_state
test_failure_preserves_expired_timestamp
test_transport_failure_behaves_like_non_2xx
test_print_only_does_not_advance
test_within_window_suppresses_without_posting
test_warn_inside_window_suppresses
test_warn_outside_window_posts_again
test_warn_with_no_prior_state_posts_immediately
test_info_still_throttled_beyond_the_warn_window

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]