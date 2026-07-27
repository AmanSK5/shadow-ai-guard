# Collector delivery-state tests

The endpoint collectors (macOS, Linux, Windows) throttle informational
findings so they report at most once per 24 hours. The throttle state
advances only after confirmed delivery to the receiver.

These collectors are full system scripts (they resolve hardware serials,
console users, and fetch the registry over HTTP) and are not structured
for unit-test sourcing. Rather than restructure code that runs as root on
every managed machine purely to make it testable, the Linux collector is
driven end to end against a fake receiver.

## Automated: Linux

`test_linux_collector.sh` covers the whole table below for Linux. It runs
the real script, so it exercises curl and the actual delivery path. CI runs
it on every push and it gates image publishing.

```bash
docker run --rm -v "$PWD:/w" -w /w python:3.12-slim sh -c \
  "apt-get update -qq && apt-get install -yqq curl >/dev/null && \
   endpoint/tests/test_linux_collector.sh"
```

It must run as root with a clean `/home`, hence the container: the collector
resolves the console user from the first non-root home it finds, and if some
other home sorts ahead of the test user's, no findings are produced and every
assertion about state passes because nothing happened. The script checks for
that and refuses to run rather than pass vacuously.

Two of the tests supply the registry from disk via `AIGUARD_REGISTRY_FILE`.
Without it, pointing the collector at a dead port or omitting the receiver
base fails the registry fetch first, so `report()` is never reached and the
test passes without testing anything. Both were written that way initially
and only caught by deliberately breaking the collector to check the tests
noticed.

macOS and Windows follow the same shape but need their own runners; the
manual procedure below still applies to them.

## Expected behaviour

| Scenario | State outcome |
|---|---|
| HTTP 200, info finding (macOS) | Key written with current timestamp |
| HTTP 200 or 204, info finding (Linux) | Key written with current timestamp |
| Successful response, info finding (Windows) | Key written with current timestamp (Invoke-RestMethod completes without throwing) |
| HTTP non-2xx, info finding (no prior state) | Key omitted |
| HTTP non-2xx, info finding (expired prior state) | Old timestamp preserved |
| Transport failure, info finding | Same as non-2xx |
| Print-only mode, info finding | Old timestamp preserved (or omitted if none) |
| Warn finding, any outcome | Key may be written, but warns skip the throttle check so it has no effect |
| Suppressed info finding (within 24h) | Old timestamp carried forward, no request made |
| Unrelated state entries | Outside the scope of this test. Collectors rebuild state from the current scan, so entries for tools not detected during the run may not be carried forward. |

## Manual verification

### Fake receiver

Start a receiver that returns a configurable status code:

```bash
# Returns 200 on POST /report, 200 with a minimal registry on GET:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        print(f'POST {self.path}')
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{\"ok\":true}')
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{\"version\":1,\"cli\":[{\"tool\":\"claude-code\",\"config_paths\":[\".claude-aiguard-test.json\"],\"account_json_path\":\".claude-aiguard-test.json\",\"account_json_keys\":[\"oauthAccount\"],\"binaries\":[\"claude\"]}],\"ide\":[],\"desktop\":[],\"mcp\":[]}')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 9999), H).serve_forever()
" &
FAKE_PID=$!
```

Change `self.send_response(200)` in `do_POST` to `500` to test failure.

### Linux

Run on a real machine with a real user home (the collector resolves the
logged-in user from `/home`, so it needs an actual non-root home directory).

```bash
# Create a test-only config file (does not touch ~/.claude.json):
printf '%s\n' '{"oauthAccount":"tester@example.com"}' \
  > "$HOME/.claude-aiguard-test.json"

# Against the fake receiver (HTTP 200):
sudo AIGUARD_RECEIVER_BASE=http://127.0.0.1:9999 \
     AIGUARD_TOKEN=test \
     AIGUARD_CORP_DOMAINS=example.com \
     ./endpoint/linux/ai-guard-collector.sh

# Check state:
cat /var/lib/ai-guard/reported.state
# Should contain the finding key with a current epoch timestamp, e.g.:
#   cli|claude-code|example.com 1753100000

# To test failed delivery, the finding must be eligible for reporting.
# The successful run above created a fresh 24h throttle timestamp, so
# you need to expire it first. Check the actual key in your state file
# (it may differ from the example if your username or tool differs),
# then replace its timestamp with an expired value:
sudo sed -i 's/\(cli|claude-code|example.com\) .*/\1 1000000000/' \
    /var/lib/ai-guard/reported.state

# Now restart the fake receiver returning 500 and run again:
sudo AIGUARD_RECEIVER_BASE=http://127.0.0.1:9999 \
     AIGUARD_TOKEN=test \
     AIGUARD_CORP_DOMAINS=example.com \
     ./endpoint/linux/ai-guard-collector.sh

# Confirm the receiver received the POST attempt (check the fake
# receiver's terminal for the request). Then check state:
cat /var/lib/ai-guard/reported.state
# The finding's timestamp should still be the expired value (1000000000),
# NOT the current time. This means it will retry on the next run.

# Print-only mode (no AIGUARD_RECEIVER_BASE):
sudo AIGUARD_CORP_DOMAINS=example.com \
     ./endpoint/linux/ai-guard-collector.sh
cat /var/lib/ai-guard/reported.state
# Timestamps should not advance.

# Clean up the test fixture:
rm -f "$HOME/.claude-aiguard-test.json"
```

### macOS

```bash
# Create a test-only config file (does not touch ~/.claude.json):
printf '%s\n' '{"oauthAccount":"tester@example.com"}' \
  > "$HOME/.claude-aiguard-test.json"

# Successful delivery (HTTP 200):
sudo ./endpoint/macos/ai-guard-collector.sh \
     "" "" "" \
     "http://127.0.0.1:9999" "test" "example.com"
cat "/Library/Application Support/ai-guard/reported.state"
# Should contain the finding key with a current epoch timestamp.

# To test failed delivery, expire the finding's throttle timestamp
# so the collector will attempt to report it again. Check the actual
# key in your state file (it may differ from the example below if
# your username or tool differs), then replace its timestamp:
sudo sed -i '' 's/\(cli|claude-code|example.com\) .*/\1 1000000000/' \
    "/Library/Application Support/ai-guard/reported.state"

# Restart the fake receiver returning 500, then run again:
sudo ./endpoint/macos/ai-guard-collector.sh \
     "" "" "" \
     "http://127.0.0.1:9999" "test" "example.com"

# Confirm the receiver received the POST attempt, then check state:
cat "/Library/Application Support/ai-guard/reported.state"
# The timestamp should still be the expired value, not the current time.

# Clean up the test fixture:
rm -f "$HOME/.claude-aiguard-test.json"
```

### Windows

Start a listener in PowerShell that serves the registry on GET and
accepts findings on POST:

```powershell
# Fake receiver: returns registry JSON on GET /registry/collector,
# returns 200 on POST /report. Change $PostStatus to 500 to test failure.
$PostStatus = 200
$RegistryJson = '{"version":1,"cli":[{"tool":"claude-code","config_paths":[".claude-aiguard-test.json"],"account_json_path":".claude-aiguard-test.json","account_json_keys":["oauthAccount"],"binaries":["claude"]}],"ide":[],"desktop":[],"mcp":[]}'

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:9999/")
$listener.Start()
Write-Host "Listening on http://localhost:9999/ (POST status: $PostStatus)"
while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    if ($ctx.Request.HttpMethod -eq 'GET') {
        $body = [Text.Encoding]::UTF8.GetBytes($RegistryJson)
        $ctx.Response.StatusCode = 200
        $ctx.Response.ContentType = 'application/json'
        $ctx.Response.ContentLength64 = $body.Length
        $ctx.Response.OutputStream.Write($body, 0, $body.Length)
    } else {
        Write-Host "POST $($ctx.Request.Url.AbsolutePath) -> $PostStatus"
        $ctx.Response.StatusCode = $PostStatus
    }
    $ctx.Response.Close()
}
```

In another shell, create the fixture, edit `$ReceiverBase` in the
collector to `http://localhost:9999`, then run:

```powershell
# Create a test-only config file (does not touch ~/.claude.json):
'{"oauthAccount":"tester@example.com"}' | Set-Content "$env:USERPROFILE\.claude-aiguard-test.json"

.\endpoint\windows\ai-guard-collector.ps1
Get-Content C:\ProgramData\ai-guard\reported.state.json
# Should contain the finding key with a current epoch timestamp.

# To test failed delivery, expire the finding's throttle timestamp.
# Check the actual key in the state file (it may differ from the
# example if your username or tool differs), then set it to an
# expired value:
$state = Get-Content C:\ProgramData\ai-guard\reported.state.json -Raw | ConvertFrom-Json
$state.'cli|claude-code|example.com' = 1000000000
$state | ConvertTo-Json | Set-Content C:\ProgramData\ai-guard\reported.state.json

# Restart the fake receiver with $PostStatus = 500, then run again:
.\endpoint\windows\ai-guard-collector.ps1

# Confirm the receiver received the POST attempt, then check state:
Get-Content C:\ProgramData\ai-guard\reported.state.json
# The timestamp should still be 1000000000, not the current time.

# Clean up the test fixture:
Remove-Item "$env:USERPROFILE\.claude-aiguard-test.json" -ErrorAction SilentlyContinue
```