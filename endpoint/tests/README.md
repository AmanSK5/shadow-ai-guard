# Collector delivery-state tests

The endpoint collectors (macOS, Linux, Windows) throttle informational
findings so they report at most once per 24 hours. The throttle state
advances only after confirmed delivery to the receiver.

These collectors are full system scripts (they resolve hardware serials,
console users, and fetch the registry over HTTP) and are not structured
for unit-test sourcing. Verification is manual.

## Expected behaviour

| Scenario | State outcome |
|---|---|
| HTTP 2xx, info finding | Key written with current timestamp |
| HTTP non-2xx, info finding (no prior state) | Key omitted |
| HTTP non-2xx, info finding (expired prior state) | Old timestamp preserved |
| Transport failure, info finding | Same as non-2xx |
| Print-only mode, info finding | Old timestamp preserved (or omitted if none) |
| Warn finding, any outcome | Key may be written, but warns skip the throttle check so it has no effect |
| Suppressed info finding (within 24h) | Old timestamp carried forward, no request made |
| Unrelated state entries | Preserved regardless of this finding's outcome |

## Manual verification

### Fake receiver

Start a receiver that returns a configurable status code:

```bash
# Returns 200 on POST /report, 200 with a minimal registry on GET:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{\"ok\":true}')
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{\"version\":1,\"cli\":[{\"tool\":\"claude-code\",\"config_paths\":[\".claude.json\"],\"account_json_path\":\".claude.json\",\"account_json_keys\":[\"oauthAccount\"],\"binaries\":[\"claude\"]}],\"ide\":[],\"desktop\":[],\"mcp\":[]}')
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
# Make sure the logged-in user's home has a detectable AI tool config:
echo '{"oauthAccount":"tester@example.com"}' > ~/.claude.json

# Against the fake receiver (HTTP 200):
sudo AIGUARD_RECEIVER_BASE=http://127.0.0.1:9999 \
     AIGUARD_TOKEN=test \
     AIGUARD_CORP_DOMAINS=example.com \
     ./endpoint/linux/ai-guard-collector.sh

# Check state:
cat /var/lib/ai-guard/reported.state
# Should contain the finding key with a current epoch timestamp.

# Now restart the fake receiver returning 500, and run again:
cat /var/lib/ai-guard/reported.state
# The timestamp should NOT have advanced.

# Print-only mode (no AIGUARD_RECEIVER_BASE):
sudo AIGUARD_CORP_DOMAINS=example.com \
     ./endpoint/linux/ai-guard-collector.sh
cat /var/lib/ai-guard/reported.state
# Timestamps should not advance.
```

### macOS

Same approach using Jamf script parameters:

```bash
sudo ./endpoint/macos/ai-guard-collector.sh \
     "" "" "" \
     "http://127.0.0.1:9999" "test" "example.com"
cat "/Library/Application Support/ai-guard/reported.state"
```

### Windows

Start a listener in PowerShell, then run the collector:

```powershell
# Fake receiver (returns 200):
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:9999/")
$listener.Start()
while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $ctx.Response.StatusCode = 200
    $ctx.Response.Close()
}

# In another shell, run the collector (edit $ReceiverBase first):
.\endpoint\windows\ai-guard-collector.ps1
Get-Content C:\ProgramData\ai-guard\reported.state.json
```
