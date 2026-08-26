#!/bin/sh
# Seeds synthetic shadow-AI findings into the demo receiver so the dashboard
# has something to show. All data is fake: users are Pokemon, domains are
# example / gmail, devices are made up. Safe to re-run.
set -e
R="${RECEIVER:-http://receiver:8080}/report"
T="${TOKEN:-demo-token}"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

post() {
  curl -s -o /dev/null -w '%{http_code} ' \
    -X POST "$R" \
    -H "Authorization: Bearer $T" \
    -H "Content-Type: application/json" \
    --data "$1"
}

echo "seeding demo findings -> $R"

# A spread designed so every dashboard panel lights up: personal (warn) and
# corporate (info) accounts, all three endpoint OSes, plus cloud and network.
# Corporate domain in this demo is "example.com"; the dashboard's corporate
# domains variable already defaults to it, so the colouring needs no setup.

# --- personal accounts (these are the red ones) ---
post "{\"tool\":\"claude-code\",\"surface\":\"cli\",\"os\":\"macos\",\"account_domain\":\"gmail.com\",\"device\":\"C02PIKACHU\",\"user\":\"pikachu\",\"evidence\":\"~/.claude.json\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"codex-cli\",\"surface\":\"cli\",\"os\":\"linux\",\"account_domain\":\"gmail.com\",\"device\":\"NIX-BULBA\",\"user\":\"bulbasaur\",\"evidence\":\"~/.codex/auth.json\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\"}"
post "{\"tool\":\"chatgpt\",\"surface\":\"browser\",\"os\":\"windows\",\"account_domain\":\"outlook.com\",\"device\":\"WIN-CHARM\",\"user\":\"charmander\",\"evidence\":\"chatgpt.com\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"collector-windows\"}"
post "{\"tool\":\"fireflies\",\"surface\":\"cloud\",\"os\":\"unknown\",\"account_domain\":\"gmail.com\",\"device\":\"\",\"user\":\"squirtle\",\"evidence\":\"interactive sign-in to Fireflies\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"entra_sign_in\"}"

# --- corporate accounts (informational, the green ones) ---
post "{\"tool\":\"claude-code\",\"surface\":\"cli\",\"os\":\"macos\",\"account_domain\":\"example.com\",\"device\":\"C02EEVEE\",\"user\":\"eevee\",\"evidence\":\"~/.claude.json\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"github-copilot\",\"surface\":\"ide\",\"os\":\"windows\",\"account_domain\":\"\",\"device\":\"WIN-SNORLAX\",\"user\":\"snorlax\",\"evidence\":\".vscode/extensions/github.copilot\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-windows\"}"
post "{\"tool\":\"claude\",\"surface\":\"desktop\",\"os\":\"linux\",\"account_domain\":\"example.com\",\"device\":\"NIX-MEW\",\"user\":\"mew\",\"evidence\":\"~/.config/Claude\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\"}"

post "{\"tool\":\"fireflies\",\"surface\":\"cloud\",\"os\":\"unknown\",\"account_domain\":\"example.com\",\"device\":\"\",\"user\":\"psyduck\",\"evidence\":\"interactive sign-in to Fireflies\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"entra_sign_in\"}"
post "{\"tool\":\"chatgpt\",\"surface\":\"cloud\",\"os\":\"unknown\",\"account_domain\":\"example.com\",\"device\":\"\",\"user\":\"eevee\",\"evidence\":\"interactive sign-in to ChatGPT\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"entra_sign_in\"}"

# --- presence only, no account readable ---
post "{\"tool\":\"cursor\",\"surface\":\"desktop\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02GENGAR\",\"user\":\"gengar\",\"evidence\":\"~/.cursor\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"ollama\",\"surface\":\"desktop\",\"os\":\"linux\",\"account_domain\":\"\",\"device\":\"NIX-DITTO\",\"user\":\"ditto\",\"evidence\":\"ollama binary\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\"}"

# --- mcp + network ---
post "{\"tool\":\"claude-code-mcp:atlassian,figma\",\"surface\":\"mcp\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02PIKACHU\",\"user\":\"pikachu\",\"evidence\":\".claude.json mcpServers\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"deepseek\",\"surface\":\"network\",\"os\":\"unknown\",\"account_domain\":\"\",\"device\":\"NIX-BULBA\",\"device_name\":\"BULBASAUR-NIX\",\"user\":\"bulbasaur\",\"evidence\":\"dns:deepseek.com\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"sentinelone_bridge\"}"

# --- paste guard (browser extension events + one heartbeat) ---
post "{\"tool\":\"chatgpt.com\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"warn\",\"evidence\":\"paste warned: aws_access_key\",\"device\":\"PIKACHU-MBP\",\"os\":\"macos\",\"reported_at\":\"$(now)\"}"
post "{\"tool\":\"claude.ai\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"warn\",\"evidence\":\"paste overridden: classification_marking\",\"device\":\"EEVEE-WIN\",\"os\":\"windows\",\"reported_at\":\"$(now)\"}"
post "{\"tool\":\"paste-guard\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"info\",\"evidence\":\"heartbeat version=1.1.1 mode=warn reason=demo\",\"device\":\"PIKACHU-MBP\",\"os\":\"macos\",\"reported_at\":\"$(now)\"}"

echo ""
echo "done. open http://localhost:3000 and view the Shadow AI dashboard."