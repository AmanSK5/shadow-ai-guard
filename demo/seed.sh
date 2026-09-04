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
post "{\"tool\":\"codex-cli\",\"surface\":\"cloud\",\"os\":\"unknown\",\"account_domain\":\"example.com\",\"device\":\"\",\"user\":\"snorlax\",\"evidence\":\"interactive sign-in to Codex\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"entra_sign_in\"}"

# --- presence only, no account readable ---
post "{\"tool\":\"cursor\",\"surface\":\"desktop\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02GENGAR\",\"user\":\"gengar\",\"evidence\":\"~/.cursor\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"ollama\",\"surface\":\"desktop\",\"os\":\"linux\",\"account_domain\":\"\",\"device\":\"NIX-DITTO\",\"user\":\"ditto\",\"evidence\":\"ollama binary\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\"}"

# --- what runs without a person ---
# The Agentic AI view. Four shapes, because the page is only worth having if
# it can tell them apart: a timer under a key nobody owns, a machine with no
# owner on record, a scheduled job that IS properly attributed, and the one
# with nothing installed to find - a process that is not a browser and not a
# tool the registry knows, reaching a model API.
post "{\"tool\":\"claude-code\",\"surface\":\"cli\",\"os\":\"linux\",\"account_domain\":\"\",\"device\":\"NIX-BULBA\",\"user\":\"bulbasaur\",\"evidence\":\"/etc/systemd/system/nightly-triage.service\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\",\"mode\":\"autonomous\",\"identity\":\"machine\",\"trigger\":\"systemd timer, every 15 min\",\"schedule\":\"oncalendar:*:0/15\"}"
post "{\"tool\":\"claude-code\",\"surface\":\"cli\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02EEVEE\",\"user\":\"\",\"evidence\":\"~/Library/LaunchAgents/ai.helper.plist\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\",\"mode\":\"autonomous\",\"identity\":\"machine\",\"trigger\":\"launchd, at login\",\"schedule\":\"atlogin\"}"
post "{\"tool\":\"claude-code\",\"surface\":\"cli\",\"os\":\"macos\",\"account_domain\":\"example.com\",\"device\":\"C02PIKACHU\",\"user\":\"pikachu\",\"evidence\":\"~/Library/LaunchAgents/daily-notes.plist\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\",\"mode\":\"autonomous\",\"identity\":\"person\",\"trigger\":\"launchd, every 6 hours\",\"schedule\":\"interval:21600\"}"
# No config file, no known binary, no MCP. Only the network saw it.
post "{\"tool\":\"claude\",\"surface\":\"network\",\"os\":\"linux\",\"account_domain\":\"\",\"device\":\"NIX-GENGAR\",\"user\":\"\",\"evidence\":\"DNS lookup for api.anthropic.com (via python3)\",\"severity\":\"warn\",\"reported_at\":\"$(now)\",\"source\":\"sentinelone_dns\",\"trigger\":\"cron, 0 2 * * *\",\"schedule\":\"cron:0 2 * * *\"}"
# A browser reaching the same place is the ordinary case and must NOT appear.
post "{\"tool\":\"claude\",\"surface\":\"network\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02MEW\",\"user\":\"mew\",\"evidence\":\"DNS lookup for claude.ai (via Google Chrome)\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"sentinelone_dns\"}"
# Reach for the unattended linux box, so its chain has something in the last box.
post "{\"tool\":\"claude-code-mcp\",\"surface\":\"mcp\",\"os\":\"linux\",\"account_domain\":\"\",\"device\":\"NIX-BULBA\",\"user\":\"bulbasaur\",\"evidence\":\".claude.json mcpServers: github,postgres-prod\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-linux\"}"

# --- mcp + network ---
post "{\"tool\":\"claude-code-mcp:atlassian,figma\",\"surface\":\"mcp\",\"os\":\"macos\",\"account_domain\":\"\",\"device\":\"C02PIKACHU\",\"user\":\"pikachu\",\"evidence\":\".claude.json mcpServers\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"collector-macos\"}"
post "{\"tool\":\"deepseek\",\"surface\":\"network\",\"os\":\"unknown\",\"account_domain\":\"\",\"device\":\"NIX-BULBA\",\"device_name\":\"BULBASAUR-NIX\",\"user\":\"bulbasaur\",\"evidence\":\"dns:deepseek.com\",\"severity\":\"info\",\"reported_at\":\"$(now)\",\"source\":\"sentinelone_bridge\"}"

# --- paste guard (browser extension events + one heartbeat) ---
post "{\"tool\":\"chatgpt.com\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"warn\",\"evidence\":\"paste warned: aws_access_key\",\"device\":\"PIKACHU-MBP\",\"os\":\"macos\",\"reported_at\":\"$(now)\"}"
post "{\"tool\":\"claude.ai\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"warn\",\"evidence\":\"paste overridden: classification_marking\",\"device\":\"EEVEE-WIN\",\"os\":\"windows\",\"reported_at\":\"$(now)\"}"
post "{\"tool\":\"paste-guard\",\"surface\":\"browser\",\"source\":\"paste_guard\",\"severity\":\"info\",\"evidence\":\"heartbeat version=1.1.1 mode=warn reason=demo\",\"device\":\"PIKACHU-MBP\",\"os\":\"macos\",\"reported_at\":\"$(now)\"}"

echo ""
echo "done. open http://localhost:3000 and view the Shadow AI dashboard."
# --- the estate itself ---------------------------------------------------
# A real deployment's operator does this by hand: read the setup code from
# the receiver's log, create the owner account, name the estate, walk the
# single sign-on wizard. The demo pins the code (SETUP_CODE on the receiver,
# demo only) so this script can do the same over the same endpoints, and the
# portal opens on a sign-in screen with the Microsoft button already there.
# Safe to re-run: once the owner exists the setup door is closed (409) and
# everything below is skipped.
A="${RECEIVER:-http://receiver:8080}"
if [ -n "${SETUP_CODE:-}" ]; then
  echo "creating the owner account and switching single sign-on on"
  sess=$(curl -s -X POST "$A/admin/setup" -H 'Content-Type: application/json' \
    --data "{\"setup_code\":\"$SETUP_CODE\",\"username\":\"${OWNER_USER:-gengar}\",\"password\":\"${OWNER_PASSWORD:-gengar-demo-portal}\"}")
  tok=$(printf '%s' "$sess" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
  if [ -z "$tok" ]; then
    echo "  skipped: $sess"
  else
    auth="Authorization: Bearer $tok"
    users=$(curl -s "$A/admin/users" -H "$auth")
    uid=$(printf '%s' "$users" | tr '{' '\n' | grep "\"username\": *\"${OWNER_USER:-gengar}\"" \
      | sed -n 's/.*"id": *"\([0-9a-f]\{16\}\)".*/\1/p' | head -n 1)
    printf '  sign-on address: '
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "$A/admin/users/$uid/email" -H "$auth" \
      -H 'Content-Type: application/json' --data "{\"email\":\"${OWNER_EMAIL:-gengar@example.com}\"}"
    printf '  estate name and single sign-on: '
    curl -s -o /dev/null -w '%{http_code}\n' -X PUT "$A/admin/settings" -H "$auth" \
      -H 'Content-Type: application/json' --data "{\"org_name\":\"${ORG_NAME:-Pallet Town Ltd}\",\"sso_tenant_id\":\"11111111-2222-3333-4444-555555555555\",\"sso_client_id\":\"66666666-7777-8888-9999-000000000000\",\"sso_client_secret\":\"demo-client-secret\",\"sso_redirect_uri\":\"${PORTAL_URL:-http://localhost:8091}/sso/callback\",\"sso_enabled\":\"1\"}"
  fi
fi
