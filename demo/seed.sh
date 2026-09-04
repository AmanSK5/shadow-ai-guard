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
#
# Safe to re-run. Once the owner exists the setup door is closed, so a re-run
# signs in with the owner's password instead and leaves the estate settings
# alone - somebody who switched single sign-on off to walk the wizard keeps
# it off. The demo data below is re-applied every time.
A="${RECEIVER:-http://receiver:8080}"
U="${OWNER_USER:-gengar}"; PW="${OWNER_PASSWORD:-gengar-demo-portal}"
tok=""
if [ -n "${SETUP_CODE:-}" ]; then
  sess=$(curl -s -X POST "$A/admin/setup" -H 'Content-Type: application/json' \
    --data "{\"setup_code\":\"$SETUP_CODE\",\"username\":\"$U\",\"password\":\"$PW\"}")
  tok=$(printf '%s' "$sess" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
  if [ -n "$tok" ]; then
    echo "created the owner account; naming the estate and switching single sign-on on"
    auth="Authorization: Bearer $tok"
    users=$(curl -s "$A/admin/users" -H "$auth")
    uid=$(printf '%s' "$users" | tr '{' '\n' | grep "\"username\": *\"$U\"" \
      | sed -n 's/.*"id": *"\([0-9a-f]\{16\}\)".*/\1/p' | head -n 1)
    printf '  sign-on address: '
    curl -s -o /dev/null -w '%{http_code}\n' -X POST "$A/admin/users/$uid/email" -H "$auth" \
      -H 'Content-Type: application/json' --data "{\"email\":\"${OWNER_EMAIL:-gengar@example.com}\"}"
    printf '  estate name and single sign-on: '
    curl -s -o /dev/null -w '%{http_code}\n' -X PUT "$A/admin/settings" -H "$auth" \
      -H 'Content-Type: application/json' --data "{\"org_name\":\"${ORG_NAME:-Pallet Town Ltd}\",\"sso_tenant_id\":\"11111111-2222-3333-4444-555555555555\",\"sso_client_id\":\"66666666-7777-8888-9999-000000000000\",\"sso_client_secret\":\"demo-client-secret\",\"sso_redirect_uri\":\"${PORTAL_URL:-http://localhost:8091}/sso/callback\",\"sso_enabled\":\"1\"}"
  else
    echo "owner account already exists; signing in to refresh the demo data"
    sess=$(curl -s -X POST "$A/admin/login" -H 'Content-Type: application/json' \
      --data "{\"username\":\"$U\",\"password\":\"$PW\"}")
    tok=$(printf '%s' "$sess" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
    [ -z "$tok" ] && echo "  could not sign in as $U (password changed?): $sess"
  fi
fi

# --- demo data behind the sign-in ------------------------------------------
# Budget and Fleet are empty until an admin links a plan or enrolls a device,
# and a demo that shows two empty pages teaches nothing. Three plans with
# seat tiers and member lists, chosen so every Budget state appears: seats
# nobody uses, people using a tool with no seat, a personal account running
# beside a paid one. And one enrollment token with three devices enrolled
# through the real /enroll exchange, so Fleet has a roll to show.
if [ -n "$tok" ]; then
  auth="Authorization: Bearer $tok"
  put() { curl -s -o /dev/null -w '%{http_code} ' -X PUT "$A$1" -H "$auth" -H 'Content-Type: application/json' --data "$2"; }
  printf 'budget plans: '
  put /admin/budget/subscription '{"tool_id":"chatgpt","plan_key":"business","vendor":"OpenAI","plan":"Business","currency":"GBP","renewal_date":"2027-03-31","owner":"Security","notes":"Annual, invoiced quarterly","seat_tiers":[{"name":"Business","seats":10,"unit_price_monthly":25}],"covers":["codex-cli"]}'
  put /admin/budget/subscription '{"tool_id":"claude","plan_key":"team","vendor":"Anthropic","plan":"Team","currency":"GBP","renewal_date":"2027-01-15","owner":"Engineering","notes":"Premium seats include Claude Code","seat_tiers":[{"name":"Standard","seats":6,"unit_price_monthly":27},{"name":"Premium","seats":2,"unit_price_monthly":120,"covers":["claude-code"]}],"covers":["claude-code"]}'
  put /admin/budget/subscription '{"tool_id":"github-copilot","plan_key":"business","vendor":"GitHub","plan":"Copilot Business","currency":"USD","renewal_date":"2026-12-01","owner":"Engineering","seat_tiers":[{"name":"Business","seats":8,"unit_price_monthly":19}]}'
  echo
  printf 'budget members: '
  put /admin/budget/members '{"tool_id":"chatgpt","plan_key":"business","source":"csv","members":[{"email":"eevee@example.com","name":"Eevee","role":"member","seat_tier":"Business"},{"email":"snorlax@example.com","name":"Snorlax","role":"member","seat_tier":"Business"},{"email":"psyduck@example.com","name":"Psyduck","role":"member","seat_tier":"Business"},{"email":"mew@example.com","name":"Mew","role":"admin","seat_tier":"Business"},{"email":"jigglypuff@example.com","name":"Jigglypuff","role":"member","seat_tier":"Business"},{"email":"meowth@example.com","name":"Meowth","role":"member","seat_tier":"Business"}]}'
  put /admin/budget/members '{"tool_id":"claude","plan_key":"team","source":"csv","members":[{"email":"eevee@example.com","name":"Eevee","role":"member","seat_tier":"Premium"},{"email":"mew@example.com","name":"Mew","role":"member","seat_tier":"Standard"},{"email":"gengar@example.com","name":"Gengar","role":"owner","seat_tier":"Standard"},{"email":"snorlax@example.com","name":"Snorlax","role":"member","seat_tier":"Standard"},{"email":"lapras@example.com","name":"Lapras","role":"member","seat_tier":"Standard"}]}'
  put /admin/budget/members '{"tool_id":"github-copilot","plan_key":"business","source":"csv","members":[{"email":"snorlax@example.com","name":"Snorlax","role":"member","seat_tier":"Business"},{"email":"eevee@example.com","name":"Eevee","role":"member","seat_tier":"Business"},{"email":"onix@example.com","name":"Onix","role":"member","seat_tier":"Business"}]}'
  echo
  if ! curl -s "$A/admin/enrollment-tokens" -H "$auth" | grep -q "Demo rollout"; then
    printf 'enrollment: '
    mint=$(curl -s -X POST "$A/admin/enrollment-tokens" -H "$auth" -H 'Content-Type: application/json' \
      --data '{"note":"Demo rollout (Jamf and Intune)","ttl_days":365}')
    et=$(printf '%s' "$mint" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
    for d in "macos C02PIKACHU pikachu-mbp" "linux NIX-BULBA nix-bulba" "windows WIN-CHARM WIN-CHARM"; do
      set -- $d
      curl -s -o /dev/null -w '%{http_code} ' -X POST "$A/enroll" -H "Authorization: Bearer $et" \
        -H 'Content-Type: application/json' --data "{\"platform\":\"$1\",\"serial\":\"$2\",\"hostname\":\"$3\",\"agent_version\":\"demo\"}"
    done
    echo
  fi
fi
