#!/bin/sh
# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

# A larger synthetic estate on top of seed.sh: fifty-odd devices, two dozen
# tools, twenty personal accounts, six subscriptions. The point is not the
# story of any one finding but the shape of the pages when there is a lot of
# them - which is what a real estate looks like and what the demo's handful
# of findings cannot show. Everything is fake: users are Pokemon, domains
# are example / gmail / outlook, devices are made up. Safe to re-run.
#
#   docker compose run --rm --entrypoint "/bin/sh /seed-large.sh" seeder
# shellcheck disable=SC2088  # evidence strings are data, not paths to expand
set -e
R="${RECEIVER:-http://receiver:8080}/report"
T="${TOKEN:-demo-token}"
A="${RECEIVER:-http://receiver:8080}"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
post() {
  curl -s -o /dev/null -w '.' -X POST "$R" -H "Authorization: Bearer $T" \
    -H "Content-Type: application/json" --data "$1"
}
# f TOOL SURFACE OS DOMAIN DEVICE USER EVIDENCE SEVERITY SOURCE [extra json]
f() {
  post "{\"tool\":\"$1\",\"surface\":\"$2\",\"os\":\"$3\",\"account_domain\":\"$4\",\"device\":\"$5\",\"user\":\"$6\",\"evidence\":\"$7\",\"severity\":\"$8\",\"reported_at\":\"$(now)\",\"source\":\"$9\"${10:+,${10}}}"
}
echo "seeding a large synthetic estate -> $R"

# --- the fleet: macOS, Windows and Linux machines with a local user each ---
MAC="abra alakazam arbok arcanine beedrill bellsprout blastoise butterfree caterpie chansey clefable clefairy cloyster cubone dewgong diglett dodrio doduo dragonair dragonite"
WIN="dratini drowzee dugtrio ekans electabuzz electrode exeggcute exeggutor farfetchd fearow flareon gastly geodude gloom golbat golduck"
NIX="goldeen golem graveler grimer growlithe gyarados haunter hitmonchan hitmonlee horsea hypno ivysaur"

# Endpoint collectors see the tools people installed. The mix leans the way
# real estates do: a few tools everywhere, a long tail on one or two machines.
i=0
for u in $MAC; do
  d="MBP-$(echo $u | tr a-z A-Z)"; i=$((i+1))
  f claude browser macos example.com "$d" "$u" "claude.ai in Chrome" info collector-macos
  [ $((i % 2)) -eq 0 ] && f claude-code cli macos example.com "$d" "$u" "~/.claude.json" info collector-macos
  [ $((i % 3)) -eq 0 ] && f chatgpt desktop macos example.com "$d" "$u" "/Applications/ChatGPT.app" info collector-macos
  [ $((i % 4)) -eq 0 ] && f cursor desktop macos "" "$d" "$u" "/Applications/Cursor.app" info collector-macos
  [ $((i % 5)) -eq 0 ] && f wispr-flow desktop macos "" "$d" "$u" "/Applications/Wispr Flow.app" info collector-macos
  [ $((i % 6)) -eq 0 ] && f warp desktop macos "" "$d" "$u" "/Applications/Warp.app" info collector-macos
  [ $((i % 7)) -eq 0 ] && f ollama desktop macos "" "$d" "$u" "ollama binary" info collector-macos
  [ $((i % 8)) -eq 0 ] && f lm-studio desktop macos "" "$d" "$u" "/Applications/LM Studio.app" info collector-macos
  [ $((i % 9)) -eq 0 ] && f perplexity desktop macos "" "$d" "$u" "/Applications/Perplexity.app" info collector-macos
  [ $((i % 5)) -eq 1 ] && f claude-code-mcp mcp macos "" "$d" "$u" ".claude.json mcpServers: github,linear" info collector-macos
done
for u in $WIN; do
  d="WIN-$(echo $u | tr a-z A-Z)"; i=$((i+1))
  f microsoft-copilot browser windows example.com "$d" "$u" "copilot.microsoft.com in Edge" info collector-windows
  [ $((i % 2)) -eq 0 ] && f claude-code cli windows example.com "$d" "$u" "%USERPROFILE%\\\\.claude.json" info collector-windows
  [ $((i % 3)) -eq 0 ] && f github-copilot ide windows "" "$d" "$u" "VS Code extension GitHub.copilot" info collector-windows
  [ $((i % 4)) -eq 0 ] && f codeium ide windows "" "$d" "$u" "VS Code extension Codeium.codeium" info collector-windows
  [ $((i % 5)) -eq 0 ] && f grammarly browser windows "" "$d" "$u" "Chrome extension Grammarly" info collector-windows
  [ $((i % 6)) -eq 0 ] && f notion-ai browser windows example.com "$d" "$u" "notion.so AI in Edge" info collector-windows
done
for u in $NIX; do
  d="NIX-$(echo $u | tr a-z A-Z)"; i=$((i+1))
  f claude-code cli linux example.com "$d" "$u" "~/.claude.json" info collector-linux
  [ $((i % 2)) -eq 0 ] && f codex-cli cli linux example.com "$d" "$u" "~/.codex/config.toml" info collector-linux
  [ $((i % 3)) -eq 0 ] && f gemini-cli cli linux "" "$d" "$u" "~/.gemini/settings.json" info collector-linux
  [ $((i % 4)) -eq 0 ] && f ollama desktop linux "" "$d" "$u" "ollama binary" info collector-linux
  [ $((i % 5)) -eq 0 ] && f warp desktop linux "" "$d" "$u" "warp-terminal binary" info collector-linux
done

# --- personal accounts: twenty, across the tools people actually use ---
p=0
for pair in abra:chatgpt alakazam:chatgpt arbok:chatgpt arcanine:chatgpt beedrill:gemini bellsprout:claude-code \
            blastoise:claude-code butterfree:codex-cli caterpie:codex-cli chansey:chatgpt dratini:chatgpt \
            drowzee:claude dugtrio:claude-code ekans:chatgpt goldeen:codex-cli golem:claude-code graveler:codex-cli \
            grimer:chatgpt growlithe:claude-code gyarados:gemini; do
  u=${pair%%:*}; t=${pair##*:}; p=$((p+1))
  case "$u" in
    drat*|drow*|dugt*|ekan*) d="WIN-$(echo $u | tr a-z A-Z)"; os=windows; src=collector-windows;;
    gold*|gole*|grav*|grim*|grow*|gyar*) d="NIX-$(echo $u | tr a-z A-Z)"; os=linux; src=collector-linux;;
    *) d="MBP-$(echo $u | tr a-z A-Z)"; os=macos; src=collector-macos;;
  esac
  dom=gmail.com; [ $((p % 4)) -eq 0 ] && dom=outlook.com; [ $((p % 7)) -eq 0 ] && dom=me.com
  case "$t" in
    chatgpt|gemini|claude) f "$t" browser "$os" "$dom" "$d" "$u" "signed in as $u@$dom" warn browser_extension;;
    *) f "$t" cli "$os" "$dom" "$d" "$u" "~/.config credentials: $u@$dom" warn "$src";;
  esac
done

# --- cloud identities: sign-ins the tenant saw, with no machine attached ---
for u in $MAC $WIN; do
  case "$u" in a*|b*|d*) f chatgpt cloud unknown example.com "" "$u" "interactive sign-in to ChatGPT" info entra_sign_in;; esac
  case "$u" in c*|e*|f*) f fireflies cloud unknown example.com "" "$u" "interactive sign-in to Fireflies" info entra_sign_in;; esac
  case "$u" in g*) f github-copilot cloud unknown example.com "" "$u" "interactive sign-in to GitHub" info entra_sign_in;; esac
done
for u in abra beedrill chansey dodrio ekans flareon; do
  f openai-api-platform cloud unknown example.com "" "$u" "consent grant: OpenAI API" info entra_consent_grant
done
for u in arbok cloyster dragonite golbat; do
  f atlassian-rovo cloud unknown example.com "" "$u" "interactive sign-in to Atlassian" info entra_sign_in
done

# --- machines only the scanners know: the coverage gaps ---
GAP="jigglypuff jolteon jynx kabuto kabutops kadabra kakuna kangaskhan kingler koffing krabby lapras lickitung machamp machoke machop magikarp magmar magnemite magneton mankey marowak"
g=0
for u in $GAP; do
  g=$((g+1)); d="LT-$(echo $u | tr a-z A-Z)"
  if [ $((g % 2)) -eq 0 ]; then
    f claude network unknown "" "$d" "" "DNS lookup for claude.ai (via Google Chrome)" info sentinelone_dns
  else
    f paste-guard browser windows "" "$d" "" "heartbeat version=1.1.1 mode=warn" info paste_guard
  fi
  [ $((g % 3)) -eq 0 ] && f chatgpt network unknown "" "$d" "" "DNS lookup for chatgpt.com (via Edge)" info sentinelone_dns
  [ $((g % 5)) -eq 0 ] && f deepseek network unknown "" "$d" "" "dns:deepseek.com" info sentinelone_dns
done

# --- the paste guard, on the machines that have it ---
for u in $MAC $WIN; do
  case "$u" in a*|b*|c*|d*|e*|f*)
    case "$u" in d*|e*|f*) d="WIN-$(echo $u | tr a-z A-Z)"; os=windows;; *) d="MBP-$(echo $u | tr a-z A-Z)"; os=macos;; esac
    f paste-guard browser "$os" "" "$d" "" "heartbeat version=1.1.1 mode=warn" info paste_guard;;
  esac
done
f chatgpt.com browser macos "" MBP-ABRA "" "paste warned: aws_access_key" warn paste_guard
f claude.ai browser windows "" WIN-DRATINI "" "paste warned: classification_marking" warn paste_guard

# --- what runs without a person ---
f claude-code cli linux "" NIX-GOLDEEN "" "/etc/systemd/system/nightly-triage.service" warn collector-linux '"mode":"autonomous","identity":"machine","trigger":"systemd timer, every 15 min","schedule":"oncalendar:*:0/15"'
f claude-code cli macos "" MBP-ARBOK "" "~/Library/LaunchAgents/ai.helper.plist" warn collector-macos '"mode":"autonomous","identity":"machine","trigger":"launchd, at login","schedule":"atlogin"'
f claude-code cli macos example.com MBP-ABRA abra "~/Library/LaunchAgents/daily-notes.plist" info collector-macos '"mode":"autonomous","identity":"person","trigger":"launchd, every 6 hours","schedule":"interval:21600"'
f claude network linux "" NIX-GOLEM "" "DNS lookup for api.anthropic.com (via python3)" warn sentinelone_dns '"trigger":"cron, 0 2 * * *","schedule":"cron:0 2 * * *"'

echo ""
# --- six subscriptions, with the seat lists a vendor export would carry ---
U="${OWNER_USER:-gengar}"; PW="${OWNER_PASSWORD:-gengar-demo-portal}"
sess=$(curl -s -X POST "$A/admin/login" -H 'Content-Type: application/json' \
  --data "{\"username\":\"$U\",\"password\":\"$PW\"}")
tok=$(printf '%s' "$sess" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
if [ -z "$tok" ]; then echo "could not sign in as $U; budget not seeded"; exit 0; fi
auth="Authorization: Bearer $tok"
put() { curl -s -o /dev/null -w '%{http_code} ' -X PUT "$A$1" -H "$auth" -H 'Content-Type: application/json' --data "$2"; }
members() {
  # members TOOL PLAN TIER names...
  t=$1; pk=$2; tier=$3; shift 3; out=""
  for n in "$@"; do out="$out{\"email\":\"$n@example.com\",\"name\":\"$n\",\"role\":\"member\",\"seat_tier\":\"$tier\"},"; done
  put /admin/budget/members "{\"tool_id\":\"$t\",\"plan_key\":\"$pk\",\"source\":\"csv\",\"members\":[${out%,}]}"
}
printf 'budget plans: '
put /admin/budget/subscription '{"tool_id":"chatgpt","plan_key":"business","vendor":"OpenAI","plan":"Business","currency":"GBP","renewal_date":"2027-03-31","owner":"Security","seat_tiers":[{"name":"Business","seats":13,"unit_price_monthly":25}],"covers":["codex-cli"]}'
put /admin/budget/subscription '{"tool_id":"claude","plan_key":"team","vendor":"Anthropic","plan":"Team","currency":"GBP","renewal_date":"2026-10-01","owner":"Engineering","seat_tiers":[{"name":"Standard","seats":10,"unit_price_monthly":27},{"name":"Premium","seats":3,"unit_price_monthly":120,"covers":["claude-code"]}],"covers":["claude-code"]}'
put /admin/budget/subscription '{"tool_id":"claude","plan_key":"max-20","vendor":"Anthropic","plan":"Max 20","currency":"GBP","renewal_date":"2026-10-01","owner":"Engineering","seat_tiers":[{"name":"Max 20","seats":4,"unit_price_monthly":180,"covers":["claude-code"]}],"covers":["claude-code"]}'
put /admin/budget/subscription '{"tool_id":"claude","plan_key":"max-5","vendor":"Anthropic","plan":"Max 5","currency":"GBP","renewal_date":"2026-10-01","owner":"Engineering","seat_tiers":[{"name":"Max 5","seats":6,"unit_price_monthly":90,"covers":["claude-code"]}],"covers":["claude-code"]}'
put /admin/budget/subscription '{"tool_id":"cursor","plan_key":"teams","vendor":"Anysphere","plan":"Teams","currency":"USD","renewal_date":"2026-10-01","owner":"Engineering","seat_tiers":[{"name":"Teams","seats":1,"unit_price_monthly":40}]}'
put /admin/budget/subscription '{"tool_id":"fireflies","plan_key":"enterprise","vendor":"Fireflies","plan":"Enterprise","currency":"USD","renewal_date":"2027-07-14","owner":"Operations","seat_tiers":[{"name":"Enterprise","seats":14,"unit_price_monthly":39}]}'
echo; printf 'budget members: '
members chatgpt business Business abra alakazam arbok arcanine beedrill bellsprout blastoise butterfree caterpie chansey clefable clefairy cloyster
members claude team Standard abra dratini drowzee dugtrio ekans electabuzz electrode exeggcute exeggutor farfetchd
members claude max-20 "Max 20" goldeen golem graveler grimer
members claude max-5 "Max 5" growlithe gyarados haunter hitmonchan hitmonlee horsea
members cursor teams Teams cubone
members fireflies enterprise Enterprise caterpie chansey clefable clefairy cloyster cubone dewgong diglett dodrio doduo dragonair dragonite ekans electabuzz
echo
echo "done. the estate now has a fleet's worth of findings; sign in as $U to see it."
