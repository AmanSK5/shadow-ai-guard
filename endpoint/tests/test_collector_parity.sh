#!/usr/bin/env bash
# Cross-collector invariants, asserted statically.
#
# Why static rather than end-to-end: the Linux collector is the only one CI can
# actually run, and it was the only one of the three that had this right. The
# macOS collector deduped on "surface|tool" while Linux and Windows deduped on
# "surface|tool|trigger", so on macOS every scheduled-job finding was discarded
# whenever the tool was also installed - which is every machine anybody would
# schedule it on. The scheduler scan therefore reported nothing on macOS from
# the day it shipped, and no test could have noticed because no test runs the
# macOS collector.
#
# These assertions cost nothing and hold on any runner. A property that must be
# true of all three collectors is checked against all three.
set -u
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

MAC=endpoint/macos/ai-guard-collector.sh
LIN=endpoint/linux/ai-guard-collector.sh
WIN=endpoint/windows/ai-guard-collector.ps1

echo "the dedupe key includes the trigger, in all three"
# A scheduled job and an installed tool are different findings about the same
# tool. Two scheduled jobs on one machine are two findings. Both require the
# trigger in the key; without it the second is silently dropped.
# sed the function body rather than a fixed -A window: a comment added above
# the line would otherwise slide it out of view and pass the test by accident.
key_line() { sed -n "/^$2()/,/^}/p" "$1" | grep -E 'local (key|k)='; }
key_line "$MAC" report_once | grep -q '"\$1|\$2|\${7:-}"' \
  && ok "macos"   || bad "macos: report_once drops the trigger from its key"
key_line "$LIN" report_once | grep -q '"\$1|\$2|\${7:-}"' \
  && ok "linux"   || bad "linux: report_once drops the trigger from its key"
grep -q '\$key = "\$Surface|\$Tool|\$Trigger"' "$WIN" \
  && ok "windows" || bad "windows: Send-FindingOnce drops the trigger from its key"

echo "the collector version moves when the collectors do"
# The scheduler scan shipped without this moving, so a collector that could
# read schedulers and one that could not both reported 2.0.0 - and an empty
# Agentic AI page could not be told from an undeployed one.
mv=$(grep -m1 '^COLLECTOR_VERSION=' "$MAC" | cut -d'"' -f2)
lv=$(grep -m1 '^COLLECTOR_VERSION=' "$LIN" | cut -d'"' -f2)
wv=$(grep -m1 'CollectorVersion = ' "$WIN" | cut -d"'" -f2)
if [ "$mv" = "$lv" ] && [ "$lv" = "$wv" ]; then
  ok "all three report $mv"
else
  bad "versions disagree: macos=$mv linux=$lv windows=$wv"
fi

echo "the scripts the portal serves match the ones in endpoint/"
# The portal hands these to an operator to deploy. A fix that lands in one
# copy and not the other ships the bug to the fleet while the repo looks fixed.
for pair in "$MAC portal/collector-scripts/collector-macos.sh" \
            "$LIN portal/collector-scripts/collector-linux.sh" \
            "$WIN portal/collector-scripts/collector-windows.ps1"; do
  set -- $pair
  if diff -q "$1" "$2" >/dev/null 2>&1; then
    ok "$(basename "$2")"
  else
    bad "$(basename "$2") differs from $1"
  fi
done

[ "$fail" -eq 0 ] && echo "collector parity: all invariants hold" \
                  || echo "collector parity: FAILED"
exit "$fail"
