#!/bin/bash
#
# ai-guard Extension Attribute (macOS)
# Reads the summary written by ai-guard-collector.sh so AI tooling per device
# is visible and smart-groupable in Jamf inventory. No scanning happens here;
# the collector does the work on its own schedule.
#
# Jamf Pro > Settings > Computer Management > Extension Attributes
#   Display name: AI Guard - AI Tools Detected
#   Data type:    String
#   Input type:   Script

SUMMARY_FILE="/Library/Application Support/ai-guard/last_scan.txt"

if [ -f "$SUMMARY_FILE" ]; then
  echo "<result>$(/bin/cat "$SUMMARY_FILE")</result>"
else
  echo "<result>not yet scanned</result>"
fi
