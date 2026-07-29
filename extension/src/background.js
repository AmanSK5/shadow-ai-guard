// AI Guard - background service worker
// Receives domain-only account flags and content-free paste-guard events,
// dedupes them, attaches the MDM-stamped device id, and POSTs to the
// configured endpoint.
// v1.1.0: Slack webhook support removed; the receiver is the only sink.

const FALLBACK_ENDPOINT = ""; // leave blank; set via managed config in production
const FALLBACK_DEVICE = "";   // optional: set a label for LOCAL testing only
const FALLBACK_AUTH_TOKEN = ""; // optional: set for LOCAL testing only
const DEDUPE_WINDOW_MS = 6 * 60 * 60 * 1000; // one flag per tool+domain per 6h
const seen = new Map();

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg) return;

  if (msg.type === "personal-account") {
    const key = msg.tool + ":" + msg.domain;
    const now = Date.now();
    if (seen.has(key) && now - seen.get(key) < DEDUPE_WINDOW_MS) return;
    seen.set(key, now);
    report({
      tool: msg.tool,
      account_domain: msg.domain,
      reported_at: msg.ts,
    }).catch((e) => console.warn("[ai-account-guard] report failed", e));
    return;
  }

  if (msg.type === "paste-guard") {
    // Content-side already dedupes. Mapped onto the receiver's existing
    // Finding schema so no receiver change is needed: source identifies the
    // guard, evidence carries "<action>: <detector ids>". The matched text
    // never reaches this worker.
    report({
      tool: msg.tool,
      surface: "browser",
      source: "paste_guard",
      severity: "warn",
      evidence: "paste " + msg.action + ": " + msg.detectors.join(","),
      reported_at: msg.ts,
    }).catch((e) => console.warn("[ai-account-guard] report failed", e));
  }
});

// ---- heartbeat: proves the whole chain works per device ----
// Sent on browser startup, install/update, and daily via chrome.alarms.
// Traverses extension -> managed config -> token -> receiver -> Loki, so one
// heartbeat in the last 24h means the paste guard on that device WORKS, not
// just that the MDM delivered a profile. Carries version and mode only.

const HEARTBEAT_MIN_INTERVAL_MS = 20 * 60 * 60 * 1000; // at most ~once a day
const HEARTBEAT_ALARM = "ai-guard-heartbeat";
const HEARTBEAT_RETRY_ALARM = "ai-guard-heartbeat-retry";
const HEARTBEAT_RETRY_MINUTES = 60;

async function heartbeat(reason) {
  try {
    const state = await chrome.storage.local.get("lastHeartbeat");
    const now = Date.now();
    if (state.lastHeartbeat && now - state.lastHeartbeat < HEARTBEAT_MIN_INTERVAL_MS) return;
    let mode = "warn";
    try {
      const cfg = await chrome.storage.managed.get("pasteGuardMode");
      if (cfg && ["off", "warn", "block"].includes(cfg.pasteGuardMode)) mode = cfg.pasteGuardMode;
    } catch (e) { /* unmanaged: fallback mode stands */ }

    // Independent of whether the heartbeat lands. A device that cannot reach
    // the receiver is exactly the one that might need a newer version to get
    // out of that state, so the update check does not wait on delivery.
    chrome.runtime.requestUpdateCheck(() => {});

    const delivered = await report({
      tool: "paste-guard",
      surface: "browser",
      source: "paste_guard",
      severity: "info",
      evidence: "heartbeat version=" + chrome.runtime.getManifest().version +
                " mode=" + mode + " reason=" + reason,
      reported_at: new Date().toISOString(),
    });

    // Only now. Writing the timestamp before delivery was confirmed meant a
    // failed POST still counted as done, so the device went quiet for the
    // whole interval and looked like a broken install on the dashboard for a
    // day. delivered is false in print-only mode, where there is nothing to
    // confirm and nothing to remember.
    if (delivered) await chrome.storage.local.set({ lastHeartbeat: now });
  } catch (e) {
    console.warn("[ai-account-guard] heartbeat failed", e);
    // Try again in an hour rather than waiting for tomorrow's alarm. Creating
    // an alarm with an existing name replaces it, so repeated failures do not
    // stack up.
    chrome.alarms.create(HEARTBEAT_RETRY_ALARM, { delayInMinutes: HEARTBEAT_RETRY_MINUTES });
  }
}

chrome.runtime.onStartup.addListener(() => heartbeat("startup"));
chrome.runtime.onInstalled.addListener(() => heartbeat("installed"));
chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 60 * 24 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === HEARTBEAT_ALARM) heartbeat("alarm");
  if (a.name === HEARTBEAT_RETRY_ALARM) heartbeat("retry");
});

async function getConfig() {
  try {
    const cfg = await chrome.storage.managed.get([
      "reportEndpoint",
      "deviceIdentifier",
      "authToken",
    ]);
    return {
      endpoint: (cfg && cfg.reportEndpoint) || FALLBACK_ENDPOINT,
      device: (cfg && cfg.deviceIdentifier) || FALLBACK_DEVICE || "unknown",
      authToken: (cfg && cfg.authToken) || FALLBACK_AUTH_TOKEN || "",
    };
  } catch (e) {
    return {
      endpoint: FALLBACK_ENDPOINT,
      device: FALLBACK_DEVICE || "unknown",
      authToken: FALLBACK_AUTH_TOKEN || "",
    };
  }
}

// Returns true when the receiver accepted the finding, false when there is no
// endpoint to send it to, and throws when delivery failed. Callers that record
// state need to know the difference: a POST that returned 401 or never left
// the machine is not a delivered finding, and treating it as one is how a
// device goes quiet without anything noticing.
async function report(payload) {
  const { endpoint, device, authToken } = await getConfig();
  payload.device = device;

  if (!endpoint) {
    // No endpoint set (e.g. loaded unpacked with no MDM config). Surface the
    // flag in the service worker console so local testing is visible.
    console.log("[ai-account-guard] FLAG (no endpoint set):", payload);
    return false;
  }

  const headers = { "Content-Type": "application/json" };
  if (authToken) headers["Authorization"] = "Bearer " + authToken;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: headers,
    body: JSON.stringify(payload),
  });

  // fetch only rejects on a network-level failure, so a 401 or a 500 arrives
  // here looking like success unless the status is checked.
  if (!response.ok) {
    throw new Error("receiver returned HTTP " + response.status);
  }
  return true;
}