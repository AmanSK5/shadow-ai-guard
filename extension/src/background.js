// AI Guard - background service worker
// Receives domain-only account flags and content-free paste-guard events,
// dedupes them, attaches the MDM-stamped device id, and POSTs to the
// configured endpoint.
// v1.1.0: Slack webhook support removed; the receiver is the only sink.

// Firefox exposes the extension APIs as browser.* returning promises, and also
// as chrome.* returning callbacks. Chrome has no browser.* at all, and its
// chrome.* returns promises under MV3. So chrome.* is the namespace that exists
// in both and the one that behaves differently in each: every await in this
// file would resolve to undefined in Firefox. Resolve the namespace once and
// use that.
const api = globalThis.browser ?? globalThis.chrome;

const FALLBACK_ENDPOINT = ""; // leave blank; set via managed config in production
const FALLBACK_DEVICE = "";   // optional: set a label for LOCAL testing only
const FALLBACK_AUTH_TOKEN = ""; // optional: set for LOCAL testing only
const DEDUPE_WINDOW_MS = 6 * 60 * 60 * 1000; // one flag per tool+domain per 6h

// Dedupe state for personal-account flags. This was a module-level Map, which
// lives exactly as long as the service worker does: Chrome stops an MV3
// worker after roughly thirty seconds idle and content.js checks every five
// minutes, so the six-hour window was in practice one flag per check. The
// receiver's alert TTL hid it from Slack, which is why nobody noticed, but
// every repeat was a Loki line, a skewed occurrence count and a slice of the
// portal's read budget.
//
// storage.session survives worker restarts, is cleared when the browser
// exits and is never written to disk, which is the right lifetime for "we
// already said this today". storage.local is the fallback for a browser
// without it: the same fix the heartbeat already uses for lastHeartbeat.
const SEEN_KEY = "personalAccountSeen";

function seenStore() {
  return api.storage.session || api.storage.local;
}

// True if this tool+domain was reported inside the window. Otherwise records
// it and returns false. Entries past the window are dropped on the way
// through so the object cannot grow without bound.
async function alreadyReported(key, now) {
  const store = seenStore();
  let seen = {};
  try {
    const state = await store.get(SEEN_KEY);
    seen = (state && state[SEEN_KEY]) || {};
  } catch (e) { /* unreadable state is an empty state: report rather than lose */ }

  if (seen[key] && now - seen[key] < DEDUPE_WINDOW_MS) return true;

  for (const k of Object.keys(seen)) {
    if (now - seen[k] >= DEDUPE_WINDOW_MS) delete seen[k];
  }
  seen[key] = now;
  try {
    await store.set({ [SEEN_KEY]: seen });
  } catch (e) { /* a write that fails costs one duplicate, not a finding */ }
  return false;
}

async function onPersonalAccount(msg) {
  const key = msg.tool + ":" + msg.domain;
  if (await alreadyReported(key, Date.now())) return;
  await report({
    tool: msg.tool,
    // Absent until 1.2.0. The receiver defaults surface to "browser" and
    // severity to "warn", so these findings looked right while carrying no
    // source at all: on one fleet that was thousands a week that could not
    // be traced to a detector. Defaults that happen to be correct are not
    // the same as fields that are set.
    surface: "browser",
    source: "browser_extension",
    severity: "warn",
    account_domain: msg.domain,
    reported_at: msg.ts,
  });
}

api.runtime.onMessage.addListener((msg) => {
  if (!msg) return;

  if (msg.type === "personal-account") {
    // Not returned. A listener that returns a promise tells Firefox a reply is
    // coming, and content.js is not waiting for one.
    onPersonalAccount(msg)
      .catch((e) => console.warn("[ai-account-guard] report failed", e));
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
// Sent on browser startup, install/update, and daily via api.alarms.
// Traverses extension -> managed config -> token -> receiver -> Loki, so one
// heartbeat in the last 24h means the paste guard on that device WORKS, not
// just that the MDM delivered a profile. Carries version and mode only.

const HEARTBEAT_MIN_INTERVAL_MS = 20 * 60 * 60 * 1000; // at most ~once a day
const HEARTBEAT_ALARM = "ai-guard-heartbeat";
const HEARTBEAT_RETRY_ALARM = "ai-guard-heartbeat-retry";
const HEARTBEAT_RETRY_MINUTES = 60;

async function heartbeat(reason) {
  try {
    const state = await api.storage.local.get("lastHeartbeat");
    const now = Date.now();
    if (state.lastHeartbeat && now - state.lastHeartbeat < HEARTBEAT_MIN_INTERVAL_MS) return;
    let mode = "warn";
    try {
      const cfg = await api.storage.managed.get("pasteGuardMode");
      if (cfg && ["off", "warn", "block"].includes(cfg.pasteGuardMode)) mode = cfg.pasteGuardMode;
    } catch (e) { /* unmanaged: fallback mode stands */ }

    // Independent of whether the heartbeat lands. A device that cannot reach
    // the receiver is exactly the one that might need a newer version to get
    // out of that state, so the update check does not wait on delivery.
    //
    // Chrome only. Firefox has no requestUpdateCheck and polls its own update
    // manifest on its own schedule, so there is nothing to ask for and calling
    // it would throw inside the heartbeat.
    if (api.runtime.requestUpdateCheck) api.runtime.requestUpdateCheck(() => {});

    const delivered = await report({
      tool: "paste-guard",
      surface: "browser",
      source: "paste_guard",
      severity: "info",
      evidence: "heartbeat version=" + api.runtime.getManifest().version +
                " mode=" + mode + " reason=" + reason,
      reported_at: new Date().toISOString(),
    });

    // Only now. Writing the timestamp before delivery was confirmed meant a
    // failed POST still counted as done, so the device went quiet for the
    // whole interval and looked like a broken install on the dashboard for a
    // day. delivered is false in print-only mode, where there is nothing to
    // confirm and nothing to remember.
    if (delivered) await api.storage.local.set({ lastHeartbeat: now });
  } catch (e) {
    console.warn("[ai-account-guard] heartbeat failed", e);
    // Try again in an hour rather than waiting for tomorrow's alarm. Creating
    // an alarm with an existing name replaces it, so repeated failures do not
    // stack up.
    api.alarms.create(HEARTBEAT_RETRY_ALARM, { delayInMinutes: HEARTBEAT_RETRY_MINUTES });
  }
}

api.runtime.onStartup.addListener(() => heartbeat("startup"));
api.runtime.onInstalled.addListener(() => heartbeat("installed"));
api.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 60 * 24 });
api.alarms.onAlarm.addListener((a) => {
  if (a.name === HEARTBEAT_ALARM) heartbeat("alarm");
  if (a.name === HEARTBEAT_RETRY_ALARM) heartbeat("retry");
});

async function getConfig() {
  try {
    const cfg = await api.storage.managed.get([
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
// api.runtime.getPlatformInfo returns "mac", "win", "linux", "cros",
// "android", "openbsd". The receiver's vocabulary is macos, windows, linux,
// unknown, and it coerces anything else to unknown - so ChromeOS reports
// honestly as unknown rather than being forced into one of the three.
const OS_NAMES = { mac: "macos", win: "windows", linux: "linux" };
let osPromise = null;

function detectOs() {
  // Resolved once and reused. getPlatformInfo is async and cheap, but a
  // service worker can be woken hundreds of times a day.
  if (!osPromise) {
    osPromise = api.runtime.getPlatformInfo()
      .then((info) => OS_NAMES[info.os] || "unknown")
      .catch(() => "unknown");
  }
  return osPromise;
}

async function report(payload) {
  const { endpoint, device, authToken } = await getConfig();
  payload.device = device;

  // Set here rather than at each call site: three callers had three chances
  // to forget it, and all three did. The receiver coerced the missing field
  // to "unknown", so every browser finding was unattributable to an OS and
  // nothing said why.
  if (!payload.os) payload.os = await detectOs();

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