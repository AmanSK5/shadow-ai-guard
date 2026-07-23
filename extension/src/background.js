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
    });
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
    });
  }
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

async function report(payload) {
  const { endpoint, device, authToken } = await getConfig();
  payload.device = device;

  if (!endpoint) {
    // No endpoint set (e.g. loaded unpacked with no MDM config). Surface the
    // flag in the service worker console so local testing is visible.
    console.log("[ai-account-guard] FLAG (no endpoint set):", payload);
    return;
  }

  const headers = { "Content-Type": "application/json" };
  if (authToken) headers["Authorization"] = "Bearer " + authToken;

  try {
    await fetch(endpoint, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.warn("[ai-account-guard] report failed", e);
    // optionally queue in chrome.storage.local and retry on next event
  }
}
