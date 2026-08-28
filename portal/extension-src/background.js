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

// Managed mode. authToken in the policy may be an enrollment token (aige_...)
// instead of the shared token: this profile then exchanges it once at /enroll
// for its own device credential (aigd_...), kept in storage.local, and reports
// with that. The prefix is the switch - the same contract as the endpoint
// collectors, so an operator flips one policy value when ready.
const ENROLL_PREFIX = "aige_";
const ENROLLMENT_KEY = "enrollment";
const AGENT_VERSION = api.runtime.getManifest().version;

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

// Paste-guard findings outlive the tab they happened in. The guard warns or
// blocks locally whether or not anything is recorded, so a failed POST costs
// no protection - but it costs the audit trail, and "we blocked a card number
// going into ChatGPT" is the half someone asks about later. Unlike a personal
// account, which is still true at the next five-minute check, a paste happened
// once: nothing re-derives it, so a dropped one is gone.
//
// storage.local, because this has to survive a browser restart - the receiver
// being down and the browser being closed overnight are the same evening.
// Bounded both ways so a long outage cannot grow without limit or replay
// something stale into next week's dashboard.
const QUEUE_KEY = "pendingFindings";
const QUEUE_MAX = 100;
const QUEUE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const FLUSH_ALARM = "ai-guard-flush";
const FLUSH_RETRY_MINUTES = 10;

async function readQueue(now) {
  try {
    const state = await api.storage.local.get(QUEUE_KEY);
    const q = (state && state[QUEUE_KEY]) || [];
    return q.filter((e) => e && e.queued_at && now - e.queued_at < QUEUE_TTL_MS);
  } catch (e) {
    return [];
  }
}

// The payload is built here rather than stored as handed in, so what waits on
// disk is the same content-free shape that would have been POSTed: tool,
// surface, source, severity, the detector ids, the time it happened. The
// matched text never reaches this worker in the first place, and this keeps
// it that way if anyone ever changes the message.
async function enqueue(payload, now) {
  const q = await readQueue(now);
  q.push({
    queued_at: now,
    payload: {
      tool: payload.tool,
      surface: payload.surface,
      source: payload.source,
      severity: payload.severity,
      evidence: payload.evidence,
      reported_at: payload.reported_at,
    },
  });
  // Newest wins. An outage long enough to overflow this has bigger problems
  // than its oldest hundred events, and the alternative - dropping what just
  // happened - is the wrong half to lose.
  const kept = q.slice(-QUEUE_MAX);
  if (kept.length < q.length) {
    console.warn("[ai-account-guard] pending queue full, dropped "
                 + (q.length - kept.length) + " oldest");
  }
  try {
    await api.storage.local.set({ [QUEUE_KEY]: kept });
  } catch (e) { /* nothing else to fall back to */ }
  api.alarms.create(FLUSH_ALARM, { delayInMinutes: FLUSH_RETRY_MINUTES });
}

// Oldest first, stopping at the first failure: the receiver being down is the
// reason there is a queue, and draining into a dead endpoint just turns one
// outage into a hundred failed requests. Whatever did not go stays queued.
async function flushQueue() {
  const now = Date.now();
  const q = await readQueue(now);
  if (!q.length) {
    try { await api.storage.local.remove(QUEUE_KEY); } catch (e) { /* fine */ }
    return;
  }
  let sent = 0;
  for (const entry of q) {
    try {
      await report({ ...entry.payload });
      sent++;
    } catch (e) {
      break;
    }
  }
  const left = q.slice(sent);
  try {
    if (left.length) await api.storage.local.set({ [QUEUE_KEY]: left });
    else await api.storage.local.remove(QUEUE_KEY);
  } catch (e) { /* retried on the next flush */ }
  if (left.length) {
    api.alarms.create(FLUSH_ALARM, { delayInMinutes: FLUSH_RETRY_MINUTES });
  }
}

async function readSeen() {
  try {
    const state = await seenStore().get(SEEN_KEY);
    return (state && state[SEEN_KEY]) || {};
  } catch (e) {
    // Unreadable state is an empty state: report rather than lose.
    return {};
  }
}

// True if this tool+domain was reported inside the window. Read-only: the
// window opens when the finding is delivered, not when it is attempted.
async function wasRecentlyReported(key, now) {
  const seen = await readSeen();
  return Boolean(seen[key] && now - seen[key] < DEDUPE_WINDOW_MS);
}

// Opens the six-hour window on a finding that actually landed. Entries past
// the window are dropped on the way through so the object cannot grow
// without bound.
async function markReported(key, now) {
  const seen = await readSeen();
  for (const k of Object.keys(seen)) {
    if (now - seen[k] >= DEDUPE_WINDOW_MS) delete seen[k];
  }
  seen[key] = now;
  try {
    await seenStore().set({ [SEEN_KEY]: seen });
  } catch (e) { /* a write that fails costs one duplicate, not a finding */ }
}

async function onPersonalAccount(msg) {
  const key = msg.tool + ":" + msg.domain;
  const now = Date.now();
  if (await wasRecentlyReported(key, now)) return;
  // Marked only once report() has resolved. It throws when the POST failed -
  // the receiver 503s precisely so a caller knows the finding is not stored -
  // and marking first meant a 503 silenced the flag for six hours while
  // content.js kept re-checking every five minutes. It returns false in
  // print-only mode, which does count: there was nothing to deliver, and the
  // window should still stop the console filling up.
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
  await markReported(key, now);
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
    const payload = {
      tool: msg.tool,
      surface: "browser",
      source: "paste_guard",
      severity: "warn",
      evidence: "paste " + msg.action + ": " + msg.detectors.join(","),
      reported_at: msg.ts,
    };
    report(payload).catch((e) => {
      console.warn("[ai-account-guard] report failed, queued for retry", e);
      return enqueue(payload, Date.now());
    });
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
      evidence: "heartbeat version=" + AGENT_VERSION +
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

// The heartbeat is the one thing that runs on a schedule whether or not
// anyone browses, so it is also when a backlog gets a chance to drain. A
// heartbeat that succeeds proves the whole chain is up, which is exactly the
// moment the queue is worth retrying.
const drain = () => flushQueue()
  .catch((e) => console.warn("[ai-account-guard] flush failed", e));

api.runtime.onStartup.addListener(() => { heartbeat("startup"); drain(); });
api.runtime.onInstalled.addListener(() => { heartbeat("installed"); drain(); });
api.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 60 * 24 });
api.alarms.onAlarm.addListener((a) => {
  if (a.name === HEARTBEAT_ALARM) { heartbeat("alarm"); drain(); }
  if (a.name === HEARTBEAT_RETRY_ALARM) heartbeat("retry");
  if (a.name === FLUSH_ALARM) drain();
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

// ---- enrollment (managed mode) ----

// The receiver base is the report endpoint minus its path. The policy carries
// the full endpoint, as it always has, so nothing new is configured.
function receiverBase(endpoint) {
  // A query string on the endpoint is allowed and dropped; the path must
  // end in /report (or the legacy /flag) for /enroll to be derivable.
  const m = /^(.*)\/(report|flag)\/?(\?.*)?$/.exec(endpoint);
  return m ? m[1] : null;
}

// Eight hex characters, made once per browser profile. It is part of this
// profile's serial, not a secret: uniqueness is all it provides, and the
// fallback exists for a runtime without crypto.
function newInstallId() {
  const bytes = new Uint8Array(4);
  try { crypto.getRandomValues(bytes); } catch (e) {
    for (let i = 0; i < 4; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function storedEnrollment() {
  try {
    const state = await api.storage.local.get(ENROLLMENT_KEY);
    return (state && state[ENROLLMENT_KEY]) || null;
  } catch (e) { return null; }
}

// One in-flight enrollment at a time. A worker that wakes to a startup
// heartbeat and a content-script flag at once would otherwise enroll twice,
// and the second would displace the first.
let enrollPromise = null;

function enrollOnce(cfg, prior) {
  if (!enrollPromise) {
    enrollPromise = enroll(cfg, prior).finally(() => { enrollPromise = null; });
  }
  return enrollPromise;
}

async function enroll(cfg, prior) {
  const base = receiverBase(cfg.endpoint);
  if (!base) {
    throw new Error("cannot enroll: reportEndpoint must end in /report to derive /enroll");
  }
  // The serial is the MDM-stamped device id plus a per-profile id. One
  // machine legitimately runs several managed profiles (Chrome and Edge, two
  // Chrome profiles); with the bare device id they would take turns
  // displacing each other on the receiver. The id is kept across
  // re-enrollments so the receiver sees the same profile, not a new one.
  const installId = (prior && prior.installId) || newInstallId();
  const serial = cfg.device + "/" + installId;
  const response = await fetch(base + "/enroll", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Authorization": "Bearer " + cfg.authToken },
    body: JSON.stringify({ platform: "browser", serial: serial, hostname: "",
                           agent_version: AGENT_VERSION }),
  });
  if (!response.ok) {
    // An expired or revoked enrollment token is an operations task, and the
    // console is the only log this worker has; the heartbeat retry keeps
    // asking hourly, so a fixed policy takes effect without a restart.
    throw new Error("enrollment failed: receiver returned HTTP " + response.status);
  }
  let body = null;
  try { body = await response.json(); } catch (e) { /* handled below */ }
  if (!body || typeof body.device_token !== "string" || !body.device_token.startsWith("aigd_")) {
    // A 200 from something that is not the receiver (a captive portal, a
    // default backend) must not become an empty credential that then reads
    // as "revoked" on every report.
    throw new Error("enrollment failed: the response carried no device credential");
  }
  // "with" records which enrollment token issued this credential. A refused
  // credential is re-enrolled only once the policy carries a different token
  // (see report), so revoking a profile sticks until an operator rotates it.
  const enrollment = { cred: body.device_token, installId: installId, with: cfg.authToken };
  await api.storage.local.set({ [ENROLLMENT_KEY]: enrollment });
  console.log("[ai-account-guard] enrolled as " + serial);
  return enrollment;
}

// The bearer for this report, and the enrollment it came from (null when the
// policy carries a shared token and there is nothing to re-enroll).
async function resolveBearer(cfg) {
  if (!cfg.authToken.startsWith(ENROLL_PREFIX)) {
    return { bearer: cfg.authToken, enrollment: null };
  }
  let enrollment = await storedEnrollment();
  if (!enrollment || !enrollment.cred) enrollment = await enrollOnce(cfg, enrollment);
  return { bearer: enrollment.cred, enrollment: enrollment };
}

// After a 401 on a device credential. Another caller may already have
// re-enrolled between our read and our refusal, so storage is read again
// first: a credential that differs from the refused one is the answer.
async function reenroll(cfg, refusedCred) {
  const current = await storedEnrollment();
  if (current && current.cred && current.cred !== refusedCred) return current;
  return enrollOnce(cfg, current);
}

function post(endpoint, bearer, payload) {
  const headers = { "Content-Type": "application/json",
                    "X-AiGuard-Agent-Version": AGENT_VERSION };
  if (bearer) headers["Authorization"] = "Bearer " + bearer;
  return fetch(endpoint, { method: "POST", headers: headers, body: JSON.stringify(payload) });
}

async function report(payload) {
  const cfg = await getConfig();
  payload.device = cfg.device;

  // Set here rather than at each call site: three callers had three chances
  // to forget it, and all three did. The receiver coerced the missing field
  // to "unknown", so every browser finding was unattributable to an OS and
  // nothing said why.
  if (!payload.os) payload.os = await detectOs();

  if (!cfg.endpoint) {
    // No endpoint set (e.g. loaded unpacked with no MDM config). Surface the
    // flag in the service worker console so local testing is visible.
    console.log("[ai-account-guard] FLAG (no endpoint set):", payload);
    return false;
  }

  let { bearer, enrollment } = await resolveBearer(cfg);
  let response = await post(cfg.endpoint, bearer, payload);

  if (response.status === 401 && enrollment) {
    // This profile's own credential was refused: revoked on the receiver, or
    // reissued to another enrollment of the same serial. It re-enrolls only
    // if the policy now carries a different enrollment token than the one
    // this credential came from - the browser analogue of the collector's
    // "delete device.cred": revoking a profile sticks until an operator
    // rotates the token, rather than being undone by the next heartbeat.
    if (cfg.authToken === enrollment.with) {
      throw new Error("receiver refused this profile's device credential (revoked?);"
                      + " it re-enrolls when the policy carries a new enrollment token");
    }
    console.warn("[ai-account-guard] device credential refused and the enrollment token"
                 + " has changed: re-enrolling");
    enrollment = await reenroll(cfg, bearer);
    response = await post(cfg.endpoint, enrollment.cred, payload);
  }

  // fetch only rejects on a network-level failure, so a 401 or a 500 arrives
  // here looking like success unless the status is checked.
  if (!response.ok) {
    throw new Error("receiver returned HTTP " + response.status);
  }

  // The policy token rotated (the 180-day TTL makes that routine) while
  // this credential kept working: record the current token as the one this
  // credential stands under. Otherwise a rotation months before a revoke
  // would count as the rotation *after* it, and the revoke would not stick.
  if (enrollment && enrollment.with !== cfg.authToken) {
    try {
      await api.storage.local.set({ [ENROLLMENT_KEY]: { ...enrollment, with: cfg.authToken } });
    } catch (e) { /* next success tries again */ }
  }
  return true;
}