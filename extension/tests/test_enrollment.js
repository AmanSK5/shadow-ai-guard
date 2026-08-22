// Managed mode: the policy's authToken may be an enrollment token, and the
// profile must exchange it once for its own credential and then behave like a
// device - same contract as the endpoint collectors.
//
// What is asserted, in order:
//   - an aige_ token is never sent to /report; /enroll is called once, with
//     platform "browser" and a serial of <deviceIdentifier>/<install id>, and
//     the credential it returns is what every later report carries
//   - the credential survives a worker restart (storage.local), so a second
//     boot does not enroll again
//   - two reports racing on a fresh profile share one enrollment
//   - a 401 on the credential with the SAME policy token does not re-enroll:
//     revoking a profile sticks until an operator rotates the token
//   - a 401 with a DIFFERENT policy token re-enrolls, keeps the install id
//     (same serial, same device on the receiver) and retries the report
//   - a shared token is sent as-is, with no /enroll traffic
//   - a reportEndpoint that does not end in /report cannot enroll, loudly
//
// No test framework, same as the other two. Run it with:
//     node extension/tests/test_enrollment.js

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "src", "background.js"), "utf8");

function makeStorage(backing) {
  return {
    get: (key) => Promise.resolve(key in backing ? { [key]: backing[key] } : {}),
    set: (obj) => { Object.assign(backing, obj); return Promise.resolve(); },
  };
}

// Boot the worker against a managed config and a scripted receiver.
// `receiver(url, opts)` returns {status, body}; every call is recorded.
function boot(localBacking, managed, receiver) {
  const calls = [];
  let onMessage = null, onStartup = null;
  const api = {
    storage: {
      session: makeStorage({}),
      local: makeStorage(localBacking),
      managed: { get: () => Promise.resolve(managed) },
    },
    runtime: {
      onMessage: { addListener: (fn) => { onMessage = fn; } },
      onStartup: { addListener: (fn) => { onStartup = fn; } },
      onInstalled: { addListener: () => {} },
      getManifest: () => ({ version: "9.9.9" }),
      getPlatformInfo: () => Promise.resolve({ os: "mac" }),
    },
    alarms: { create: () => {}, onAlarm: { addListener: () => {} } },
  };
  const fetch = (url, opts) => {
    const call = { url, headers: opts.headers, body: JSON.parse(opts.body) };
    calls.push(call);
    const r = receiver(url, call);
    return Promise.resolve({
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      json: () => Promise.resolve(r.body || {}),
    });
  };
  new Function("globalThis", "fetch", "console", src).call({},
    { browser: api }, fetch, { warn: () => {}, log: () => {} });
  return {
    calls,
    flag: (tool) => onMessage({ type: "paste-guard", tool, action: "blocked", detectors: ["x"], ts: "t" }),
    startup: () => onStartup(),
  };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 20; i++) await tick(); }

const POLICY = { reportEndpoint: "https://r.example/report", deviceIdentifier: "C02DEV1",
                 authToken: "aige_first" };

// A receiver that enrolls anyone and accepts any aigd_ credential it issued.
function happyReceiver() {
  const issued = new Set();
  let n = 0;
  return {
    issued,
    handle: (url, call) => {
      if (url.endsWith("/enroll")) {
        const cred = "aigd_" + (++n);
        issued.add(cred);
        return { status: 200, body: { device_id: "d1", device_token: cred } };
      }
      const bearer = (call.headers.Authorization || "").replace("Bearer ", "");
      return { status: issued.has(bearer) ? 200 : 401 };
    },
  };
}

(async () => {
  // ---- first run enrolls once, then reports with the credential ----------
  {
    const rx = happyReceiver();
    const local = {};
    const w = boot(local, POLICY, rx.handle);
    w.flag("chatgpt.com");
    await settle();
    w.flag("claude.ai");
    await settle();

    const enrolls = w.calls.filter((c) => c.url.endsWith("/enroll"));
    const reports = w.calls.filter((c) => c.url.endsWith("/report"));
    assert.strictEqual(enrolls.length, 1, "exactly one enrollment");
    assert.strictEqual(enrolls[0].headers.Authorization, "Bearer aige_first");
    assert.strictEqual(enrolls[0].body.platform, "browser");
    assert.match(enrolls[0].body.serial, /^C02DEV1\/[0-9a-f]{8}$/, "serial is device id + install id");
    assert.strictEqual(enrolls[0].body.agent_version, "9.9.9");
    assert.strictEqual(reports.length, 2);
    for (const r of reports) {
      assert.strictEqual(r.headers.Authorization, "Bearer aigd_1", "reports carry the credential");
      assert.strictEqual(r.headers["X-AiGuard-Agent-Version"], "9.9.9");
      assert.strictEqual(r.body.device, "C02DEV1");
    }
    assert.strictEqual(local.enrollment.cred, "aigd_1");
    assert.strictEqual(local.enrollment.with, "aige_first");

    // ---- restart: credential comes from storage, no second enrollment ----
    const w2 = boot(local, POLICY, rx.handle);
    w2.flag("gemini.google.com");
    await settle();
    assert.strictEqual(w2.calls.filter((c) => c.url.endsWith("/enroll")).length, 0,
      "a restarted worker reuses the stored credential");
    assert.strictEqual(w2.calls[0].headers.Authorization, "Bearer aigd_1");
  }

  // ---- concurrent first reports share one enrollment ---------------------
  {
    const rx = happyReceiver();
    const w = boot({}, POLICY, rx.handle);
    w.flag("a.example"); w.flag("b.example"); w.flag("c.example");
    await settle();
    assert.strictEqual(w.calls.filter((c) => c.url.endsWith("/enroll")).length, 1,
      "three racing reports, one enrollment");
    assert.strictEqual(w.calls.filter((c) => c.url.endsWith("/report")).length, 3);
  }

  // ---- revoked, same policy token: stays refused, no re-enroll -----------
  {
    const rx = happyReceiver();
    const local = { enrollment: { cred: "aigd_revoked", installId: "deadbeef", with: "aige_first" } };
    const w = boot(local, POLICY, rx.handle);
    w.startup();  // heartbeat: observable through lastHeartbeat
    await settle();
    assert.strictEqual(w.calls.filter((c) => c.url.endsWith("/enroll")).length, 0,
      "no re-enrollment while the policy still carries the token this credential came from");
    assert.strictEqual(local.lastHeartbeat, undefined, "the refused heartbeat is not recorded as delivered");
    assert.strictEqual(local.enrollment.cred, "aigd_revoked", "state untouched");
  }

  // ---- revoked, rotated policy token: re-enrolls, same install id, retries -
  {
    const rx = happyReceiver();
    const local = { enrollment: { cred: "aigd_revoked", installId: "deadbeef", with: "aige_first" } };
    const rotated = { ...POLICY, authToken: "aige_second" };
    const w = boot(local, rotated, rx.handle);
    w.startup();
    await settle();
    const enrolls = w.calls.filter((c) => c.url.endsWith("/enroll"));
    assert.strictEqual(enrolls.length, 1, "one re-enrollment");
    assert.strictEqual(enrolls[0].headers.Authorization, "Bearer aige_second");
    assert.strictEqual(enrolls[0].body.serial, "C02DEV1/deadbeef", "install id kept: same profile on the receiver");
    const reports = w.calls.filter((c) => c.url.endsWith("/report"));
    assert.deepStrictEqual(reports.map((r) => r.headers.Authorization),
      ["Bearer aigd_revoked", "Bearer aigd_1"], "refused, re-enrolled, retried");
    assert.ok(local.lastHeartbeat, "the retried heartbeat counts as delivered");
    assert.strictEqual(local.enrollment.with, "aige_second");
  }

  // ---- rotation while the credential still works re-stamps "with" --------
  {
    const rx = happyReceiver();
    rx.issued.add("aigd_live");
    const local = { enrollment: { cred: "aigd_live", installId: "deadbeef", with: "aige_first" } };
    const w = boot(local, { ...POLICY, authToken: "aige_second" }, rx.handle);
    w.flag("chatgpt.com");
    await settle();
    assert.strictEqual(w.calls.filter((c) => c.url.endsWith("/enroll")).length, 0,
      "a working credential is not re-enrolled on rotation");
    assert.strictEqual(local.enrollment.with, "aige_second",
      "the credential now stands under the current token, so a later revoke sticks");
    assert.strictEqual(local.enrollment.cred, "aigd_live");
  }

  // ---- a 200 without a credential is an enrollment failure, not a cred ---
  {
    const local = {};
    const w = boot(local, POLICY, (url) => url.endsWith("/enroll")
      ? { status: 200, body: { hello: "captive portal" } } : { status: 200 });
    w.startup();
    await settle();
    assert.strictEqual(local.enrollment, undefined, "nothing stored");
    assert.strictEqual(w.calls.filter((c) => c.url.endsWith("/report")).length, 0, "no report without a credential");
    assert.strictEqual(local.lastHeartbeat, undefined);
  }

  // ---- a query string on the endpoint is fine ----------------------------
  {
    const rx = happyReceiver();
    const w = boot({}, { ...POLICY, reportEndpoint: "https://r.example/report?src=ext" }, rx.handle);
    w.flag("chatgpt.com");
    await settle();
    assert.deepStrictEqual(w.calls.map((c) => c.url),
      ["https://r.example/enroll", "https://r.example/report?src=ext"]);
  }

  // ---- shared token: unchanged behaviour ---------------------------------
  {
    const w = boot({}, { ...POLICY, authToken: "shared-secret" }, () => ({ status: 200 }));
    w.flag("chatgpt.com");
    await settle();
    assert.strictEqual(w.calls.length, 1);
    assert.strictEqual(w.calls[0].url, "https://r.example/report");
    assert.strictEqual(w.calls[0].headers.Authorization, "Bearer shared-secret");
  }

  // ---- endpoint without /report: cannot derive /enroll, nothing is sent ---
  {
    const local = {};
    const w = boot(local, { ...POLICY, reportEndpoint: "https://r.example/ingest" }, () => ({ status: 200 }));
    w.startup();
    await settle();
    assert.strictEqual(w.calls.length, 0, "no enrollment token is ever sent to an unknown path");
    assert.strictEqual(local.lastHeartbeat, undefined);
  }

  console.log("ok - enrollment");
})().catch((e) => { console.error(e); process.exit(1); });
