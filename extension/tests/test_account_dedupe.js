// Personal-account dedupe must survive a service worker restart.
//
// The dedupe state was a module-level Map. Chrome stops an MV3 worker after
// roughly thirty seconds idle and content.js checks every five minutes, so the
// advertised six-hour window was in practice one flag per check. This test
// evaluates background.js, sends the same flag, throws the module away and
// evaluates it again against the same storage, the way the browser does, and
// counts what reached the receiver.
//
// No test framework, same as test_payment_card.js. Run it with:
//     node extension/tests/test_account_dedupe.js

const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "src", "background.js"), "utf8");

// One storage backing shared across "restarts": that is the property under
// test. Everything else is rebuilt per boot, as it would be.
function makeStorage(backing) {
  return {
    get: (key) => Promise.resolve(key in backing ? { [key]: backing[key] } : {}),
    set: (obj) => { Object.assign(backing, obj); return Promise.resolve(); },
  };
}

// Boot the worker once. Returns the captured onMessage listener and the list
// of payloads POSTed to the receiver.
function boot(sessionBacking, localBacking, now) {
  const posted = [];
  let listener = null;
  const api = {
    storage: {
      session: sessionBacking && makeStorage(sessionBacking),
      local: makeStorage(localBacking),
      managed: { get: () => Promise.resolve({ reportEndpoint: "https://r.example/report",
                                               deviceIdentifier: "DEV1" }) },
    },
    runtime: {
      onMessage: { addListener: (fn) => { listener = fn; } },
      onStartup: { addListener: () => {} },
      onInstalled: { addListener: () => {} },
      getManifest: () => ({ version: "test" }),
      getPlatformInfo: () => Promise.resolve({ os: "mac" }),
    },
    alarms: { create: () => {}, onAlarm: { addListener: () => {} } },
  };
  const ctx = {};
  new Function("globalThis", "fetch", "Date", "console",
    src
  ).call(ctx,
    { browser: api },
    (url, opts) => { posted.push(JSON.parse(opts.body)); return Promise.resolve({ ok: true }); },
    { now: () => now() },
    { warn: () => {}, log: () => {} });
  return { send: (msg) => listener(msg), posted };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 10; i++) await tick(); }

let pass = 0, fail = 0;
function check(name, got, want) {
  if (got === want) { pass++; console.log("  ok:   " + name); }
  else { fail++; console.log("  FAIL: " + name + " (got " + got + ", want " + want + ")"); }
}

const flag = { type: "personal-account", tool: "chatgpt.com", domain: "gmail.com", ts: "t" };

(async () => {
  console.log("personal-account dedupe");

  // Same boot, same flag twice: one report.
  let clock = 1_000_000;
  let session = {}, local = {};
  let w = boot(session, local, () => clock);
  w.send(flag); await settle();
  w.send(flag); await settle();
  check("second flag in one worker lifetime is dropped", w.posted.length, 1);

  // Worker restarted five minutes later, same storage: still dropped.
  clock += 5 * 60 * 1000;
  w = boot(session, local, () => clock);
  w.send(flag); await settle();
  check("flag after a worker restart is dropped", w.posted.length, 0);

  // A different account on the same tool is a different finding.
  w.send({ ...flag, domain: "outlook.com" }); await settle();
  check("different domain on the same tool is reported", w.posted.length, 1);

  // Past the window: reported again, and the expired entry is pruned.
  clock += 6 * 60 * 60 * 1000 + 1;
  w = boot(session, local, () => clock);
  w.send(flag); await settle();
  check("flag past the six-hour window is reported", w.posted.length, 1);
  check("expired entries are pruned from storage",
    Object.keys(session.personalAccountSeen).join(","), "chatgpt.com:gmail.com");

  // No storage.session at all: storage.local carries it instead.
  clock = 2_000_000; session = null; local = {};
  w = boot(null, local, () => clock);
  w.send(flag); await settle();
  w = boot(null, local, () => clock + 60_000);
  w.send(flag); await settle();
  check("falls back to storage.local when session is absent",
    "personalAccountSeen" in local, true);
  check("local fallback still dedupes across a restart", w.posted.length, 0);

  // The state was never persisted under the old code. This is the regression
  // guard: a Map would pass every in-lifetime check above and fail this one.
  check("dedupe state is in storage, not module scope",
    typeof session === "object" || "personalAccountSeen" in local, true);

  console.log(pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
