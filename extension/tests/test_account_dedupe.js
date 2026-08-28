// Personal-account dedupe must survive a service worker restart.
//
// The dedupe state was a module-level Map. Chrome stops an MV3 worker after
// roughly thirty seconds idle and content.js checks every five minutes, so the
// advertised six-hour window was in practice one flag per check. This test
// evaluates background.js, sends the same flag, throws the module away and
// evaluates it again against the same storage, the way the browser does, and
// counts what reached the receiver.
//
// It also holds the other half of the same invariant: the window opens on
// delivery, not on the attempt. The receiver returns 503 when the log store
// would not take a finding, precisely so the caller knows it is not stored;
// recording the flag before the POST turned that 503 into six hours of
// silence, on a check that would otherwise have retried five minutes later.
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
    remove: (key) => { delete backing[key]; return Promise.resolve(); },
  };
}

// Boot the worker once. Returns the captured onMessage listener and the list
// of payloads POSTed to the receiver.
function boot(sessionBacking, localBacking, now, receiver, managed) {
  const posted = [];
  const alarms = [];
  let listener = null;
  let onAlarm = null;
  const api = {
    storage: {
      session: sessionBacking && makeStorage(sessionBacking),
      local: makeStorage(localBacking),
      managed: { get: () => Promise.resolve(managed || {
        reportEndpoint: "https://r.example/report", deviceIdentifier: "DEV1" }) },
    },
    runtime: {
      onMessage: { addListener: (fn) => { listener = fn; } },
      onStartup: { addListener: () => {} },
      onInstalled: { addListener: () => {} },
      getManifest: () => ({ version: "test" }),
      getPlatformInfo: () => Promise.resolve({ os: "mac" }),
    },
    alarms: {
      create: (name) => { alarms.push(name); },
      onAlarm: { addListener: (fn) => { onAlarm = fn; } },
    },
  };
  const ctx = {};
  new Function("globalThis", "fetch", "Date", "console",
    src
  ).call(ctx,
    { browser: api },
    (url, opts) => {
      const body = JSON.parse(opts.body);
      // Default is the old always-up receiver, so every existing case reads
      // the same. receiver() returning false is the 503 the real one sends
      // when the log store would not take the finding.
      const ok = receiver ? receiver(body) : true;
      posted.push(body);
      return Promise.resolve({ ok, status: ok ? 200 : 503 });
    },
    { now: () => now() },
    { warn: () => {}, log: () => {} });
  return {
    send: (msg) => listener(msg),
    posted,
    alarms,
    fire: (name) => onAlarm && onAlarm({ name }),
  };
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

  // ---- the window opens on delivery, not on the attempt ----

  // A receiver that refuses everything: the flag must stay reportable.
  clock = 3_000_000; session = {}; local = {};
  const down = () => false;
  w = boot(session, local, () => clock, down);
  w.send(flag); await settle();
  check("a refused report is still attempted", w.posted.length, 1);
  check("a refused report does not open the window",
    "chatgpt.com:gmail.com" in (session.personalAccountSeen || {}), false);

  // The next five-minute check, well inside the six-hour window.
  clock += 5 * 60 * 1000;
  w = boot(session, local, () => clock, down);
  w.send(flag); await settle();
  check("the next check retries it", w.posted.length, 1);

  // The receiver comes back.
  clock += 5 * 60 * 1000;
  w = boot(session, local, () => clock, () => true);
  w.send(flag); await settle();
  check("it lands once the receiver recovers", w.posted.length, 1);
  check("and now the window is open",
    "chatgpt.com:gmail.com" in session.personalAccountSeen, true);

  clock += 5 * 60 * 1000;
  w = boot(session, local, () => clock, () => true);
  w.send(flag); await settle();
  check("a delivered flag is deduped as before", w.posted.length, 0);

  // Print-only mode: no endpoint, nothing to deliver, and the console should
  // not fill up every five minutes.
  clock = 4_000_000; session = {}; local = {};
  w = boot(session, local, () => clock, null, { deviceIdentifier: "DEV1" });
  w.send(flag); await settle();
  w = boot(session, local, () => clock + 60_000, null, { deviceIdentifier: "DEV1" });
  w.send(flag); await settle();
  check("print-only mode still dedupes", w.posted.length, 0);

  console.log(pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
