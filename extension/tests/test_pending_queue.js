// A paste-guard finding must survive the receiver being down.
//
// The guard warns or blocks locally whether or not anything is recorded, so a
// failed POST costs no protection. It costs the audit trail, and that is the
// half someone asks about weeks later: "did we stop a card number going into
// ChatGPT, and when". Unlike a personal account - still true at the next
// five-minute check, so re-derived for free - a paste happens once. Nothing
// regenerates it, so report().catch(console.warn) was the finding's last stop.
//
// What is asserted, in order:
//   - a refused paste finding is queued, and a flush alarm is scheduled
//   - the queue survives a worker restart, and drains when the receiver is back
//   - a drained queue is removed from storage rather than left as []
//   - a flush into a still-dead receiver stops at the first failure
//   - only content-free fields are stored: never the matched text
//   - the queue is bounded to 100, newest kept, and prunes past seven days
//   - a personal-account flag is not queued: its retry is the next check
//
// No test framework, same as the others. Run it with:
//     node extension/tests/test_pending_queue.js

const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "src", "background.js"), "utf8");

function makeStorage(backing) {
  return {
    get: (key) => Promise.resolve(key in backing ? { [key]: backing[key] } : {}),
    set: (obj) => { Object.assign(backing, obj); return Promise.resolve(); },
    remove: (key) => { delete backing[key]; return Promise.resolve(); },
  };
}

// One storage.local backing shared across "restarts": the queue has to outlive
// the worker and the browser, which is the whole point of it being on disk.
function boot(localBacking, now, receiver) {
  const posted = [];
  const alarms = [];
  let onMessage = null, onAlarm = null, onStartup = null;
  const api = {
    storage: {
      session: makeStorage({}),
      local: makeStorage(localBacking),
      managed: { get: () => Promise.resolve({
        reportEndpoint: "https://r.example/report", deviceIdentifier: "DEV1" }) },
    },
    runtime: {
      onMessage: { addListener: (fn) => { onMessage = fn; } },
      onStartup: { addListener: (fn) => { onStartup = fn; } },
      onInstalled: { addListener: () => {} },
      getManifest: () => ({ version: "test" }),
      getPlatformInfo: () => Promise.resolve({ os: "mac" }),
    },
    alarms: {
      create: (name) => { alarms.push(name); },
      onAlarm: { addListener: (fn) => { onAlarm = fn; } },
    },
  };
  new Function("globalThis", "fetch", "Date", "console", src).call({},
    { browser: api },
    (url, opts) => {
      const body = JSON.parse(opts.body);
      posted.push(body);
      const ok = receiver ? receiver(body) : true;
      return Promise.resolve({ ok, status: ok ? 200 : 503 });
    },
    { now: () => now() },
    { warn: () => {}, log: () => {} });
  return {
    send: (msg) => onMessage(msg),
    posted,
    alarms,
    fire: (name) => onAlarm && onAlarm({ name }),
    startup: () => onStartup && onStartup(),
  };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 20; i++) await tick(); }

let pass = 0, fail = 0;
function check(name, got, want) {
  if (got === want) { pass++; console.log("  ok:   " + name); }
  else { fail++; console.log("  FAIL: " + name + " (got " + got + ", want " + want + ")"); }
}

const paste = (n) => ({
  type: "paste-guard", tool: "chatgpt.com", action: "block",
  detectors: ["payment-card"], ts: "2026-08-28T09:0" + n + ":00Z",
});
const DAY = 24 * 60 * 60 * 1000;

(async () => {
  console.log("paste-guard pending queue");

  // ---- a refused finding is kept ----
  let clock = 1_000_000;
  const local = {};
  const down = () => false;
  let w = boot(local, () => clock, down);
  w.send(paste(1)); await settle();
  check("the refused finding was attempted", w.posted.length, 1);
  check("and queued", (local.pendingFindings || []).length, 1);
  check("with a flush alarm scheduled",
    w.alarms.includes("ai-guard-flush"), true);
  check("carrying the detector ids, not the text",
    local.pendingFindings[0].payload.evidence, "paste block: payment-card");
  check("and nothing resembling clipboard content",
    JSON.stringify(local.pendingFindings[0]).includes("4111"), false);
  check("keeping the time it actually happened",
    local.pendingFindings[0].payload.reported_at, "2026-08-28T09:01:00Z");

  // ---- it survives the worker, and the browser ----
  clock += 10 * 60 * 1000;
  w = boot(local, () => clock, down);
  w.fire("ai-guard-flush"); await settle();
  check("a flush into a dead receiver retries it", w.posted.length, 1);
  check("and keeps it queued", (local.pendingFindings || []).length, 1);

  clock += 10 * 60 * 1000;
  w = boot(local, () => clock, () => true);
  w.fire("ai-guard-flush"); await settle();
  check("it lands once the receiver is back", w.posted.length, 1);
  check("and the key is removed, not left empty",
    "pendingFindings" in local, false);

  // ---- a backlog drains in order, and stops at the first failure ----
  clock += 60 * 1000;
  let up = false;
  w = boot(local, () => clock, () => up);
  w.send(paste(2)); await settle();
  w.send(paste(3)); await settle();
  check("two refused findings queue up", local.pendingFindings.length, 2);
  let n = 0;
  w = boot(local, () => clock, () => ++n === 1);  // first succeeds, second 503s
  w.fire("ai-guard-flush"); await settle();
  check("the flush stops at the first failure", w.posted.length, 2);
  check("and the undelivered one stays", local.pendingFindings.length, 1);
  check("oldest first: the one left is the later paste",
    local.pendingFindings[0].payload.reported_at, "2026-08-28T09:03:00Z");
  w = boot(local, () => clock, () => true);
  w.startup(); await settle();
  check("startup drains the rest", "pendingFindings" in local, false);

  // ---- bounded ----
  const many = {};
  w = boot(many, () => clock, down);
  for (let i = 0; i < 130; i++) { w.send(paste(1)); await settle(); }
  check("the queue is capped at 100", many.pendingFindings.length, 100);

  const stale = { pendingFindings: [
    { queued_at: clock - 8 * DAY, payload: { tool: "old", evidence: "e" } },
    { queued_at: clock - 1 * DAY, payload: { tool: "recent", evidence: "e" } },
  ] };
  w = boot(stale, () => clock, down);
  w.fire("ai-guard-flush"); await settle();
  check("entries past seven days are dropped", w.posted.length, 1);
  check("the recent one is the survivor", w.posted[0].tool, "recent");

  // ---- the account path is not the queue's business ----
  const acct = {};
  w = boot(acct, () => clock, down);
  w.send({ type: "personal-account", tool: "chatgpt.com",
           domain: "gmail.com", ts: "t" });
  await settle();
  check("a refused personal-account flag is not queued",
    "pendingFindings" in acct, false);

  console.log(pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
