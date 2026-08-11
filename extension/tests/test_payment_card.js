// Payment card detector: real card formats only, not any run of digits.
//
// The detector fired on SVG path and polygon data. The old pattern allowed a
// separator after every single digit, so `points="12 2 15 8 22 9 17 14"` was a
// candidate, and Luhn passes 10% of arbitrary digit runs so it filtered almost
// nothing. Measured over 50,000 generated samples of path data, phone numbers,
// timestamps and reference numbers: 5.97% flagged before the fix, 0% after,
// with every real format from 13 to 19 digits still detected.
//
// No test framework: the extension has no build step and no package.json, and
// one file does not justify the dependency. Run it with:
//     node extension/tests/test_payment_card.js
//
// guard.js is a content script with no exports, so it is evaluated here against
// stubbed browser globals and the functions are picked off afterwards. That is
// less brittle than matching function bodies out of the source text.

const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "src", "guard.js"), "utf8");

// Enough of the browser for the module body to run. Nothing here is exercised
// by the tests; it exists so the top-level statements do not throw.
// guard.js resolves its namespace as globalThis.browser ?? globalThis.chrome,
// so the stub has to live on globalThis. Declaring it as a local const would
// leave api undefined and the module-level calls would fail as silent rejected
// promises while these tests still passed.
const stubs = `
  globalThis.browser = { storage: { managed: { get: () => Promise.resolve({}) } },
                         runtime: { sendMessage: () => Promise.resolve() } };
  const document = { addEventListener: () => {}, getElementById: () => null,
                     createElement: () => ({ style: {}, appendChild: () => {},
                       addEventListener: () => {}, remove: () => {} }),
                     documentElement: { appendChild: () => {} },
                     activeElement: null };
  const location = { hostname: "test" };
  const window = { getSelection: () => ({ rangeCount: 0 }) };
  const setInterval = () => 0;
  const setTimeout = () => 0;
`;

const ctx = {};
new Function(
  stubs + "\n" + src + "\n" +
  "this.hasPaymentCard = hasPaymentCard; this.luhnOk = luhnOk; this.scan = scan;"
).call(ctx);

const { hasPaymentCard, luhnOk } = ctx;

let pass = 0, fail = 0;
function check(name, got, want) {
  if (got === want) { pass++; console.log("  ok:   " + name); }
  else { fail++; console.log("  FAIL: " + name + " (got " + got + ", want " + want + ")"); }
}

// Build a Luhn-valid number of a given length, so no test depends on a real
// card having existed.
function mkCard(prefix, len) {
  let body = prefix, seed = 7;
  while (body.length < len - 1) { seed = (seed * 31 + 17) % 10; body += seed; }
  for (let c = 0; c <= 9; c++) if (luhnOk(body + String(c))) return body + String(c);
  throw new Error("no valid check digit for " + body);
}
const group = (s, n) => s.replace(new RegExp("(\\d{" + n + "})(?=\\d)", "g"), "$1 ");

const c13 = mkCard("4", 13), c16 = mkCard("4", 16), c19 = mkCard("6", 19);

console.log("payment card detector");

check("16 digits, unbroken", hasPaymentCard(c16), true);
check("16 digits, grouped in fours", hasPaymentCard(group(c16, 4)), true);
check("16 digits, hyphenated", hasPaymentCard(group(c16, 4).replace(/ /g, "-")), true);
check("13 digits, unbroken", hasPaymentCard(c13), true);
check("19 digits, unbroken", hasPaymentCard(c19), true);
check("19 digits, grouped 4-4-4-4-3", hasPaymentCard(group(c19, 4)), true);
check("Amex, grouped 4-6-5", hasPaymentCard("3782 822463 10005"), true);
check("Diners, grouped 4-6-4", hasPaymentCard("3056 930902 5904"), true);
check("card embedded in a sentence",
  hasPaymentCard("card on file: " + group(c16, 4) + " exp 12/28"), true);
check("card in a CSV row", hasPaymentCard(c16 + ",visa,12/28"), true);

check("SVG polygon points",
  hasPaymentCard('<polygon points="12 2 15 8 22 9 17 14 18 21 12 18 6 21 7 14 2 9 9 8"/>'), false);
check("SVG path coordinate pairs",
  hasPaymentCard('<path d="M 10 20 L 30 40 L 50 60 L 70 80 L 90 100 L 110 120 L 130 140"/>'), false);
check("SVG transform matrix",
  hasPaymentCard('transform="matrix(1 0 0 1 12 34)" d="M 1 2 3 4 5 6 7 8 9 0 1 2 3 4"'), false);
check("three-digit coordinate run",
  hasPaymentCard('points="100 200 300 400 500 600"'), false);
check("UK phone numbers", hasPaymentCard("020 7946 0018 and 020 7946 0019"), false);
check("timestamps", hasPaymentCard("2026-08-11 14:23:07 2026-08-12 09:15:44"), false);
check("mixed separators are not a card format",
  hasPaymentCard("4111-1111 1111-1111"), false);

// The Luhn gate still has to do its job.
check("16 digits failing Luhn", hasPaymentCard("4111111111111112"), false);

// CARD_RE is module-level with /g, so lastIndex persists between calls. A
// second call on the same input must give the same answer.
const twice = group(c16, 4);
check("repeat call gives the same answer",
  hasPaymentCard(twice) && hasPaymentCard(twice), true);

console.log("\npassed: " + pass + "  failed: " + fail);
process.exit(fail ? 1 : 0);
