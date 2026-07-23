// AI Guard - content script
// Runs on each supported AI tool, resolves the signed-in account,
// discards the local part immediately, and flags if the domain is not allowed.

const FALLBACK_ALLOWED = ["example.com"];

// Per-tool resolvers. Each returns an email string or null.
// IMPORTANT: these hit undocumented internal endpoints / DOM. Confirm each
// one in devtools per tool and re-check after any vendor UI change.
const RESOLVERS = {
  "chatgpt.com": resolveChatGPT,
  "chat.openai.com": resolveChatGPT,
  "claude.ai": resolveClaude,
  "gemini.google.com": resolveGemini,
  "otter.ai": resolveOtter,
  "www.otter.ai": resolveOtter,
  "fireflies.ai": resolveFireflies,
  "app.fireflies.ai": resolveFireflies,
  "copilot.microsoft.com": resolveMsCopilot,
};

async function resolveChatGPT() {
  // NextAuth session endpoint, same-origin so the page cookies attach.
  const res = await fetch("/api/auth/session", { credentials: "include" });
  if (!res.ok) return null;
  const data = await res.json();
  return (data && data.user && data.user.email) || null;
}

async function resolveClaude() {
  // VERIFY: confirm the current-account endpoint and field name in devtools.
  // If the endpoint shape changes, the DOM fallback below picks it up.
  try {
    const res = await fetch("/api/auth/current_account", { credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      if (data && data.email) return data.email;
    }
  } catch (e) { /* fall through to DOM */ }
  return resolveFromAnyElement('[data-testid*="email"], [class*="email"]');
}

function resolveGemini() {
  // Google one-bar exposes the account in an aria-label such as
  // "Google Account: Name (name@domain)". Network-layer enforcement via
  // X-GoogApps-Allowed-Domains is cleaner for Google, but this catches it too.
  return resolveFromAnyElement('a[aria-label*="@"], [aria-label*="@"]');
}

function resolveOtter() {
  // CONFIRMED: Otter renders the account email in the sidebar account switcher
  // as a standalone leaf element. It is only visually truncated via the
  // "truncate" CSS class; textContent holds the full address. Its classes are
  // generic Tailwind utilities, so match on shape (a leaf whose entire text is
  // an email) rather than class names.
  return resolveExactEmailLeaf();
}

function resolveFireflies() {
  // VERIFY: try the account/settings selectors first, then fall back to the
  // shape-based leaf match (same approach confirmed working for Otter).
  return (
    resolveFromAnyElement(
      '[class*="email"], [class*="account"], [class*="user"], [aria-label*="@"]'
    ) || resolveExactEmailLeaf()
  );
}

function resolveMsCopilot() {
  // VERIFY: catches the CONSUMER Copilot (copilot.microsoft.com) signed in with
  // a personal Microsoft account. The work M365 Copilot is Entra-based and runs
  // in-app, so it is not covered here. Selectors first, then shape-based leaf.
  return (
    resolveFromAnyElement(
      '[aria-label*="@"], [class*="account"], [class*="email"], [data-testid*="account"]'
    ) || resolveExactEmailLeaf()
  );
}

function resolveFromAnyElement(selector) {
  const nodes = document.querySelectorAll(selector);
  for (const node of nodes) {
    const hay = (node.getAttribute("aria-label") || "") + " " + (node.textContent || "");
    const m = hay.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/);
    if (m) return m[0];
  }
  return null;
}

// Shape-based resolver: find a leaf element whose ENTIRE trimmed text is an
// email. Account/profile fields hold the address on its own; an address inside
// a transcript or chat body is embedded in a longer string and is ignored.
// Independent of class names, so it survives vendor UI churn.
function resolveExactEmailLeaf() {
  const exact = /^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$/;
  const nodes = document.querySelectorAll("div, span, p, a, button, li");
  for (const node of nodes) {
    if (node.childElementCount) continue;
    const txt = (node.textContent || "").trim();
    if (exact.test(txt)) return txt;
  }
  return null;
}

function domainOf(email) {
  const at = email.lastIndexOf("@");
  return at === -1 ? null : email.slice(at + 1).toLowerCase();
}

async function getAllowedDomains() {
  try {
    const cfg = await chrome.storage.managed.get("allowedDomains");
    if (cfg && Array.isArray(cfg.allowedDomains) && cfg.allowedDomains.length) {
      return cfg.allowedDomains.map((d) => d.toLowerCase());
    }
  } catch (e) { /* managed storage not set, use fallback */ }
  return FALLBACK_ALLOWED;
}

async function check() {
  const host = location.hostname;
  const resolver = RESOLVERS[host];
  if (!resolver) return;

  let email = null;
  try { email = await resolver(); } catch (e) { return; }
  if (!email) return;

  const domain = domainOf(email); // local part is dropped here and never leaves the page
  if (!domain) return;

  const allowed = await getAllowedDomains();
  if (allowed.includes(domain)) return;

  chrome.runtime.sendMessage({
    type: "personal-account",
    tool: host,
    domain: domain,            // e.g. "gmail.com" for context, no name
    ts: new Date().toISOString(),
  });
}

// SPAs swap accounts without a full reload, so check on load and on an interval.
// The early staggered checks catch SPA hydration so a live test fires in seconds.
check();
[3000, 10000, 30000].forEach((d) => setTimeout(check, d));
setInterval(check, 5 * 60 * 1000);
