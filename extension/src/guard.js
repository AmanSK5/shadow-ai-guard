// AI Guard - paste guard content script
// Intercepts paste/drop into AI tools, scans the text locally for secret
// patterns, and warns or blocks BEFORE the content reaches the page.
// The matched text NEVER leaves the page: reports carry detector ids only.

const FALLBACK_PASTE_MODE = "warn"; // off | warn | block (managed config wins)
const REPORT_DEDUPE_MS = 5 * 60 * 1000; // one report per tool+detector per 5m
const reported = new Map();

// Detector set, v1.1.0. Two shapes: { re } for pattern matches, { test } for
// detectors needing logic (checksums, counting). Entropy scanning and the
// org/client term list are deferred to v1.2 behind managed config.
//
// Deliberately excluded (false-positive rate would train people to ignore
// the overlay): UK sort codes (collide with dd-mm-yy dates), dates of birth,
// passport and driving licence numbers, single email addresses.

const BULK_EMAIL_THRESHOLD = 10;
const EMAIL_RE = /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g;

function luhnOk(digits) {
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

function hasPaymentCard(text) {
  const re = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const digits = m[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) return true;
  }
  return false;
}

const FALLBACK_MARKINGS = [
  "client confidential",
  "internal confidential",
  "confidential internal",
  "internal use only",
  "strictly confidential",
  "commercial in confidence",
];
// Compound labels match case-insensitively; bare CONFIDENTIAL only in full
// caps (how classification stamps render), so prose and email disclaimer
// footers ("this email is confidential...") stay silent. Bare "internal" is
// undetectable by marking: it is everyday prose. The org term list planned
// for v1.2 covers that tier from the content side.
let markingRe = buildMarkingRe(FALLBACK_MARKINGS);
let markingCapsRe = /\bCONFIDENTIAL\b/;

function buildMarkingRe(labels) {
  const esc = labels
    .filter((l) => typeof l === "string" && l.trim())
    .map((l) => l.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+"));
  return esc.length ? new RegExp("\\b(?:" + esc.join("|") + ")\\b", "i") : null;
}

function hasClassificationMarking(text) {
  if (markingRe && markingRe.test(text)) return true;
  return markingCapsRe.test(text);
}

async function refreshMarkings() {
  try {
    const cfg = await chrome.storage.managed.get("classificationMarkings");
    if (cfg && Array.isArray(cfg.classificationMarkings) && cfg.classificationMarkings.length) {
      markingRe = buildMarkingRe(cfg.classificationMarkings);
    }
  } catch (e) { /* managed storage not set, fallback list stays */ }
}
refreshMarkings();
setInterval(refreshMarkings, 5 * 60 * 1000);

function hasBulkEmails(text) {
  const m = text.match(EMAIL_RE);
  if (!m) return false;
  return new Set(m.map((e) => e.toLowerCase())).size >= BULK_EMAIL_THRESHOLD;
}

const DETECTORS = [
  // --- developer credentials ---
  { id: "aws_access_key", label: "AWS access key",
    re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { id: "private_key", label: "private key",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "gitlab_pat", label: "GitLab personal access token",
    re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: "github_token", label: "GitHub token",
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: "anthropic_key", label: "Anthropic API key",
    re: /\bsk-ant-[A-Za-z0-9-]{20,}\b/ },
  { id: "openai_key", label: "OpenAI API key",
    re: /\bsk-[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]{10,}\b|\bsk-[A-Za-z0-9]{48}\b/ },
  { id: "slack_token", label: "Slack token",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "jwt", label: "JWT",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/ },
  { id: "google_api_key", label: "Google API key",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "azure_storage_secret", label: "Azure storage secret",
    re: /\b(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=%]{20,}/ },

  // --- marketing / SaaS platform credentials ---
  { id: "stripe_live_key", label: "Stripe live secret key",
    re: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/ },
  { id: "mailchimp_key", label: "Mailchimp API key",
    re: /\b[0-9a-f]{32}-us\d{1,2}\b/ },
  { id: "hubspot_token", label: "HubSpot access token",
    re: /\bpat-(?:na|eu)\d+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ },
  { id: "sendgrid_key", label: "SendGrid API key",
    re: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/ },
  { id: "meta_access_token", label: "Meta access token",
    re: /\bEAA[A-Za-z0-9]{30,}\b/ },

  // --- shared credentials ---
  { id: "password_assignment", label: "password",
    re: /(?:password|passwd|pwd|passcode)\s*[:=]\s*\S{4,}/i },

  // --- personal and financial data ---
  { id: "payment_card", label: "payment card number", test: hasPaymentCard },
  { id: "uk_nino", label: "National Insurance number",
    re: /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/ },
  { id: "iban", label: "IBAN",
    re: /\b(?:GB|IE|FR|DE|ES|IT|NL|BE|CH|PT|SE|DK|NO|PL|AT|FI|LU)\d{2}[A-Z0-9]{10,30}\b/ },
  { id: "bulk_emails", label: "bulk email list", test: hasBulkEmails },
  { id: "classification_marking", label: "classification marking",
    test: hasClassificationMarking },
];

function scan(text) {
  const hits = [];
  for (const d of DETECTORS) {
    const hit = d.re ? d.re.test(text) : d.test(text);
    if (hit) hits.push(d);
  }
  return hits;
}

async function getPasteMode() {
  try {
    const cfg = await chrome.storage.managed.get("pasteGuardMode");
    if (cfg && typeof cfg.pasteGuardMode === "string" &&
        ["off", "warn", "block"].includes(cfg.pasteGuardMode)) {
      return cfg.pasteGuardMode;
    }
  } catch (e) { /* managed storage not set, use fallback */ }
  return FALLBACK_PASTE_MODE;
}

// Cache the mode so the paste handler can act synchronously. preventDefault
// only works inside the event turn, so the decision cannot await anything.
let pasteMode = FALLBACK_PASTE_MODE;
getPasteMode().then((m) => { pasteMode = m; });
setInterval(() => { getPasteMode().then((m) => { pasteMode = m; }); }, 5 * 60 * 1000);

function isEditable(el) {
  if (!el) return false;
  if (el.isContentEditable) return true;
  const tag = (el.tagName || "").toLowerCase();
  return tag === "textarea" || tag === "input";
}

function handleCapture(event) {
  if (!event.isTrusted) return; // ignore synthetic events from page scripts
  if (pasteMode === "off") return;

  const dt = event.clipboardData || event.dataTransfer;
  if (!dt) return;
  const text = dt.getData("text/plain");
  if (!text) return; // image or file paste: out of scope for the text guard

  const target = event.target;
  if (!isEditable(target) && !isEditable(document.activeElement)) return;

  const hits = scan(text);
  if (!hits.length) return;

  // Stop the content reaching the page in both warn and block mode. Warn mode
  // then offers reinsertion; block mode does not.
  event.preventDefault();
  event.stopImmediatePropagation();

  const action = pasteMode === "block" ? "blocked" : "warned";
  showOverlay(hits, action, action === "warned" ? () => {
    reinsert(target, text);
    report(hits, "overridden");
  } : null);
  report(hits, action);
}

document.addEventListener("paste", handleCapture, true);
document.addEventListener("drop", handleCapture, true);

function reinsert(target, text) {
  const el = isEditable(target) ? target : document.activeElement;
  if (!el) return;
  el.focus();
  if (el.isContentEditable) {
    // If the click cost us the selection, put a caret at the end of the
    // editor so insertText has somewhere to insert.
    const sel = window.getSelection();
    if (!sel.rangeCount || !el.contains(sel.anchorNode)) {
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
    }
    document.execCommand("insertText", false, text);
  } else if ("value" in el) {
    const start = el.selectionStart != null ? el.selectionStart : el.value.length;
    if (el.setRangeText) {
      el.setRangeText(text, start, start, "end");
    } else {
      el.value += text;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

function report(hits, action) {
  const key = location.hostname + ":" + action + ":" +
    hits.map((h) => h.id).sort().join(",");
  const now = Date.now();
  if (reported.has(key) && now - reported.get(key) < REPORT_DEDUPE_MS) return;
  reported.set(key, now);

  chrome.runtime.sendMessage({
    type: "paste-guard",
    tool: location.hostname,
    action: action,                       // warned | blocked | overridden
    detectors: hits.map((h) => h.id),     // ids only, never the matched text
    ts: new Date().toISOString(),
  });
}

// Minimal overlay: inline-styled, high z-index, auto-dismiss. Deliberately
// framework-free so it cannot clash with the host page.
function showOverlay(hits, action, onOverride) {
  const existing = document.getElementById("taag-paste-overlay");
  if (existing) existing.remove();

  const labels = hits.map((h) => h.label).join(", ");
  const box = document.createElement("div");
  box.id = "taag-paste-overlay";
  box.style.cssText =
    "position:fixed;top:16px;right:16px;z-index:2147483647;max-width:340px;" +
    "background:#1f2430;color:#fff;border-left:4px solid " +
    (action === "blocked" ? "#e5484d" : "#f5a524") + ";" +
    "border-radius:6px;padding:12px 14px;font:13px/1.45 -apple-system," +
    "'Segoe UI',sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.35);";

  const title = document.createElement("div");
  title.style.cssText = "font-weight:600;margin-bottom:4px;";
  title.textContent = action === "blocked" ? "Paste blocked" : "Sensitive content detected";
  box.appendChild(title);

  const body = document.createElement("div");
  body.textContent = "Detected: " + labels + ". This looks like something " +
    "that should not go into an AI tool. (AI Guard)";
  box.appendChild(body);

  const row = document.createElement("div");
  row.style.cssText = "margin-top:10px;display:flex;gap:8px;";

  if (onOverride) {
    const go = document.createElement("button");
    go.textContent = "Paste anyway";
    go.style.cssText =
      "background:#f5a524;border:0;border-radius:4px;padding:5px 10px;" +
      "color:#1f2430;font-weight:600;cursor:pointer;font:inherit;";
    // preventDefault on mousedown so the click does not move focus and
    // selection out of the editor; the insert then lands where the paste
    // was headed.
    go.addEventListener("mousedown", (e) => e.preventDefault());
    go.addEventListener("click", () => { box.remove(); onOverride(); });
    row.appendChild(go);
  }

  const dismiss = document.createElement("button");
  dismiss.textContent = "Dismiss";
  dismiss.style.cssText =
    "background:transparent;border:1px solid #555;border-radius:4px;" +
    "padding:5px 10px;color:#ddd;cursor:pointer;font:inherit;";
  dismiss.addEventListener("click", () => box.remove());
  row.appendChild(dismiss);

  box.appendChild(row);
  document.documentElement.appendChild(box);
  setTimeout(() => { if (box.isConnected && !onOverride) box.remove(); }, 8000);
  if (onOverride) setTimeout(() => { if (box.isConnected) box.remove(); }, 20000);
}
