// Run with: node --test portal/tests/activation_card.test.cjs
//
// The activation card, rendered by the browser's own function against the
// shapes the receiver actually answers with. Same harness as the overview
// renderers, for the same reason: this card makes claims about what a
// deployment is entitled to, and the wrong claim is worse than a broken
// layout. What is checked here is mostly what it must NOT say - never that
// a deployment is on the open edition when the read failed, and never the
// key itself.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../app/static/index.html'), 'utf8');
const card = html.slice(html.indexOf('let ACT = null, ACTMSG = null;'),
                        html.indexOf('function diagnosticsCards() {'));
const escape = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function render(act, {role = 'owner', msg = null} = {}) {
  const c = vm.createContext({
    AUTH: {role},
    DIAG: {deployment: {namespace: 'ai-guard'}},
    esc: escape,
    uiCommand: cmd => `<div class="ui-cmd"><code>${escape(cmd)}</code></div>`,
  });
  vm.runInContext(card + '; ACT = this.act; ACTMSG = this.msg; this.out = activationCard();',
                  Object.assign(c, {act, msg}));
  return c.out;
}

const ACTIVE = {state: 'active', id: 'NYX-0001', org: 'Acme Group Ltd',
  plan: 'enterprise', devices: 2500, issued: '2026-01-01',
  expires: '2027-06-30', days_left: 300, registry: 'registry.example.com',
  fingerprint: '58aa-0b39-7247'};

test('with no key, the card says open edition and claims nothing else', () => {
  const out = render({state: 'none'});
  assert.match(out, /open edition/);
  assert.match(out, /Open edition/);
  assert.match(out, /Apache 2\.0/);
  assert.match(out, /offline, no outbound request/);
  assert.doesNotMatch(out, /activated/);
});

test('a failed read is not "no subscription"', () => {
  // The bug this exists to stop: answering the question from a read that
  // never happened, and telling a paying customer they have no licence.
  const out = render({state: 'unknown'});
  assert.match(out, /not read/);
  assert.match(out, /nothing is claimed either way/);
  assert.doesNotMatch(out, /Open source/);
  assert.doesNotMatch(out, /Paste an activation key/);
});

test('an activated deployment shows what it bought, and never the key', () => {
  const out = render(ACTIVE);
  assert.match(out, /Acme Group Ltd/);
  assert.match(out, /enterprise/);
  assert.match(out, /up to 2500 devices/);
  assert.match(out, /2027-06-30/);
  assert.match(out, /in 300 days/);
  assert.match(out, /58aa-0b39-7247/);
  assert.doesNotMatch(out, /nyxl_/);
});

test('the commands name the deployment\'s own namespace and registry', () => {
  const out = render(ACTIVE);
  assert.match(out, /kubectl -n ai-guard create secret docker-registry nyxus-registry/);
  assert.match(out, /--docker-server=registry\.example\.com/);
  assert.match(out, /helm upgrade --install nyxus/);
  // The key goes in from the operator's shell, never from the page.
  assert.match(out, /export NYXUS_KEY=/);
  assert.doesNotMatch(out, /nyxl_/);
});

test('a key that names no registry says where the real one comes from', () => {
  const out = render(Object.assign({}, ACTIVE, {registry: ''}));
  assert.match(out, /&lt;registry&gt;/);
  assert.match(out, /welcome message names the registry/);
});

test('a subscription close to its end says so before it ends', () => {
  const soon = render(Object.assign({}, ACTIVE, {days_left: 20}));
  assert.match(soon, /health-note warning/);
  assert.match(soon, /runs out on 2027-06-30/);
  // And says plainly that nothing stops working, because nothing does.
  assert.match(soon, /nothing stops working on the day/);
  assert.doesNotMatch(render(ACTIVE), /health-note warning/);
});

test('an expired key is shown as genuine and lapsed, not as a forgery', () => {
  const out = render(Object.assign({}, ACTIVE,
    {state: 'expired', expires: '2026-02-01', days_left: -29}));
  assert.match(out, /expired/);
  assert.match(out, /29 days ago/);
  assert.match(out, /Acme Group Ltd/);
  assert.match(out, /carries on exactly as it is/);
  // Still worth showing the handoff: renewing is the point.
  assert.match(out, /Move this deployment to Nyxus/);
});

test('a key this release cannot verify says to upgrade before suspecting it', () => {
  const out = render({state: 'invalid', fingerprint: 'aaaa-bbbb-cccc',
                      code: 'not_ours',
                      reason: 'this key was not issued for this software'});
  assert.match(out, /cannot be checked/);
  assert.match(out, /upgrade first/);
  assert.match(out, /aaaa-bbbb-cccc/);
  assert.match(out, /Remove it/);
});

test('only an owner is offered the field', () => {
  for (const role of ['admin', 'viewer']) {
    const out = render({state: 'none'}, {role});
    assert.doesNotMatch(out, /data-act="act-save"/);
    assert.match(out, /An owner account activates a subscription/);
  }
  assert.match(render({state: 'none'}, {role: 'owner'}), /data-act="act-save"/);
});

test('an activated owner can replace or remove, and a viewer sees the facts', () => {
  const owner = render(ACTIVE);
  assert.match(owner, /Paste a renewed key to replace this one/);
  assert.match(owner, /data-act="act-clear"/);
  const viewer = render(ACTIVE, {role: 'viewer'});
  assert.match(viewer, /Acme Group Ltd/);
  assert.doesNotMatch(viewer, /data-act="act-/);
});

test('a refusal is shown as one, and escaped', () => {
  const out = render({state: 'none'},
                     {msg: {ok: false, text: 'this key is <damaged>'}});
  assert.match(out, /health-note danger/);
  assert.match(out, /this key is &lt;damaged&gt;/);
});

test('an organisation name is escaped rather than rendered', () => {
  const out = render(Object.assign({}, ACTIVE, {org: '<img src=x onerror=1>'}));
  assert.match(out, /&lt;img src=x/);
  assert.doesNotMatch(out, /<img src=x/);
});
