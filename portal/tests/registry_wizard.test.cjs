// Run with: node --test portal/tests/registry_wizard.test.cjs
// The tool wizard edits an entry without losing what it does not show.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../app/static/index.html'), 'utf8');
const wizard = html.slice(html.indexOf('const RW_SURFACES = ['), html.indexOf('const RW_STEPS'));

function context() {
  const c = vm.createContext({RW: null, REDIT: null, RPRE: null, RERR: '', RADV: false});
  vm.runInContext(wizard, c);
  return c;
}

// Everything the JSON editor can set and the wizard does not show.
const SAVED = {
  id: 'acme-ai', name: 'Acme AI', vendor: 'Acme', category: 'unreviewed', risk_tier: 'medium',
  domains: ['acme.ai'], app_names: ['Acme AI.app'],
  extension_ids: {vscode: ['acme.acme-ai'], chrome: ['abcdefghijklmnopabcdefghijklmnop']},
  cli: {binaries: ['acme'], account_json_path: '.acme/auth.json'},
  mcp_config_paths_macos: ['Library/Acme/mcp.json'],
  inference_domains: ['api.acme.ai'], env_vars: ['ACME_API_KEY'],
};

test('an edit saved without changes is the entry it started from', () => {
  const c = context();
  c.rwFromEntry('acme-ai', SAVED);
  assert.deepEqual(JSON.parse(JSON.stringify(c.rwEntry())), SAVED);
});

test('an edit changes what was edited and keeps everything else', () => {
  const c = context();
  c.rwFromEntry('acme-ai', SAVED);
  c.RW.sugs.find(s => s.f === 'cli.binaries').on = false;
  c.RW.sugs.push({f: 'extension_ids.vscode', v: 'acme.acme-two', why: 'me', conf: 'high', on: true});
  const e = JSON.parse(JSON.stringify(c.rwEntry()));
  assert.deepEqual(e.cli, {account_json_path: '.acme/auth.json'});
  assert.deepEqual(e.extension_ids.chrome, SAVED.extension_ids.chrome);
  assert.deepEqual(e.extension_ids.vscode, ['acme.acme-ai', 'acme.acme-two']);
  assert.deepEqual(e.inference_domains, SAVED.inference_domains);
  assert.deepEqual(e.mcp_config_paths_macos, SAVED.mcp_config_paths_macos);
});

test('back from the JSON editor, the wizard holds what the JSON said', () => {
  const c = context();
  c.rwOpen({});
  c.RW.name = 'Acme AI'; c.RW.vendor = 'Acme'; c.rwResuggest();
  const typed = JSON.parse(JSON.stringify(c.rwEntry()));
  typed.extension_ids = {chrome: ['abcdefghijklmnopabcdefghijklmnop']};
  typed.app_names = ['Acme AI.app'];             // one of the derived guesses, ticked by hand
  typed.notes = 'from the JSON';
  c.rwApplyEntry(typed);
  const e = JSON.parse(JSON.stringify(c.rwEntry()));
  assert.deepEqual(e.extension_ids, {chrome: ['abcdefghijklmnopabcdefghijklmnop']});
  assert.deepEqual(e.app_names, ['Acme AI.app']);
  assert.equal(e.notes, 'from the JSON');
});

test('a value removed in the JSON is unticked in the wizard', () => {
  const c = context();
  c.rwFromEntry('acme-ai', SAVED);
  const typed = JSON.parse(JSON.stringify(SAVED));
  delete typed.app_names;
  c.rwApplyEntry(typed);
  assert.equal(c.rwEntry().app_names, undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(c.rwEntry().extension_ids)), SAVED.extension_ids);
});
