// Run with: node --test portal/tests/astra_overview.test.cjs
// Exercise the actual browser renderers with controlled API-shaped data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../app/static/index.html'), 'utf8');
const helpers = html.slice(html.indexOf('let ASTRA_PERSONAL_TOOLS = false;'), html.indexOf('const WIDGETS = {'));
const widgets = html.slice(html.indexOf('const WIDGETS = {'), html.indexOf('// The truncation banner'));
const escape = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function context(overrides={}) {
  const c = vm.createContext({
    G:{devices:{one:{collector_seen:true},two:{scanner_seen:true}},tools:{cloud:{devices:[],identities:['a','b'],surfaces:['cloud']}},personal_accounts:[{key:'a',tool:'cloud',user:'a'}]},
    REG:{rows:[{id:'cloud',name:'Cloud tool',vendor:'Vendor',status_source:'registry'}]},
    REGTOOLS:[], PSTAT:null, CAND:[], S:{reporting:1,groups:[{group:'cloud',reporting:1,total:5,sources:[]}]},
    CFG:{}, AUTH:null, dataOk:()=>true, ents:o=>Object.entries(o||{}),paKey:r=>r.key,
    esc:escape, fmtWindow:h=>h+' hours',hoursNow:()=>24,trendChip:()=>'',spark:()=>'<svg></svg>',
    match:()=>true, NAVICONS:{governance:'<path/>'},widgetForm:()=> 'table',formToggle:()=>'',
    fetch:()=>{throw new Error('Renderers must not fetch');},...overrides
  });
  vm.runInContext(helpers+widgets+'; this.widgets = WIDGETS;',c);
  return c;
}
test('accepted findings leave the open count, acknowledged findings do not',()=>{
  const c=context({G:{devices:{},tools:{a:{}},personal_accounts:[{key:'accepted',tool:'a'},{key:'ack',tool:'a'}]},PSTAT:{accepted:{status:'accepted'},ack:{status:'acknowledged'}}});
  const f=c.astraOverviewFacts();
  assert.equal(f.personal.length,2);assert.equal(f.open.length,1);assert.equal(f.open[0].key,'ack');
});
test('collector coverage counts actual signals, including a source-less observed device',()=>{
  const c=context({G:{devices:{a:{collector_seen:true},b:{scanner_seen:true},c:{}},tools:{},personal_accounts:[]}});
  const f=c.astraOverviewFacts();
  assert.equal(f.collectors,1);assert.equal(f.coverage,33);assert.equal(f.gaps.length,1);
  assert.match(c.widgets.detection_coverage(),/No collector signal <b>2<\/b>/);
});
test('no observed devices gives unavailable coverage rather than an invented percentage',()=>{
  const c=context({G:{devices:{},tools:{},personal_accounts:[]},S:{reporting:0,groups:[]}});
  assert.equal(c.astraOverviewFacts().coverage,null);
  const out=c.widgets.stat_row();assert.match(out,/Nothing reporting/);assert.doesNotMatch(out,/Monitoring healthy/);
  assert.match(c.widgets.detection_coverage(),/Collector coverage unavailable/);
});
test('a failed findings read never presents retained counts as current data',()=>{
  const c=context({dataOk:()=>false});
  assert.match(c.widgets.stat_row(),/Data unavailable/);
  assert.doesNotMatch(c.widgets.stat_row(),/Monitoring healthy/);
  assert.match(c.widgets.top_tools(),/Findings are unavailable/);
  assert.match(c.widgets.detection_coverage(),/Collector coverage unavailable/);
});
test('unavailable register data is separate from zero decisions',()=>{
  const c=context({REG:null});
  assert.equal(c.astraOverviewFacts().recorded,null);
  assert.match(c.widgets.stat_row(),/Register data unavailable/);
  assert.match(c.astraFocusRows(c.astraOverviewFacts()),/Register data is unavailable/);
});
test('only explicit decisions for discovered tools contribute to the register metric',()=>{
  const c=context({G:{devices:{},tools:{a:{},b:{},c:{}},personal_accounts:[]},REG:{rows:[{id:'a',status_source:'governance',status:'refused'},{id:'b',status_source:'portal',status:'reviewing',days_overdue:2},{id:'c',status_source:'registry'},{id:'unobserved',status_source:'portal'}]}});
  const f=c.astraOverviewFacts();assert.equal(f.recorded.length,2);assert.equal(f.undecided,1);assert.equal(f.overdue,1);
});
test('cloud-only tools retain zero devices alongside their separate identity count',()=>{
  const c=context();const out=c.widgets.top_tools();
  assert.match(out,/<td class="num">0<\/td><td class="num">2<\/td>/);
  assert.match(out,/View Cloud tool details/);assert.match(out,/data-open="tool" data-key="cloud"/);
});
test('the table contains every matching tool instead of truncating away cloud-only tools',()=>{
  const many=Object.fromEntries(Array.from({length:9},(_,i)=>['t'+i,{devices:[],identities:[],surfaces:[]}]))
  const c=context({G:{devices:{},tools:many,personal_accounts:[]}});
  const out=c.widgets.top_tools();assert.match(out,/9 of 9 discovered tools/);assert.match(out,/data-key="t8"/);
});
test('the personal filter uses open lifecycle findings, not all historic personal rows',()=>{
  const c=context({PSTAT:{a:{status:'accepted'}}});vm.runInContext('ASTRA_PERSONAL_TOOLS = true;',c);
  const out=c.widgets.top_tools();assert.match(out,/No tools match this view/);assert.match(out,/0 of 1 discovered tools/);
});
test('tool metadata and finding identifiers are escaped before becoming markup',()=>{
  const id='x" onclick="bad';const attack='<img src=x onerror=bad>';
  const c=context({G:{devices:{},tools:{[id]:{devices:[],identities:[],surfaces:[attack]}},personal_accounts:[]},REG:{rows:[{id,name:attack,vendor:attack}]}});
  const out=c.widgets.top_tools();assert.doesNotMatch(out,/<img /);assert.doesNotMatch(out,/data-key="x" onclick=/);assert.match(out,/&lt;img/);
});
