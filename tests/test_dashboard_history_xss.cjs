const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
class Element {
  constructor(tag, document) { this.tagName = tag; this.ownerDocument = document; this.children = []; this.className = ''; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(value) { throw Error('HTML sink used'); }
  appendChild(node) { this.children.push(node); return node; }
  replaceChildren(fragment) { this.children = [...fragment.children]; this._text = ''; }
}
const document = {createElement(tag) {return new Element(tag, document);}, createDocumentFragment() {return new Element('fragment', document);}};
const context = {window: {}};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../static/dashboard_ui.js'), 'utf8'), context);
const ui = context.window.DashboardUI;
const payload = '<img src=x onerror="alert(1)"></td><script>alert(1)</script>& "';
const tbody = document.createElement('tbody');
ui.renderRows(tbody, [{id:payload,url:payload,summary:payload,date:payload,verdict:'malicious" onclick="alert(1)'}]);
assert.equal(tbody.children.length, 1);
const cells = tbody.children[0].children;
assert.equal(cells.length, 5);
assert.equal(cells[0].textContent, '#'+payload);
for (const i of [1,3,4]) assert.equal(cells[i].textContent,payload);
assert.equal(cells[2].children[0].className, 'verdict-badge v-unknown');
assert.equal(cells[2].textContent, 'UNKNOWN');
assert.equal(cells.filter(cell=>cell.children.length).length,1);
ui.renderRows(tbody,[{id:0,url:'https://example.com/?a=1&b=2',summary:'A & B < C',date:'2026-10-06',verdict:'harmless'}]);
assert.equal(tbody.children[0].children[0].textContent,'#0');
assert.equal(tbody.children[0].children[3].textContent,'A & B < C');
assert.equal(tbody.children[0].children[2].children[0].className,'verdict-badge v-harmless');
const scans=ui.normalizeScans([null,[],{}, {id:{},url:{},date:12,summary:false,verdict:'__proto__'}]);
assert.equal(scans.length,2);
assert.equal(scans[1].url,''); assert.equal(scans[1].date,'12'); assert.equal(scans[1].verdict,'unknown');
assert.equal(ui.normalizeScans({}).length,0);
ui.renderRows(tbody,[]); assert.equal(tbody.children.length,0);
console.log('Dashboard malicious data, text fidelity, verdict vocabulary and refresh checks passed.');
(async () => {
  const ids = Object.fromEntries(['table-body','search-input','filter-select','total-count','safe-count','mal-count','sus-count','filtered-count'].map(id=>[id,document.createElement(id==='table-body'?'tbody':'div')]));
  ids['search-input'].value='';
  let selected='';
  document.getElementById=id=>ids[id];
  document.querySelectorAll=()=>[];
  document.querySelector=selector=>{selected=selector;return {classList:{add(){}}};};
  context.document=document;
  context.DashboardUI=ui;
  context.fetch=async()=>({ok:true,json:async()=>({scans:[{id:1,url:payload,summary:payload,date:payload,verdict:'<img>'},{id:2,url:'https://good.example/a',verdict:'harmless'}]})});
  context.setInterval=()=>{};
  context.console=console;
  const staticPage=process.argv.includes('--static');
  const template=fs.readFileSync(path.join(__dirname,staticPage?'../static/dashboard/index.html':'../templates/dashboard-v2.html'),'utf8');
  const script=staticPage ? [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1] : template.match(/\{% block body_extra %\}[\s\S]*?<script>([\s\S]*?)<\/script>/)[1];
  vm.runInContext(script,context);
  await vm.runInContext('loadData()',context);
  assert.equal(ids['table-body'].children.length,2);
  assert.equal(ids['total-count'].textContent,'2');
  assert.equal(ids['table-body'].children[0].children[1].textContent,payload);
  vm.runInContext("filterBy('harmless')",context);
  assert.equal(selected,'.stat-card.safe');
  assert.equal(ids['table-body'].children.length,1);
  assert.equal(ids['table-body'].children[0].children[1].textContent,'https://good.example/a');
  vm.runInContext("filterBy('malicious\" onclick=alert(1)')",context);
  assert.equal(selected,'.stat-card.total');
  assert.equal(ids['table-body'].children.length,2);
  ids['search-input'].value='good.example';
  vm.runInContext('renderTable()',context);
  assert.equal(ids['table-body'].children.length,1);
  assert.equal(ids['filtered-count'].textContent,'1 scans');
  console.log('Dashboard loading, missing Chart.js, filter cards and search integration checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
