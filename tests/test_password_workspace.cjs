const assert=require('node:assert/strict'),crypto=require('node:crypto').webcrypto;
class Element{constructor(tag){this.tagName=tag;this.children=[];this.style={setProperty(){}};this.handlers={};}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}addEventListener(k,v){this.handlers[k]=v;}set innerHTML(v){throw Error('unsafe sink');}}
global.document={createElement:t=>new Element(t),getElementById:()=>null};
const {render,securePassword}=require('../static/password_workspace.js');
const outputs=new Set();for(let i=0;i<100;i++){const p=securePassword(crypto);assert.equal(p.length,24);assert(/^[A-Za-z2-9!@#$%&*_-]+$/.test(p));outputs.add(p);}assert.equal(outputs.size,100);
assert.throws(()=>securePassword({}),/randomness/);
const evil='<img src=x onerror=alert(1)>',host=new Element('section');render({local_strength:{score:Infinity,strength:evil,findings:[{message:evil}],deductions:[{reason:evil,points:evil}]},pwned:{status:'found',message:evil,count:evil},recommendations:[evil],summary:[evil]},host);
const nodes=[];function walk(n){nodes.push(n);n.children.forEach(walk);}walk(host);assert(nodes.some(n=>n.textContent===evil));assert(nodes.every(n=>!['img','script','iframe'].includes(n.tagName)));
for(const status of ['found','not_found','unavailable','skipped'])render({local_strength:{score:null},pwned:{status}},new Element('div'));
console.log('PASS: text-only report, distinct exposure states, bounded scores and cryptographic generator.');
