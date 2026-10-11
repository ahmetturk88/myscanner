const assert=require('node:assert/strict');
class Element{constructor(tag){this.tagName=tag;this.children=[];this.style={setProperty(){}};}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}addEventListener(){}set innerHTML(v){throw Error('unsafe sink');}}
global.document={createElement:t=>new Element(t),getElementById:()=>null};
const {render}=require('../static/ssl_workspace.js'),host=new Element('section'),evil='<img src=x onerror=alert(1)>';
render({domain:evil,valid:false,assessment:{score:Infinity,warning:evil},issuer:evil,subject:evil,subject_names:[evil],cipher:{name:evil},findings:[{title:evil,detail:evil}],checks:[{name:evil,status:evil}],summary:[evil],not_checked:[evil]},host);
const nodes=[];function walk(n){nodes.push(n);n.children.forEach(walk);}walk(host);assert(nodes.some(n=>n.textContent===evil));assert(nodes.every(n=>!['img','iframe','script'].includes(n.tagName)));
const texts=valid=>{const h=new Element('section');render({valid,assessment:{score:100}},h);const out=[];(function w(n){if(n.textContent)out.push(n.textContent);n.children.forEach(w);})(h);return out;};
assert(texts(true).includes('Certificate verification passed'));
assert(texts(false).includes('Certificate verification failed'));
for(const valid of [null,undefined]){const t=texts(valid);assert(t.includes('Certificate validity unknown'));assert(!t.some(x=>/verification passed/.test(x)));}
console.log('PASS: native text rendering, bounded coverage and distinct verified/invalid/unknown states.');
