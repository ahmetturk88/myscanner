const assert=require('node:assert/strict');
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.style={setProperty(){}};this.events={};this.classList={add:x=>{this.className=(this.className||'')+' '+x;}};}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 addEventListener(name,fn){this.events[name]=fn;}
 set innerHTML(v){throw Error('Unsafe HTML sink');}
}
global.document={createElement:tag=>new Element(tag),getElementById:()=>null};
const {render,toCSV}=require('../static/site_workspace.js');
const evil='<img src=x onerror=alert(1)>';
const host=new Element('section');
render({domain:evil,verdict:evil,assessment:{score:Infinity,warning:evil},scope:evil,report_brief:[evil],checks:[{name:evil,status:evil}],http:{chain:[{url:evil,status_code:302,destination:evil}]},content:{title:evil,forms:[{action:evil}]},dns:{TXT:{values:[evil],status:'unavailable'}},provider:{status:'unavailable',reason:evil,red_flags:[evil]},findings:[{title:evil,detail:evil,severity:evil}],header_observations:[{name:evil,value:evil,status:'missing'}],discovery:{}},host);
const flattened=[];function walk(n){flattened.push(n);n.children.forEach(walk);}walk(host);
assert(flattened.some(n=>n.textContent===evil));
assert(flattened.every(n=>!String(n.className||'').includes('<')));
assert(flattened.every(n=>!['img','iframe','script'].includes(n.tagName)));
assert(toCSV({checks:[{name:'=1+1',status:'unavailable'}]}).includes('"\'=1+1"'));
console.log('PASS: hostile report content remains text, states are bounded, CSV formulas escaped.');
