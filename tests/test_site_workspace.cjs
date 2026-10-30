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
// site-posture-v1: the "Site setup" card shows hosting, mail protection, software and outside scripts as text.
const setupHost=new Element('section');
render({domain:'shop.example',verdict:'suspicious',assessment:{score:90},checks:[],findings:[],discovery:{},crawl:{policy:'site-crawl-v1',pages_read:2,privacy_notice:true,pages:[]},
  posture:{policy:'site-posture-v1',hosting:{status:'completed',country:evil,network:'Example Net',asn:64500,ip:'192.0.2.1'},mail:{status:'completed',protected:false,dmarc_policy:'none',spf:evil},
    technology:[{name:'WordPress',version:'5.2',source:'generator'}],old_software:['WordPress 5.2'],mixed_content:{scripts:1,frames:0,other:2},
    cookies:[{name:evil,secure:false,httponly:true,samesite:''}],copied_scripts:[{host:evil,brand:'PayPal'}],outside_scripts:[{host:evil,url:evil}]},_pdf_receipt:'signed'},setupHost);
const setupNodes=[];(function walk(n){setupNodes.push(n);n.children.forEach(walk);})(setupHost);
const setupTexts=setupNodes.map(n=>n.textContent).filter(Boolean);
for(const words of ['Site setup','Email in its name','Not protected (DMARC none)','WordPress','Privacy notice (KVKK)','Uses the name PayPal','Download PDF report'])assert(setupTexts.includes(words),words);
assert(setupNodes.every(n=>!['img','iframe','script'].includes(n.tagName)));
assert(setupNodes.some(n=>String(n.className||'').includes('warning')&&n.textContent==='warning'));
console.log('PASS: the site setup card and the PDF button render server evidence as text.');
