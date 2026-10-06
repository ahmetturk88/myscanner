const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const payload=`');globalThis.pwned=1;//<img src=x onerror="alert(1)">`;
class Element{constructor(dataset){this.dataset=dataset;this.handlers={};this.attributes={};}addEventListener(k,f){this.handlers[k]=f;}removeAttribute(k){delete this.attributes[k];delete this[k];}setAttribute(k,v){this.attributes[k]=v;}}
const links=['javascript:alert(1)','data:text/html,<svg onload=alert(1)>','//evil.example','https://user:pass@example.com','https://example.com/?a=1&b=2',payload].map(webUrl=>new Element({webUrl}));
const buttons=[new Element({deleteKind:'user',deleteId:'7',deleteLabel:payload}),new Element({deleteKind:'scan',deleteId:'8',deleteLabel:payload}),new Element({deleteKind:'user',deleteId:payload,deleteLabel:payload}),new Element({deleteKind:'constructor',deleteId:'7',deleteLabel:payload})];
const uuid='d801f857-e63f-40ae-af7d-53c1f1016f00',checks=[new Element({checkScan:uuid}),new Element({checkScan:payload})],calls=[];
let ready;
const ctx={window:{confirmDelete:(...args)=>calls.push(args),checkStatus:arg=>calls.push(arg)},URL,document:{addEventListener:(event,fn)=>{assert.equal(event,'DOMContentLoaded');ready=fn;},querySelectorAll:selector=>({'[data-web-url]':links,'[data-delete-kind]':buttons,'[data-check-scan]':checks})[selector]}};
vm.createContext(ctx);for(const file of ['scan_ui.js','display_actions.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../static',file),'utf8'),ctx);ready();
links.forEach((link,i)=>{if(i===4){assert.equal(link.href,'https://example.com/?a=1&b=2');assert.equal(link.rel,'noopener noreferrer');}else{assert.equal(link.href,undefined);assert.equal(link.attributes['aria-disabled'],'true');}});
for(const b of [...buttons,...checks])b.handlers.click();assert.deepEqual(calls,[['user','7',payload],['scan','8',payload],uuid]);assert.equal(ctx.pwned,undefined);
console.log('Saved link schemes, literal deletion labels and UUID actions checks passed.');
