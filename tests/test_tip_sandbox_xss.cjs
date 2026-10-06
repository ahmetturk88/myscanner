const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..'),payload='<img src=x onerror="globalThis.pwned=1"><svg onload="globalThis.pwned=1">\'"&';
function page(filename){
 const nodes={};
 class E{constructor(){this.style={};this.handlers={};this.children=[];this.value='';this.innerHTML='';this.textContent='';this.classList={add(){},remove(){},toggle(){}};}addEventListener(k,f){this.handlers[k]=f;}appendChild(e){this.children.push(e);}scrollIntoView(){}remove(){}}
 const node=id=>nodes[id] ||=new E();
 const ctx={console,URL,Math,Date,setTimeout(){},setInterval(){},clearInterval(){},alert(){},window:{scrollTo(){}},document:{body:new E(),getElementById:node,createElement:()=>new E(),querySelectorAll:()=>[],querySelector:()=>null},fetch:async()=>({json:async()=>({success:false})})};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(root,'static/scan_ui.js'),'utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
 const source=fs.readFileSync(path.join(root,'templates',filename),'utf8');for(const m of source.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))vm.runInContext(m[1].replace(/    loadStats\(\);\n    loadIocs\(\);/,' '),ctx);
 return{ctx,nodes,node};
}
(async()=>{
 const sections=[];const collect=(p,label)=>{for(const [id,n] of Object.entries(p.nodes))if(n.innerHTML)sections.push({name:label+' '+id,html:n.innerHTML});assert.equal(p.ctx.pwned,undefined);};
 const s=page('sandbox.html');s.ctx.renderResults({verdict:'constructor',threat_score:payload,sources:{[payload]:payload,constructor:payload},mb_data:{found:true,signature:payload},sha256:payload,md5:payload,sha1:payload,vt_detections:[null,{engine:payload,result:payload}],behavior:{registry_keys:[payload],files_created:{},mutexes:[]},network:{domains:[payload]},mitre_attacks:[null,{attck_id:payload,technique:payload,tactic:payload}],signatures:[null,{name:payload,description:payload,severity:payload}],static_analysis:{security_score:payload,indicators:[payload,null,{description:payload}]}});assert.equal(s.node('scoreNum').textContent,'0%');assert.equal(s.node('verdictText').textContent,'UNKNOWN');collect(s,'sandbox');
 s.ctx.renderResults({sources:{},vt_detections:{},mitre_attacks:{},signatures:{},behavior:{registry_keys:'bad'},network:{domains:{}},static_analysis:{indicators:{}}});
 const t=page('tip_dashboard.html');t.ctx.showToast(payload,'error');assert.equal(t.ctx.document.body.children[0].textContent,payload);assert.equal(t.ctx.document.body.children[0].innerHTML,'');
 t.ctx.fetch=async()=>({json:async()=>({success:true,pages:payload,iocs:[{value:payload,type:payload,severity:payload,confidence:payload,threat_type:payload,first_seen:payload},null]})});await t.ctx.loadIocs();assert(t.node('iocsTableBody').innerHTML.includes('width: 0%'));collect(t,'tip table');assert.equal(t.ctx.getSeverityClass('constructor'),'medium');assert.equal(t.ctx.getTypeBadge('__proto__'),'medium');
 t.node('lookupValue').value=payload;t.ctx.fetch=async()=>({json:async()=>({success:true,result:{found:true,highest_severity:payload,max_confidence:payload,count:payload,tip_score:payload,summary:payload,tags:[payload]}})});await t.node('lookupBtn').handlers.click();collect(t,'tip match');
 t.ctx.fetch=async()=>({json:async()=>({success:true,result:{found:false}})});await t.node('lookupBtn').handlers.click();collect(t,'tip no match');
 t.ctx.fetch=async()=>{throw new Error(payload);};await t.node('lookupBtn').handlers.click();collect(t,'tip exception');
 t.ctx.fetch=async()=>({json:async()=>({success:false})});await t.node('lookupBtn').handlers.click();assert(!t.node('lookupResult').innerHTML.includes('appears to be clean'));collect(t,'tip unavailable');
 console.log(JSON.stringify({payload,sections}));
})().catch(e=>{console.error(e);process.exitCode=1;});
