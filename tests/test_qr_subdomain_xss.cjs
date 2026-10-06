const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..');
const payload=`<img src=x onerror="globalThis.pwned=1"><svg onload="globalThis.pwned=1">'"\\&`;
function setup(name){
 const elements={},copied=[],opened=[],scanned=[],requests=[];
 function node(id){return elements[id] ||= {innerHTML:'',textContent:'',style:{},className:'',children:[],handlers:{},offsetTop:20,
 classList:{add(){},remove(){}},addEventListener(event,callback){this.handlers[event]=callback;},
 appendChild(child){this.children.push(child);},replaceChildren(){this.children=[];this.innerHTML='';},
 querySelectorAll(){this.buttons=[...this.innerHTML.matchAll(/<button class="scan-subdomain" type="button" data-group="(active|redirects)" data-index="(\d+)"/g)].map(match=>({...node('button-'+match[1]+match[2]),dataset:{group:match[1],index:match[2]}}));return this.buttons;}};}
 const ctx={window:{scrollTo(){},location:{}},URL,console,setTimeout(){},document:{getElementById:node,createElement(tag){return {...node('new-'+Math.random()),tagName:tag};}},navigator:{clipboard:{writeText(value){copied.push(value);return Promise.resolve();}}},localStorage:{setItem(){}},fetch:async(url,options)=>{requests.push({url,body:options.body});return {json:async()=>({verdict:'clean'})};}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(root,'static/scan_ui.js'),'utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
 const template=fs.readFileSync(path.join(root,'templates',name),'utf8');
 const scripts=[...template.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match=>match[1]).filter(Boolean);
 for(const script of scripts) vm.runInContext(script,ctx);
 return {ctx,elements,copied,opened,scanned,requests,node};
}
(async()=>{
 const qr=setup('qr_scanner.html');
 qr.ctx.renderTextResult(payload);
 const copy=qr.elements['action-buttons'].children[0];
 assert.equal(copy.tagName,'button');assert.equal(copy.type,'button');assert.equal(copy.innerHTML,'');
 copy.handlers.click();assert.equal(qr.copied[0],payload);assert.equal(qr.ctx.pwned,undefined);
 const url=`https://good.example/?q='"&x=1`;
 qr.ctx.window.open=(...args)=>qr.opened.push(args);
 qr.ctx.gotoScanner=value=>qr.scanned.push(value);
 qr.ctx.rescanURL=value=>qr.scanned.push(value);
 qr.ctx.renderURLResult(url,{verdict:payload,stats:{harmless:payload,malicious:payload,suspicious:payload,undetected:payload}});
 let buttons=qr.elements['action-buttons'].children;
 assert.equal(buttons.length,4);buttons[0].handlers.click();assert.equal(qr.copied[1],url);
 buttons[1].handlers.click();assert.equal(qr.opened[0][0],qr.ctx.ScanUI.webURL(url));assert.equal(qr.opened[0][2],'noopener,noreferrer');
 buttons[2].handlers.click();buttons[3].handlers.click();assert.equal(qr.scanned.length,2);
 const qrStats=qr.elements['stats-grid'].innerHTML;
 for(const unsafe of ['javascript:alert(1)','data:text/html,<script>','https://u:p@good.example','https://good.example/\n']){
  qr.ctx.renderURLResult(unsafe,{stats:{}});buttons=qr.elements['action-buttons'].children;
  assert.equal(buttons.length,2);assert.equal(buttons[1].disabled,true);
 }
 qr.ctx.renderTextResult('A & B < C');qr.elements['action-buttons'].children[0].handlers.click();assert.equal(qr.copied.at(-1),'A & B < C');
 const sub=setup('subdomain_finder.html');
 const data={total_checked:payload,active_count:payload,redirect_count:payload,inactive_count:payload,total_found:payload,subdomains:{active:[{full_domain:payload,ip:payload,subdomain:payload}],redirects:[{full_domain:payload,ip:payload,subdomain:payload}],inactive:[{full_domain:payload,ip:payload}]}};
 sub.ctx.renderResult(data);const result=sub.elements['result-card'];
 assert.equal(result.buttons.length,2);
 result.buttons[0].handlers.click();await Promise.resolve();await Promise.resolve();
 assert.equal(JSON.parse(sub.requests[0].body).domain,payload);assert.equal(sub.ctx.pwned,undefined);
 await sub.ctx.scanSubdomain(payload,payload);
 const modal=sub.elements['modal-status'].innerHTML;
 console.log(JSON.stringify({payload,qrStats,subHTML:result.innerHTML,modal}));
})().catch(error=>{console.error(error);process.exitCode=1;});
