const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..');
const payload=`<img src=x onerror="globalThis.pwned=1"><svg onload="globalThis.pwned=1">'"\\&`;
const escape=v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
function setup(name){
 const elements={},copied=[],opened=[],scanned=[],requests=[],downloads=[];
 class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.handlers={};this.style={};this.attrs={};this.className='';this._text='';this.offsetTop=20;this.classList={add(){},remove(){}};this.value='';}
  set textContent(v){this._text=String(v);this.children=[];}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  set innerHTML(v){if(v) throw new Error('Untrusted HTML sink used');this.replaceChildren();}
  get innerHTML(){return this.children.map(c=>c.serialize()).join('') || escape(this._text);}
  appendChild(c){this.children.push(c);return c;}
  replaceChildren(...children){this.children=children;this._text='';}
  addEventListener(event,callback){this.handlers[event]=callback;}
  setAttribute(key,value){this.attrs[key]=String(value);}
  querySelectorAll(selector){const result=[];function visit(n){for(const c of n.children){if(selector==='button' && c.tagName==='button' || selector==='button.scan-subdomain' && c.tagName==='button' && c.className==='scan-subdomain' || selector==='input' && c.tagName==='input' || selector==='select' && c.tagName==='select')result.push(c);visit(c);}}visit(this);return result;}
  querySelector(selector){return this.querySelectorAll(selector)[0];}
  focus(){ctx.document.activeElement=this;}
  click(){if(this.tagName==='a')downloads.push({name:this.download,href:this.href});else return this.handlers.click?.();}
  serialize(){const attrs={...this.attrs};if(this.className)attrs.class=this.className;if(this.type)attrs.type=this.type;return '<'+this.tagName+Object.entries(attrs).map(([k,v])=>' '+k+'="'+escape(v)+'"').join('')+'>'+escape(this._text)+this.children.map(c=>c.serialize()).join('')+'</'+this.tagName+'>';}
 }
 const node=id=>elements[id] ||= new Element();
 const ctx={window:{scrollTo(){},location:{}},URL,Blob,console,setTimeout(){},document:{getElementById:node,createElement:tag=>new Element(tag),addEventListener(){},activeElement:null},navigator:{clipboard:{writeText(value){copied.push(value);return Promise.resolve();}}},localStorage:{setItem(){}},fetch:async(url,options)=>{requests.push({url,body:options.body});return {ok:true,json:async()=>assessment()};}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(root,'static/scan_ui.js'),'utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
 vm.runInContext(fs.readFileSync(path.join(root,'static/web_assessment_ui.js'),'utf8'),ctx);ctx.WebAssessmentUI=ctx.window.WebAssessmentUI;
 const template=fs.readFileSync(path.join(root,'templates',name),'utf8');
 for(const match of template.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(match[1].trim())vm.runInContext(match[1],ctx);
 return {ctx,elements,copied,opened,scanned,requests,node,downloads};
}
function assessment(){return {verdict:payload,assessment_status:'partial',summary:payload,stats:{checks_completed:payload,checks_total:payload,warning_count:payload,redirect_count:payload},checks:[{name:payload,status:payload}],structure:{hostname:payload,path:payload},dns:{A:{status:'completed',values:[payload]}},http:{chain:[{url:payload,status_code:payload}],security_headers:{'Content-Security-Policy':payload},final_url:payload},tls:{status:'unavailable',reason:payload},content:{title:payload,forms:[{action:payload}],note:payload},provider:{name:'url.vet',status:'unavailable',red_flags:[payload]},findings:[{title:payload,detail:payload}],limitations:[payload]};}
(async()=>{
 const qr=setup('qr_scanner.html'); qr.ctx.renderTextResult(payload);
 await qr.elements['action-buttons'].children[0].handlers.click();assert.equal(qr.copied[0],payload);
 const url=`https://good.example/?q='"&x=1`;
 qr.ctx.window.open=(...args)=>qr.opened.push(args);qr.ctx.gotoScanner=value=>qr.scanned.push(value);qr.ctx.rescanURL=value=>qr.scanned.push(value);
 qr.ctx.renderURLResult(url,assessment());let buttons=qr.elements['action-buttons'].children;
 assert.equal(buttons.length,4);await buttons[0].handlers.click();assert.equal(qr.copied[1],url);
 buttons[1].handlers.click();assert.equal(qr.opened[0][0],qr.ctx.ScanUI.webURL(url));assert.equal(qr.opened[0][2],'noopener,noreferrer');
 buttons[2].handlers.click();buttons[3].handlers.click();assert.equal(qr.scanned.length,2);
 const qrStats=qr.elements['assessment-details'].innerHTML;
 for(const unsafe of ['javascript:alert(1)','data:text/html,<script>','https://u:p@good.example','https://good.example/\n']){
  qr.ctx.renderURLResult(unsafe,assessment());buttons=qr.elements['action-buttons'].children;assert.equal(buttons.length,2);assert.equal(buttons[1].disabled,true);
 }
 qr.ctx.renderTextResult('A & B < C');await qr.elements['action-buttons'].children[0].handlers.click();assert.equal(qr.copied.at(-1),'A & B < C');
 assert.equal(qr.elements['assessment-details'].children.length,0);
 const sub=setup('subdomain_finder.html');
 const row={full_domain:payload,addresses:[payload],sources:[payload],subdomain:payload,public_addresses:true,verdict:'active',http:{status:'completed',status_code:payload,url:payload,location:payload},tls:{status:'completed',issuer:payload},dns:{CNAME:{values:[payload]}}};
 const data={total_found:payload,candidates_selected:payload,dns_error_count:payload,limits:{web_probe_limit:20},sources:[{name:payload,status:payload}],results:[row,{...row,full_domain:'other.example.com',verdict:'dns_only'}],unresolved:[row],all_subdomains:[payload],limitations:[payload]};
 sub.ctx.renderResult(data);const result=sub.elements['result-card'];let inspect=result.querySelectorAll('button.scan-subdomain');assert.equal(inspect.length,2);
 await inspect[0].handlers.click();assert.equal(JSON.parse(sub.requests[0].body).domain,payload);assert.equal(sub.ctx.pwned,undefined);
 const modal=sub.elements['modal-status'].innerHTML;const subHTML=result.innerHTML;
 const search=result.querySelector('input');search.value='other.example.com';search.handlers.input();assert.equal(result.querySelectorAll('button.scan-subdomain').length,1);
 const select=result.querySelector('select');search.value='';select.value='wildcard';select.handlers.change();assert.equal(result.querySelectorAll('button.scan-subdomain').length,0);
 assert.equal(sub.ctx.WebAssessmentUI.csvCell('=HYPERLINK("x")'),'"\'=HYPERLINK(""x"")"');
 console.log(JSON.stringify({payload,qrStats,subHTML,modal}));
})().catch(error=>{console.error(error);process.exitCode=1;});
