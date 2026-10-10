/* Execute the production renderers offline; inspect their markup in Python. */
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..');
const payload=`<img src=x onerror="globalThis.pwned=1"><svg onload="globalThis.pwned=1">'"\\&`;
const escape=value=>String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
function setup(filename){
 const elements={};
 class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.handlers={};this.style={};this.className='';this._text='';this._html='';this.offsetTop=20;this.classList={add(){},remove(){}};this.value='';this.checked=false;}
  set textContent(value){this._text=String(value);this.children=[];this._html='';}get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  set innerHTML(value){this._html=value;this.children=[];this._text='';}get innerHTML(){return this._html || escape(this._text)+this.children.map(c=>c.serialize()).join('');}
  append(...children){this.children.push(...children);}appendChild(child){this.children.push(child);return child;}replaceChildren(...children){this.children=children;this._html='';this._text='';}
  addEventListener(event,callback){this.handlers[event]=callback;}
  serialize(){return '<'+this.tagName+(this.className?' class="'+escape(this.className)+'"':'')+(this.type?' type="'+escape(this.type)+'"':'')+'>'+this.innerHTML+'</'+this.tagName+'>';}
 }
 const node=id=>elements[id] ||= new Element();
 const ctx={window:{scrollTo(){}},URL,console,Math,setTimeout(){},alert(){},document:{getElementById:node,createElement:tag=>new Element(tag),querySelectorAll(){return [];}},navigator:{clipboard:{writeText(){return Promise.resolve();}}}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(root,'static/scan_ui.js'),'utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
 const template=fs.readFileSync(path.join(root,'templates',filename),'utf8');
 for(const match of template.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(match[1].trim())vm.runInContext(match[1],ctx);
 if(filename==='domain_lookup.html'){vm.runInContext(fs.readFileSync(path.join(root,'static/domain_workspace.js'),'utf8'),ctx);ctx.renderResult=ctx.window.renderResult;}
 return {ctx,elements,node};
}
const sections=[];
function collect(page,label){for(const [id,node] of Object.entries(page.elements))if(node.innerHTML)sections.push({name:label+' '+id,html:node.innerHTML});assert.equal(page.ctx.pwned,undefined);}
const ip=setup('ip_check.html');
ip.ctx.renderResult({verdict:'__proto__',country_code:payload,ip:payload,country:payload,city:payload,region:payload,timezone:payload,isp:payload,org:payload,blacklist_count:payload,lat:payload,lon:payload});
ip.ctx.renderBlacklist({blacklist_count:1,blacklist_results:[{name:payload,listed:true},null]});ip.ctx.renderMap({lat:payload,lon:payload});
assert.equal(ip.elements['map-frame'].src,'');assert.equal(ip.elements['map-card'].style.display,'none');assert.equal(ip.elements['verdict-banner'].className,'verdict-banner banner-unknown');collect(ip,'IP');
ip.ctx.renderResult({country_code:'DE'});assert(ip.elements['stats-grid'].innerHTML.includes('https://flagcdn.com/24x18/de.png'));
for(const [lat,lon] of [[0,0],['0','0'],[90,180],[-90,-180]]){
 ip.ctx.renderMap({lat,lon});const url=new URL(ip.elements['map-frame'].src);assert.equal(url.hostname,'www.openstreetmap.org');assert.equal(url.searchParams.get('marker'),Number(lat)+','+Number(lon));
}
for(const value of [payload,'NaN','Infinity',null,{},true,[],91])assert.equal(ip.ctx.ScanUI.mapURL(value,0),'');
for(const value of [payload,'en/../../x','123','USA','US\n',{},null])assert.equal(ip.ctx.ScanUI.countryFlag(value),'');
const email=setup('email_check.html');
email.ctx.renderMain({verdict:'constructor',quality_score:payload,deliverability:payload,blacklisted:true,blacklist_count:payload,email:payload,domain:payload,address_risk:payload,registrar:payload,domain_age:payload,spf_record:payload,dmarc_record:payload,quality_breakdown:{},smtp_details:{mx_servers:[{preference:payload,server:payload}],message:payload}});
assert.equal(email.elements['q-bar'].style.width,'0%');
email.ctx.showSuggestions([{original:payload,suggested:payload,type:'domain_typo'}]);const suggestion=email.elements['suggestions-list'].children[0].children[1];
assert.equal(suggestion.tagName,'button');assert.equal(suggestion.type,'button');let checked=false;email.ctx.checkEmail=()=>{checked=true;};suggestion.handlers.click();assert.equal(email.elements['email-input'].value,payload);assert(checked);collect(email,'email');
email.ctx.renderMain({smtp_details:{mx_servers:{}},quality_score:100});assert.equal(email.elements['q-bar'].style.width,'100%');assert.equal(email.elements['smtp-details'].style.display,'none');assert.equal(email.elements['quality-breakdown'].style.display,'none');
email.ctx.renderMain({email:payload,assessment:{score:82,coverage:'partial',verdict:'review',categories:[{label:payload,weight:20,risk_deduction:10,coverage_deduction:5}],findings:[{message:payload,deduction:10}],missing_checks:[payload],not_checked:[payload]}});
assert.equal(email.elements['q-bar'].style.width,'82%');assert(email.elements['stats-grid'].innerHTML.includes('&lt;img'));assert(email.elements['quality-items'].innerHTML.includes('&lt;img'));assert(email.elements['coverage-details'].innerHTML.includes('&lt;img'));
for(const value of ['=SUM(A1)', '+cmd', '-2', '@x', '  =cmd'])assert(email.ctx.csvCell(value).startsWith('"\''));
assert.equal(email.ctx.csvCell('hello'), '"hello"');
email.ctx.renderMain({email:payload,dns_evidence:{spf:{audit:{status:'partial',issues:[payload],dependencies:[{domain:payload,status:payload}]}},mx:{infrastructure:[{host:payload,addresses:[payload]}]}},reputation_evidence:{scope:payload,queried_ips:[payload],checks:[{source:payload,reason:payload,status:payload,response_codes:[payload]}]}});
collect(email,'email engine');assert(email.elements['dns-evidence'].innerHTML.includes('&lt;img'));assert(email.elements['reputation-evidence'].innerHTML.includes('&lt;img'));

email.ctx.renderMain({blacklisted:true,reputation_evidence:{blacklisted_on:[payload],checks:[{source:payload,ip:payload,status:'listed'}]}});
assert(email.elements['blocklist-status'].className.includes('blocklist-listed'));assert(email.elements['blocklist-title'].textContent.includes('Warning'));assert(email.elements['blocklist-summary'].textContent.includes(payload));collect(email,'email blocklist');
email.ctx.renderMain({blacklisted:false,reputation_evidence:{coverage_status:'completed',clean_on:['zen.spamhaus.org'],queried_ips:['8.8.8.8'],checks:[{status:'not_found'}]}});assert(email.elements['blocklist-status'].className.includes('blocklist-clear'));
email.ctx.renderMain({blacklisted:false,reputation_evidence:{coverage_status:'partial'}});assert(email.elements['blocklist-status'].className.includes('blocklist-partial'));assert(!email.elements['blocklist-title'].textContent.includes('no listing'));
const domain=setup('domain_lookup.html');
domain.ctx.renderResult({registrar:payload,created:payload,expires:payload,ip:payload,country:payload,isp:payload,status:payload,whois_updated:payload,nameservers:payload,dns:[{type:'TXT',value:payload},{type:'A',value:payload},{type:'__proto__',value:payload},{type:'constructor',value:payload}],lat:payload,lon:payload});
collect(domain,'domain');
domain.ctx.renderResult({dns:{},nameservers:{}});
const ssl=setup('ssl_checker.html');
ssl.ctx.renderResult({valid:true,grade:payload,days_remaining:payload,domain:payload,issuer:payload,expiry_date:payload,tls_version:payload,valid_from:payload,valid_until:payload,serial_number:payload});
assert(ssl.elements['result-card'].innerHTML.includes('grade-unknown'));assert(!ssl.elements['result-card'].innerHTML.includes('grade-<'));collect(ssl,'SSL');
ssl.ctx.renderResult({valid:true,grade:'A+',days_remaining:100});assert(ssl.elements['result-card'].innerHTML.includes('grade-a'));
const password=setup('password_check.html');
password.ctx.renderResult({final:{color:'constructor',icon:payload,strength:payload,score:payload},password_length:payload,length:{status:payload},variety:{},entropy:{entropy_bits:payload,crack_time:payload},pwned:{is_pwned:true,count:payload},patterns:{has_issues:true,issues:[payload]},recommendations:[payload]});
assert(password.elements['result-card'].innerHTML.includes('width:0%'));assert(!password.elements['result-card'].innerHTML.includes('background: function'));collect(password,'password');
password.ctx.renderResult({final:{score:200},patterns:{has_issues:true,issues:{}},recommendations:{}});assert(password.elements['result-card'].innerHTML.includes('width:100%'));
for(const [data,label] of [[{},'Lookup unavailable'],[{status:'unavailable',is_pwned:null},'Lookup unavailable'],[{status:'skipped',is_pwned:null},'Not checked'],[{status:'not_found',is_pwned:false},'No dataset match'],[{status:'found',is_pwned:true,count:42},'Exposure detected']]) {
 password.ctx.renderResult({pwned:data});const html=password.elements['result-card'].innerHTML;assert(html.includes(label));assert(!html.includes('Clean'));
 assert.equal(password.ctx.breachPresentation(data).label,label);
}
let copied='';password.ctx.navigator.clipboard.writeText=value=>{copied=value;return Promise.resolve();};
vm.runInContext('lastResult = {final:{},variety:{},entropy:{},pwned:{status:"unavailable",is_pwned:null}}',password.ctx);
password.ctx.copyReport();assert(copied.includes('Lookup unavailable'));assert(copied.includes('unknown'));assert(!copied.includes('Clean'));
password.ctx.renderResult({});
console.log(JSON.stringify({payload,sections}));

