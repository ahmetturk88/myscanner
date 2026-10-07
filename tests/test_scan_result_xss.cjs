// Evaluates the real inline renderers with a DOM stub; never performs a scan.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '..');
const payload = '<img src=x onerror="globalThis.pwned=1"><svg onload="globalThis.pwned=1">"\'&';
function context(filename) {
    const elements = {};
    const element = id => elements[id] ||= {innerHTML:'', textContent:'', style:{},
        classList:{add(){},remove(){},toggle(){}}, addEventListener(){}, offsetTop:20, files:[]};
    const ctx = {window:{addEventListener(){},scrollTo(){}}, document:{
        getElementById:element, querySelectorAll:()=>[], querySelector:()=>null,
    }, URL, URLSearchParams, console, setTimeout(){}, setInterval(){}, clearInterval(){},
        navigator:{}, localStorage:{}, fetch(){throw Error('Unexpected network request');} };
    ctx.window.location = {search:''};
    vm.createContext(ctx);
    vm.runInContext(fs.readFileSync(path.join(root,'static/scan_ui.js'),'utf8'), ctx);
    ctx.ScanUI = ctx.window.ScanUI;
    const template = fs.readFileSync(path.join(root,'templates',filename),'utf8');
    const scripts = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]).join('\n')
        .replace(/{{ scan.id \| tojson }}/g,'1').replace(/{{ scan.status \| tojson }}/g,'"pending"')
        .replace(/if \(initStatus[^\n]*\nelse[^\n]*/g, '');
    vm.runInContext(scripts, ctx, {filename});
    return {ctx, elements};
}
const outputs = [];
const site = context('site_scanner.html');
site.ctx.showError(payload);
outputs.push({name:'site error', html:site.elements['result-card'].innerHTML});
site.ctx.renderResult({security_score:payload, verdict:'secure',
    ssl:{valid:true, issuer:payload, tls_version:payload, grade:payload, days_remaining:payload},
    performance:{server:payload, grade:payload, status_code:payload, load_time_ms:payload},
    security_headers:{grade:payload,headers:{strict_transport_security:payload,content_security_policy:payload,x_frame_options:payload}},
    dns:{a_records:[payload],mx_records:[{exchange:payload,preference:payload}]},
    seo:{title:payload,description:payload,seo_score:payload,internal_links:payload,external_links:payload}, recommendations:[payload]});
outputs.push({name:'site results',html:site.elements['result-card'].innerHTML});
const url = context('result.html');
const analysis = {security_score:payload,verdict:payload,
    urlvet:{trust_score:payload,verdict_raw:payload,red_flags:[payload],green_flags:[payload],neutral_reasons:[payload],
        domain_info:{age_human:payload,registrar:payload},ssl_info:{has_tls:true,issuer:payload,not_after:payload},
        url_features:{subdomain_count:payload,has_keywords:true,keywords_found:[payload]},
        analysis:{is_redirected:true,chain_length:payload,http_status:payload},screenshot:'javascript:globalThis.pwned=1'},
    ssl_info:{valid:true,issuer:payload,tls_version:payload,days_remaining:payload}, dns_records:{a_records:[payload]},
    recommendations:[payload],phishing_indicators:{is_phishing_suspected:true,issues:[payload]},
    deep_analysis:{page_content:{title:payload,content_risk_score:payload},behavior:{redirect_count:payload,behavior_risk_score:payload},
        whois_deep:{age_days:payload,registrar:payload,whois_risk_score:payload},osint:{osint_risk_score:payload}}};
url.ctx.renderResult({status:'completed',verdict:'safe'},analysis);
for(const [id,el] of Object.entries(url.elements)) if(el.innerHTML) outputs.push({name:'URL '+id,html:el.innerHTML});
assert(!url.elements['extra-sections'].innerHTML.includes('<img'));
analysis.urlvet.screenshot='https://images.example/screenshot.png?x=%22';
url.ctx.renderResult({status:'completed',verdict:'safe'},analysis);
assert(url.elements['extra-sections'].innerHTML.includes('https://images.example/screenshot.png'));
outputs.push({name:'URL screenshot',html:url.elements['extra-sections'].innerHTML});
const file = context('file_scanner.html');
const data = {security_score:payload,verdict:'safe',file_size_mb:payload,
    metadata:{is_pdf:true,is_script:true,is_archive:true,is_image:true,num_pages:payload,lines:payload,num_files:payload,width:payload,height:payload,
        type:payload,language:payload,format:payload,metadata:{title:payload,author:payload}},
    reputation:{sources:[payload],risk_score:payload},
    yara:{matched_rules:[payload],risk_score:payload}, malwarebazaar:{tags:[payload],signature:payload,file_name:payload,reporter:payload},
    hashes:{md5:payload,sha256:payload},file_type:{actual_type:payload,mime_type:payload,extension:payload},
    iocs:{urls:[payload],ipv4:[payload],domains:[payload],emails:[payload]},recommendations:[payload],warnings:[payload],
    pe:{is_pe:true,machine:payload,number_of_sections:payload,entry_point:payload},exiftool:{available:true,data:{title:payload}}};
file.ctx.renderResult(data); file.ctx.renderFullDeepAnalysis(data);
for(const [id,el] of Object.entries(file.elements)) if(el.innerHTML) outputs.push({name:'file '+id,html:el.innerHTML});
assert.equal(file.elements['score-fill'].style.width,'0%');
// Valid values retain their original display and layout.
site.ctx.renderResult({security_score:85,verdict:'secure',seo:{title:'Normal & useful',description:'Readable'},recommendations:['Keep HTTPS']});
assert(site.elements['result-card'].innerHTML.includes('width:85%'));
assert(site.elements['result-card'].innerHTML.includes('Normal &amp; useful'));
const helper = url.ctx.ScanUI;
assert.equal(helper.escape(0),'0');
assert.equal(helper.score(150),100); assert.equal(helper.score(-5),0);
for(const value of ['javascript:alert(1)','data:image/svg+xml,test','//evil.example/image','https://user:pass@example.com/image','https://example.com/" onerror="x']) assert.equal(helper.webURL(value),'');
assert.equal(helper.webURL('https://example.com/image?a=1&b=2'),'https://example.com/image?a=1&b=2');
let tableOptions;
const tableContext = {document:{}, ScanUI:helper, setInterval(){}, console,
    $: () => ({ready:callback=>callback(), on(){}, DataTable(options){ tableOptions=options; return {}; }})};
const tableSource = fs.readFileSync(path.join(root,'static/javascript.js'),'utf8').replace('    refreshScans();','');
vm.runInNewContext(tableSource,tableContext);
for(const column of tableOptions.columns) {
    const html = column.render(payload,'display',{id:payload});
    outputs.push({name:'history '+column.data,html});
}
assert(!tableOptions.columns[1].render('javascript:alert(1)').includes('href='));
assert(tableOptions.columns[1].render('https://example.com/?a=1&b=2').includes('a=1&amp;b=2'));
for(const output of outputs) assert(!output.html.includes('<svg'),output.name);
// Conflicting and verified evidence must override even a perfect numeric score.
const conflicting = url.ctx.renderURLVet({trust_score:100, verdict:'harmless', phishing:{in_database:true,verified:false}});
assert(conflicting.includes('Assessment needs review'));
assert(conflicting.includes('Reported entry — unverified'));
assert(!conflicting.includes('Safe — Trusted'));
const verified = url.ctx.renderURLVet({trust_score:100, verdict:'harmless', phishing:{in_database:true,verified:true}});
assert(verified.includes('Risky — Likely unsafe'));
assert(verified.includes('Verified phishing entry'));
const missing = url.ctx.renderURLVet({trust_score:100, verdict:'unknown'});
assert(missing.includes('Not assessed'));
assert(missing.includes('Assessment unavailable'));
if(process.argv.includes('--json')) console.log(JSON.stringify(outputs));
else console.log(`${outputs.length} result sections rendered safely with malicious fixtures; helper and normal-display checks passed`);
