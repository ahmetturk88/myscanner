const assert=require('node:assert/strict');const {workspace}=require('./file_workspace_harness.cjs');
async function main(){
 const w=workspace(),{ctx,nodes,get}=w,api=ctx.testAPI;
 const partial={verdict:'unknown',security_score:100,coverage_status:'partial',malwarebazaar:{status:'unavailable'},metadata:{language:'Python'},hashes:{sha256:'a'.repeat(64)},yara:{matched_rules:[]},iocs:{urls:[],ipv4:[]}};
 api.render(partial);assert.equal(get('score-num').textContent,'—');assert.equal(get('score-fill').style.width,'0%');assert(get('provider-summary').textContent.includes('Not verified'));assert(!get('provider-summary').textContent.includes('Clean'));
 api.render({...partial,verdict:'safe',coverage_status:'completed',malwarebazaar:{status:'not_found'}});assert.equal(get('score-num').textContent,'100');assert(get('score-caption').textContent.includes('LOCAL'));assert(get('provider-summary').textContent.includes('not a safety verdict'));
 api.render({...partial,malwarebazaar:{status:'matched',is_malicious:true,signature:'Threat'}});assert.equal(get('report-title').textContent,'Known threat reported');assert.equal(get('verdict-banner').dataset.tone,'danger');
 for(const score of [null,'100',NaN,101,-1]){assert.equal(api.scorePresentation({...partial,verdict:'safe',coverage_status:'completed',malwarebazaar:{status:'not_found'},security_score:score}).available,false);}
 const payload='<img src=x onerror="globalThis.pwned=1"><svg onload=alert(1)>';
 api.render({...partial,filename:payload,metadata:{title:payload,nested:{value:payload}},warnings:[payload],recommendations:[payload],iocs:{urls:[payload]},hashes:{sha256:payload}});
 assert(get('report-identity').textContent.includes(payload));assert(!get('deep-analysis-container').innerHTML.includes('<img'));assert.equal(ctx.pwned,undefined);
 api.select({name:'x.txt',size:20});assert(get('upload-error').textContent.includes('not supported'));api.select({name:'x.py',size:0});assert(get('upload-error').textContent.includes('empty'));api.select({name:'x.py',size:11*1024*1024});assert(get('upload-error').textContent.includes('exceeds'));
 api.select({name:'test.py',size:50});assert.equal(get('start-scan').disabled,false);assert.equal(get('selected-name').textContent,'test.py');
 let resolve,calls=0;ctx.fetch=()=>{calls++;return new Promise(r=>{resolve=r;});};const pending=api.analyze();api.analyze();assert.equal(calls,1);assert.equal(get('start-scan').disabled,true);resolve({ok:true,json:async()=>partial});await pending;assert.equal(get('loading-div').hidden,true);assert.equal(get('start-scan').disabled,false);assert.equal(get('result-card').hidden,false);
 ctx.fetch=async()=>({ok:false,status:500,json:async()=>({error:'secret backend path'})});await api.analyze();assert(get('upload-error').textContent.includes('temporarily unavailable'));assert(!get('upload-error').textContent.includes('secret'));
 api.reset();assert.equal(get('result-card').hidden,true);assert.equal(get('start-scan').disabled,true);
 api.select({name:'test.py',size:50});
 ctx.fetch=async()=>({ok:true,json:async()=>({...partial,_pdf_receipt:'signed-fixture'})});
 await api.analyze();
 assert.equal(get('export-pdf').disabled,false);
 // Exercise the actual PDF download handler without contacting a server.
 let request;
 ctx.URL={createObjectURL:()=> 'blob:fixture',revokeObjectURL(){}};
 ctx.fetch=async(url,options)=>{request={url,options};return{ok:true,headers:{get:()=> 'application/pdf'},blob:async()=>new Blob(['%PDF-fixture'])};};
 await get('export-pdf').listeners.click();
 assert.equal(request.url,'/api/file-report/pdf');assert.equal(JSON.parse(request.options.body).receipt,'signed-fixture');
 assert.equal(get('export-pdf').disabled,false);
 ctx.fetch=async()=>({ok:false,status:400,headers:{get:()=> 'application/json'}});
 await get('export-pdf').listeners.click();assert(get('file-feedback').textContent.includes('expired'));
 api.render(partial);assert.equal(get('export-pdf').disabled,true);
 console.log('PASS: file workspace evidence, safe DOM, upload validation and request lifecycle');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
