const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
function page(filename){
 const nodes={};const node=id=>nodes[id]||=( {innerHTML:'',textContent:'',style:{},className:'',value:'',offsetTop:0,addEventListener(){},classList:{add(){},remove(){}}} );
 const ctx={console,URL,Math,setTimeout(){},window:{scrollTo(){}},document:{getElementById:node,querySelectorAll(){return[];}},navigator:{clipboard:{writeText(){return Promise.resolve();}}}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync('static/scan_ui.js','utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
 for(const match of fs.readFileSync('templates/'+filename,'utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(match[1].trim())vm.runInContext(match[1],ctx);
 return {ctx,nodes};
}
const ip=page('ip_check.html');ip.ctx.renderResult({verdict:'unknown',reputation_status:'unavailable',blacklist_count:null,is_proxy:null,is_hosting:null});ip.ctx.renderBlacklist({reputation_status:'unavailable',blacklist_count:null});assert.equal(ip.nodes['score-num'].textContent,'Not assessed');assert.equal(ip.nodes['bl-badge'].textContent,'NOT VERIFIED');assert(!ip.nodes['bl-list'].innerHTML.includes('clean'));
ip.ctx.renderBlacklist({reputation_status:'not_found',blacklist_count:0});assert.equal(ip.nodes['bl-badge'].textContent,'NO DATASET MATCH');
ip.ctx.renderBlacklist({reputation_status:'matched',blacklist_count:1,blacklist_results:[{name:'AbuseIPDB',listed:true}]});assert(ip.nodes['bl-badge'].className.includes('listed'));
require('./test_domain_workspace.cjs');
const tls=page('ssl_checker.html');tls.ctx.renderResult({status:'unavailable',valid:null});assert.equal(tls.nodes['result-card'].style.display,'none');assert(tls.nodes['error-msg'].textContent.includes('not established'));
const file=require('./file_workspace_harness.cjs').workspace();file.ctx.testAPI.render({verdict:'unknown',security_score:100,coverage_status:'partial',malwarebazaar:{status:'unavailable',is_malicious:null}});assert.equal(file.get('score-num').textContent,'—');assert(file.get('provider-summary').textContent.includes('Not verified'));assert(!file.get('provider-summary').textContent.includes('Clean'));

