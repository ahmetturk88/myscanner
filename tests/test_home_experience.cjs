const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../static/home_experience.js'),'utf8');
function element(){return {dataset:{},hidden:false,value:'',disabled:false,children:[],listeners:{},textContent:'',className:'',addEventListener(name,fn){this.listeners[name]=fn},setAttribute(name,value){this[name]=value},append(...nodes){this.children.push(...nodes)},replaceChildren(...nodes){this.children=nodes},focus(){this.focused=true}};}
async function run(response){
 const ids=Object.fromEntries(['tool-search','tool-empty','sample-url','url-input','home-scan-form','scan-submit-state','recent-status','recent-list','refresh-reports','recent-count','recent-threats','recent-review'].map(id=>[id,element()]));
 const submit=element();ids['home-scan-form'].querySelector=()=>submit;
 const cards=['Identity','Files'].map(category=>{const e=element();e.dataset={category,search:category.toLowerCase()};return e});
 const filters=['All','Files'].map(filter=>{const e=element();e.dataset.filter=filter;return e});
 const workspace=element();workspace.dataset={recentUrl:'/api/recent_scans',reportBase:'/result/0'};workspace.querySelectorAll=s=>s==='.hx-tool'?cards:filters;
 const context={document:{querySelector:()=>workspace,getElementById:id=>ids[id],createElement:()=>element()},window:{addEventListener(){}},AbortController,setTimeout(){return 1},clearTimeout(){},fetch:async()=>response};
 vm.runInNewContext(source,context);await new Promise(resolve=>setImmediate(resolve));
 return {ids,cards,filters,submit};
}
(async()=>{
 const payload='<img src=x onerror=alert(1)>';
 const r=await run({ok:true,json:async()=>({scans:[{id:7,url:payload,verdict:'unknown',date:payload},{id:'javascript:alert(1)',url:'bad'}]})});
 assert.equal(r.ids['recent-count'].textContent,'1');assert.equal(r.ids['recent-review'].textContent,'1');
 const link=r.ids['recent-list'].children[0];assert.equal(link.href,'/result/7');assert.equal(link.children[1].children[0].textContent,payload);
 r.filters[1].listeners.click();assert.equal(r.cards[0].hidden,true);assert.equal(r.cards[1].hidden,false);
 r.ids['tool-search'].value='no-match';r.ids['tool-search'].listeners.input();assert.equal(r.ids['tool-empty'].hidden,false);
 r.ids['sample-url'].listeners.click();assert.equal(r.ids['url-input'].value,'https://example.com/');
 r.ids['home-scan-form'].listeners.submit({currentTarget:r.ids['home-scan-form']});assert.equal(r.submit.disabled,true);
 const failed=await run({ok:false});assert.equal(failed.ids['recent-count'].textContent,'—');assert.equal(failed.ids['recent-list'].children.length,0);assert(failed.ids['recent-status'].textContent.includes('could not be loaded'));
 const empty=await run({ok:true,json:async()=>({scans:[]})});assert.equal(empty.ids['recent-count'].textContent,'0');assert(empty.ids['recent-status'].textContent.includes('No saved reports'));
 console.log('PASS: report rendering keeps provider text inert, rejects invalid IDs, distinguishes empty/error states; filters and scan submission work.');
})().catch(error=>{console.error(error);process.exit(1)});
