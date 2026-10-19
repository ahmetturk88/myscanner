const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const elements={};const node=id=>elements[id]||=( {style:{},dataset:{},textContent:'',innerHTML:'',hidden:true,className:'',classList:{add(){},remove(){}},addEventListener(){},querySelector(){return null;},querySelectorAll(){return [];}} );
const details=[{textContent:'TLS certificate',hidden:false,open:false},{textContent:'Page content',hidden:false,open:false}];
let copied='';let shared=null;
const ctx={document:{getElementById:node,querySelectorAll:()=>details},window:{addEventListener(){},location:{search:''}},URL,URLSearchParams,console,setTimeout(){},navigator:{clipboard:{writeText(text){copied=text;return Promise.resolve();}}}};
vm.createContext(ctx);vm.runInContext(fs.readFileSync('static/scan_ui.js','utf8'),ctx);ctx.ScanUI=ctx.window.ScanUI;
vm.runInContext(fs.readFileSync('static/plain_report.js','utf8'),ctx);ctx.PlainReport=ctx.window.PlainReport;
let source=[...fs.readFileSync('templates/result.html','utf8').matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]).join('\n').replace(/{{ scan.id \| tojson }}/g,'1').replace(/{{ scan.status \| tojson }}/g,'"queued"').replace(/if \(initStatus[^\n]*\nelse[^\n]*/g,'');
vm.runInContext(source,ctx);
ctx.setLoadingState('queued');assert.equal(elements['phase-queue'].className,'active');assert.equal(elements['phase-analysis'].className,'');
ctx.setLoadingState('running');assert.equal(elements['phase-analysis'].className,'active');assert.equal(elements['phase-report'].className,'');
ctx.setLoadingState('report');assert.equal(elements['phase-report'].className,'active');assert(!elements['loading-text'].textContent.includes('%'));
ctx.filterEvidence('tls');assert(!details[0].hidden);assert(details[1].hidden);assert(details[0].open);ctx.filterEvidence('');assert(details.every(d=>!d.hidden));
ctx.expandEvidence(true);assert(details.every(d=>d.open));ctx.expandEvidence(false);assert(details.every(d=>!d.open));
for(const cell of ['=CMD()', '+test', '-test', '@x','  =CMD()'])assert(ctx.csvCell(cell).startsWith('"\''));assert.equal(ctx.csvCell('a"b'),'"a""b"');
assert(ctx.renderSourceOverview({deep_analysis:{osint:{urlhaus_status:'matched'}}}).includes('Dataset match reported'));
assert(ctx.renderSourceOverview({}).includes('Not verified'));assert(!ctx.renderSourceOverview({}).includes('No dataset match'));
vm.runInContext('allData={scan:{url:"https://example.org"},analysis:{aggregate_assessment:{score:95,verdict:"unknown",missing_checks:["Source unavailable"]}}}',ctx);
ctx.copyURLReport().then(()=>{assert(copied.includes('95/100'));assert(copied.includes('Source unavailable'));assert(copied.includes('not a probability'));});

const journey=ctx.renderJourney({url:'https://example.org/<img onerror=x>'},{deep_analysis:{behavior:{redirect_chain:[{url:'https://next.example/<script>x</script>',status_code:302}],final_url:'https://final.example/'}}});
assert(journey.includes('&lt;img'));assert(journey.includes('&lt;script'));assert(!journey.includes('<img'));assert(!journey.includes('href='));assert(journey.includes('302'));assert(journey.includes('https://final.example/'));

// Plain-language summary: every server value is escaped, unknown tones and states fall back safely.
const evil='<img src=x onerror=alert(1)>';
assert.equal(ctx.renderPlain(null,{}),false);
assert.equal(ctx.renderPlain({tone:'danger',label:evil,headline:evil,summary:evil,url:{prefix:'http://',host:evil,rest:evil},
  reasons:[{tone:'evil" onload="x',title:evil,detail:evil}],actions:[evil,7],checks:[{name:evil,state:'x',result:evil}],tally:evil,share_text:'Warning: hxxp://a[.]b'},
  {screenshot_url:'https://evil.example/x.png',date:'2026-10-18 19:40:00'}),true);
const plainHTML=elements['plain-report'].innerHTML;
assert(!plainHTML.includes('<img src=x'));assert(plainHTML.includes('&lt;img'));assert(!plainHTML.includes('onload="x'));
assert(!plainHTML.includes('evil.example'));assert(plainHTML.includes('Warn whoever sent it'));assert.equal(elements['plain-report'].dataset.tone,'danger');
assert.equal(elements['plain-report'].hidden,false);assert.equal(elements['rp-tools'].hidden,false);assert(elements['rp-top-when'].textContent.includes('2026-10-18'));
ctx.renderPlain({tone:'nonsense',actions:[],reasons:[],checks:[]},{screenshot_url:'/api/scan_screenshot/7'});
assert.equal(elements['plain-report'].dataset.tone,'unknown');assert(elements['plain-report'].innerHTML.includes('src="/api/scan_screenshot/7"'));
assert(elements['plain-report'].innerHTML.includes('Check another link'));
vm.runInContext('plainReport={share_text:"Warning: hxxp://a[.]b"}',ctx);
ctx.navigator.share=async data=>{shared=data;};
ctx.shareReport().then(()=>{assert.equal(shared.text,'Warning: hxxp://a[.]b');
  delete ctx.navigator.share;return ctx.shareReport();}).then(()=>{assert.equal(copied,'Warning: hxxp://a[.]b');});

// Shared renderer: unsafe "again" links fall back, the info state renders, h1 only when asked.
const sharedBox={dataset:{},hidden:true,innerHTML:'',querySelector(){return null;},querySelectorAll(){return [];}};
ctx.PlainReport.render(sharedBox,{tone:'safe',checks:[{name:'Links inside',state:'info',result:'3 links'}],actions:[]},{again:{href:'javascript:alert(1)',label:'x'}});
assert(!sharedBox.innerHTML.includes('javascript:'));assert(sharedBox.innerHTML.includes('href="/dashboard"'));
assert(sharedBox.innerHTML.includes('rp-cr rp-info'));assert(sharedBox.innerHTML.includes('<h2 class="rp-headline">'));
ctx.PlainReport.render(sharedBox,{tone:'danger'},{again:{href:'/file-scanner',label:'Check another file'},h1:true});
assert(sharedBox.innerHTML.includes('href="/file-scanner"'));assert(sharedBox.innerHTML.includes('<h1 class="rp-headline">'));
ctx.PlainReport.render(sharedBox,{tone:'danger'},{plainShare:true});assert(sharedBox.innerHTML.includes('Share this warning'));assert(!sharedBox.innerHTML.includes('Warn whoever'));
