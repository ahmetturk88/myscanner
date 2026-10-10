/* File workspace: provider data is rendered as text, never executable markup. */
(function () {
  'use strict';
  const root = document.getElementById('file-workspace');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const allowed = new Set('exe dll pdf doc docx xls xlsx zip rar 7z js py ps1 sh bat vbs scr msi'.split(' '));
  const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const list = value => Array.isArray(value) ? value : [];
  const text = value => value == null ? '' : String(value);
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const human = key => key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  function node(tag, cls, content) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (content != null) el.textContent = text(content);
    return el;
  }
  function size(bytes) {
    if (!finite(bytes) || bytes < 0) return 'Size unavailable';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KiB';
    return (bytes / 1048576).toFixed(2) + ' MiB';
  }
  function date(value) {
    if (!value) return 'Time not reported';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? 'Time not reported' : d.toLocaleString();
  }
  function state(label, tone) { const el = node('span', 'fw-state', label); el.dataset.tone = tone; return el; }
  function feedback(message) {
    clearTimeout(feedback.timer); $('file-feedback').textContent = message;
    feedback.timer = setTimeout(() => { $('file-feedback').textContent = ''; }, 4500);
  }
  async function copy(value, success) {
    try { await navigator.clipboard.writeText(value); feedback(success); }
    catch (_) { feedback('Clipboard unavailable. Use Export JSON to save the report.'); }
  }
  let selected = null, busy = false, lastResult = null, started = 0, timer = null;
  function error(message) { $('upload-error').textContent = message; $('upload-error').hidden = !message; }
  function setBusy(value) {
    busy = value; root.setAttribute('aria-busy', String(value));
    ['choose-file','remove-file','file-input','new-scan'].forEach(id => { $(id).disabled = value; });
    $('start-scan').disabled = value || !selected;
    $('start-scan').textContent = value ? 'Inspection in progress…' : 'Inspect this file →';
  }
  function select(file) {
    if (busy || !file) return;
    error('');
    const ext = text(file.name).split('.').pop().toLowerCase();
    let message = '';
    if (!file.size) message = 'This file is empty. Choose a non-empty file.';
    else if (file.size > 10 * 1024 * 1024) message = 'This file exceeds 10 MiB. Choose a smaller file.';
    else if (!text(file.name).includes('.') || !allowed.has(ext)) message = 'This file type is not supported. Check the supported file types below.';
    if (message) { error(message); $('file-input').value = ''; return; }
    selected = file;
    lastResult = null; $('result-card').hidden = true;
    $('file-info').hidden = false;
    $('selected-extension').textContent = ext.toUpperCase();
    $('selected-name').textContent = file.name;
    $('selected-meta').textContent = size(file.size) + ' · ' + (file.type || 'Browser type not reported') + ' · Modified ' + date(file.lastModified);
    $('start-scan').disabled = false;
  }
  function reset() {
    if (busy) return;
    selected = null; lastResult = null; $('file-input').value = '';
    $('file-info').hidden = true; $('result-card').hidden = true; $('loading-div').hidden = true;
    $('evidence-search').value = ''; $('start-scan').disabled = true; error('');
  }
  $('choose-file').addEventListener('click', () => { if (!busy) $('file-input').click(); });
  $('file-input').addEventListener('change', e => select(e.target.files[0]));
  $('remove-file').addEventListener('click', reset);
  $('new-scan').addEventListener('click', () => { reset(); $('choose-file').focus(); $('upload-area').scrollIntoView({behavior: 'auto', block: 'center'}); });
  const drop = $('upload-area');
  drop.addEventListener('dragover', e => { e.preventDefault(); if (!busy) drop.classList.add('drag-over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('drag-over'); if (busy) return;
    if (e.dataTransfer.files.length !== 1) { error('Choose one file at a time.'); return; }
    select(e.dataTransfer.files[0]);
  });
  $('start-scan').addEventListener('click', analyze);
  async function analyze() {
    if (!selected || busy) return;
    error(''); lastResult = null; $('result-card').hidden = true;
    setBusy(true); $('loading-div').hidden = false;
    started = Date.now(); $('elapsed-time').textContent = '0s';
    $('loading-message').textContent = 'Sending your file and waiting for the analysis response.';
    timer = setInterval(() => {
      const seconds = Math.floor((Date.now() - started) / 1000);
      $('elapsed-time').textContent = seconds + 's';
      if (seconds >= 20) $('loading-message').textContent = 'Still waiting for the server. Source availability and file complexity can affect the response time.';
    }, 1000);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 150000);
    const form = new FormData(); form.append('file', selected);
    try {
      // The application fetch wrapper in csrf.js supplies the CSRF header.
      const response = await fetch('/api/scan-file', { method: 'POST', body: form, signal: controller.signal, credentials: 'same-origin' });
      if (response.redirected) throw new Error('Your session may have expired. Sign in again before starting another scan.');
      let data;
      try { data = await response.json(); } catch (_) { throw new Error('The server did not return a readable report. Try again after checking service status.'); }
      if (!response.ok || (data && data.error)) {
        const message = response.status === 401 ? 'Sign in before scanning a file.' : response.status === 413 ? 'The server rejected the file size. Maximum: 10 MiB.' : response.status >= 500 ? 'File analysis is temporarily unavailable. Try again later.' : data && typeof data.error === 'string' ? data.error : 'The file scan request was rejected.';
        throw new Error(message);
      }
      if (!data || typeof data !== 'object' || Array.isArray(data) || typeof data.verdict !== 'string') throw new Error('The server returned an incomplete report. No safety conclusion is available.');
      lastResult = data; render(data);
      $('result-card').hidden = false;
      $('report-title').focus({preventScroll: true});
      $('result-card').scrollIntoView({behavior: 'auto', block: 'start'});
    } catch (err) {
      error(err.name === 'AbortError' ? 'The response timed out. The server may still be processing the request; check service status before submitting again.' : err instanceof TypeError ? 'The network request failed. Check your connection and service status.' : err.message);
    } finally {
      clearTimeout(timeout); clearInterval(timer); timer = null;
      $('loading-div').hidden = true; setBusy(false);
    }
  }

  function provider(d) { return object(d.malwarebazaar || object(d.hash_reputation).provider); }
  function confirmed(d) { return d.verdict === 'malicious' || (provider(d).status === 'matched' && provider(d).is_malicious === true) || (object(d.hash_reputation).status === 'matched' && object(d.hash_reputation).is_malicious === true); }
  function scorePresentation(d) {
    const missing = list(d.missing_checks);
    const incomplete = d.coverage_status !== 'completed' || missing.length > 0 || !['matched','not_found'].includes(provider(d).status);
    const assessment = object(d.assessment);
    const available = finite(assessment.score) && assessment.score >= 0 && assessment.score <= 100;
    return {available, value:available ? assessment.score : null, incomplete};
  }
  function render(d) {
    $('export-pdf').disabled = typeof d._pdf_receipt !== 'string';
    const score = scorePresentation(d), mb = provider(d), meta = object(d.metadata), ft = object(d.file_type), patterns = object(d.yara), iocs = object(d.iocs);
    const danger = confirmed(d);
    const review = !danger && ['high_risk','suspicious'].includes(d.verdict);
    const title = danger ? 'Known threat reported' : review ? 'Indicators need review' : score.incomplete || d.verdict === 'unknown' ? 'Evidence needs verification' : 'No indicators reported';
    $('verdict-banner').dataset.tone = danger ? 'danger' : review ? 'review' : score.incomplete ? 'unknown' : 'neutral';
    $('report-title').textContent = title;
    $('verdict-description').textContent = danger ? 'The report contains a malicious verdict or a confirmed hash match. Keep this file unexecuted and review the source evidence below.' : review ? 'Static checks reported risk indicators. Review their context before deciding how to handle the file.' : score.incomplete ? 'The available checks returned a report, but some evidence could not be verified. A full safety conclusion is not available.' : 'No indicators were reported by the available checks. This does not establish that the file is safe to open.';
    $('coverage-badge').textContent = score.incomplete ? 'Limited evidence coverage' : 'Configured checks returned';
    $('score-caption').textContent = 'EVIDENCE & COVERAGE INDEX';
    $('score-num').textContent = score.available ? String(score.value) + '%' : '—';
    $('score-unit').hidden = true;
    $('score-fill').style.width = score.available ? score.value + '%' : '0%';
    $('score-note').textContent = score.available ? 'Evidence index: ' + score.value + '/100. Coverage deductions: ' + text(object(d.assessment).coverage_penalty ?? 0) + ' points. Not a probability of safety.' : 'Not assigned. Missing evidence is not converted into a perfect score.';
    const identity = $('report-identity'); identity.replaceChildren(node('strong', '', d.filename || selected?.name || 'Unnamed file'), node('span', '', size(finite(d.file_size_bytes) ? d.file_size_bytes : finite(d.file_size) ? d.file_size : selected?.size)), node('span', '', 'Reported: ' + date(d.scanned_at || d.analyzed_at)));
    const grid = $('stats-grid'); grid.replaceChildren();
    const stats = [[Array.isArray(patterns.matched_rules) ? patterns.matched_rules.length : '—','Local byte patterns'],[Array.isArray(iocs.urls) ? iocs.urls.length : '—','Embedded URLs'],[Array.isArray(iocs.ipv4) ? iocs.ipv4.length : '—','Embedded IPv4 addresses'],[meta.error ? 'Unavailable' : meta.language || (ft.actual_type && ft.actual_type !== 'unknown' ? ft.actual_type : 'Not reported'),'Format / language observation']];
    stats.forEach(([value,label]) => { const card=node('div','fw-stat');card.append(node('strong','fw-stat-value',value),node('span','',label));grid.append(card); });
    const sources = $('provider-summary'); sources.replaceChildren();
    source(sources,'MalwareBazaar', mb.status === 'matched' && mb.is_malicious === true ? 'Matched' : mb.status === 'not_found' ? 'No dataset match' : 'Not verified', mb.status === 'matched' && mb.is_malicious === true ? 'danger' : mb.status === 'not_found' ? 'neutral' : 'unknown', mb.status === 'not_found' ? 'The queried hash was not found in this dataset. This is not a safety verdict.' : mb.status === 'matched' && mb.is_malicious === true ? 'A malicious hash match was reported. See the signature and source details.' : 'A verified hash lookup result was not returned. No negative match is inferred.');
    source(sources,'Local metadata',meta.error ? 'Unavailable' : Object.keys(meta).length ? 'Returned' : 'Not reported',meta.error || !Object.keys(meta).length ? 'unknown' : 'neutral','Static metadata only. File-specific parser fields appear in the evidence sections.');
    source(sources,'Byte pattern inspection',patterns.error || !Array.isArray(patterns.matched_rules) ? 'Not verified' : patterns.matched_rules.length ? 'Patterns reported' : 'No patterns reported',patterns.error || !Array.isArray(patterns.matched_rules) ? 'unknown' : patterns.matched_rules.length ? 'review' : 'neutral','Local byte heuristics; this is not a YARA engine or a sandbox execution result.');
    const next=$('recommendations'); next.replaceChildren(); const ul=node('ul','fw-list');
    list(d.missing_checks).slice(0,20).forEach(item=>ul.append(node('li','',item)));
    const recs=list(d.recommendations); recs.slice(0,12).forEach(item=>ul.append(node('li','',item)));
    if (!recs.length) ul.append(node('li','',danger ? 'Keep the file unexecuted and review the threat evidence.' : 'Review source status and metadata before deciding whether to open the file.'));
    ul.append(node('li','','No sandbox execution or multi-engine antivirus verdict is provided.')); next.append(ul);
    const findings=$('threats'); findings.replaceChildren();
    list(patterns.matched_rules).slice(0,30).forEach(rule=>finding(findings,'Local byte pattern',rule));
    list(meta.suspicious).slice(0,20).forEach(item=>finding(findings,'Metadata observation',item));
    if(mb.status==='matched' && mb.is_malicious===true) finding(findings,'MalwareBazaar hash match',mb.signature || 'Signature not reported');
    $('detection-list').hidden=!findings.childElementCount;
    renderEvidence(d); $('evidence-search').value=''; filter();
  }
  function source(parent,title,label,tone,description){const box=node('div','fw-source'),body=node('div','');body.append(node('strong','',title),node('p','',description));box.append(state(label,tone),body);parent.append(box);}
  function finding(parent,label,value){const box=node('div','fw-finding');box.append(node('strong','',label),node('p','',value));parent.append(box);}
  function section(id,title,subtitle,description,open=false){const box=node('details','fw-detail');box.id='evidence-'+id;box.open=open;const summary=node('summary',''),heading=node('div','');heading.append(node('strong','',title),node('span','',subtitle));summary.append(heading);const body=node('div','fw-detail-body');if(description)body.append(node('p','fw-detail-description',description));box.append(summary,body);$('deep-analysis-container').append(box);return body;}
  function valueText(value){if(value===true)return 'Yes';if(value===false)return 'No';if(value==null || value==='')return 'Not reported';return text(value);}
  function rows(parent,data,depth=0){const dl=node('dl','fw-data-list');let count=0;for(const [key,value] of Object.entries(object(data)).slice(0,60)){if(count++>60)break;if(value && typeof value==='object'){
      if(depth>=3){const row=node('div','fw-data-row');row.append(node('dt','',human(key)),node('dd','',JSON.stringify(value).slice(0,4000)));dl.append(row);continue;}
      const group=node('details','fw-data-group');group.append(node('summary','',human(key)+(Array.isArray(value)?' ('+value.length+')':'')));
      if(Array.isArray(value)){value.slice(0,40).forEach(item=>{if(item&&typeof item==='object')rows(group,item,depth+1);else group.append(node('p','fw-detail-description',valueText(item)));});if(!value.length)group.append(node('p','fw-detail-description','No entries reported.'));if(value.length>40)group.append(node('p','fw-detail-description','Showing the first 40 entries. Export JSON for the full response.'));}else rows(group,value,depth+1);
      dl.append(group);
    }else{const row=node('div','fw-data-row');row.append(node('dt','',human(key)),node('dd','',valueText(value)));dl.append(row);}}
    if(!Object.keys(object(data)).length)dl.append(node('p','fw-empty','No fields reported.'));parent.append(dl);}
  function renderEvidence(d){
    const container=$('deep-analysis-container');container.replaceChildren();
    const hashes=object(d.hashes),meta=object(d.metadata),ft=object(d.file_type),mb=provider(d);
    const hashBody=section('hashes','Cryptographic fingerprints','Copy a fingerprint · Compare the exact file','Fingerprints identify the bytes that were analyzed. They are not a safety rating.',true), hashGrid=node('div','fw-hash-grid');
    ['sha256','sha512','sha1','md5','blake2b'].forEach(key=>{const hash=node('div','fw-hash'),value=typeof hashes[key]==='string'?hashes[key]:'Not reported';hash.append(node('strong','',key.toUpperCase()),node('code','',value));const btn=node('button','fw-button fw-button-quiet','Copy');btn.type='button';btn.setAttribute('aria-label','Copy '+key.toUpperCase()+' fingerprint');btn.disabled=!/^[a-f0-9]{32,128}$/i.test(value);btn.addEventListener('click',()=>copy(value,key.toUpperCase()+' copied.'));hash.append(btn);hashGrid.append(hash);});hashBody.append(hashGrid);
    rows(section('type','File identity','Extension and reported format','An extension and a detected format are separate observations. Unknown types remain unknown.'),ft);
    rows(section('metadata','Metadata & structure',meta.error?'Parser evidence unavailable':meta.language?'Reported language: '+meta.language:'Reported static metadata','Fields reflect the parser response. A missing field is not a negative finding.'),meta);
    const iocBody=section('iocs','Embedded indicators','Network strings, hashes and other extracted references','Indicators are shown as text and are not opened. Their presence alone does not establish malicious intent.'),iocs=object(d.iocs);
    const keys={urls:'URLs',domains:'Domains',ipv4:'IPv4 addresses',ipv6:'IPv6 addresses',emails:'Email addresses',md5_hashes:'MD5 strings',sha1_hashes:'SHA1 strings',sha256_hashes:'SHA256 strings',bitcoin_addresses:'Bitcoin addresses',onion_addresses:'Onion addresses',telegram_links:'Telegram references',discord_webhooks:'Discord webhook references'};
    for(const [key,label] of Object.entries(keys)){const group=node('div','fw-ioc-group'),arr=iocs[key];group.append(node('h4','',label));if(!Array.isArray(arr))group.append(node('p','','Not reported.'));else if(!arr.length)group.append(node('p','','No entries reported by extraction.'));else{const chips=node('div','fw-ioc-chips');arr.slice(0,40).forEach(item=>chips.append(node('code','',item)));group.append(chips);if(arr.length>40)group.append(node('p','','Showing 40 entries. Export JSON for all reported indicators.'));}iocBody.append(group);}
    rows(section('patterns','Local byte patterns','Heuristic observations','These are local byte-pattern checks, not a YARA signature engine. No matches do not establish safety.'),object(d.yara));
    rows(section('reputation','Hash reputation','MalwareBazaar · Source evidence','Matched, no dataset match and unavailable are distinct states. A dataset negative is specific to the queried hash.'),{status:['matched','not_found'].includes(mb.status)?mb.status:'Not verified',signature:mb.signature,file_type:mb.file_type,file_name:mb.file_name,tags:list(mb.tags),first_seen:mb.first_seen,last_seen:mb.last_seen,reporter:mb.reporter,reason:mb.reason,source:'MalwareBazaar (abuse.ch)'});
    const warnings=section('warnings','Warnings & limitations','Review before opening the file','Reported warnings and evidence gaps. No sandbox execution took place.');const ul=node('ul','fw-list');list(d.warnings).concat(list(d.missing_checks)).slice(0,40).forEach(item=>ul.append(node('li','',item)));if(!ul.childElementCount)ul.append(node('li','','No warnings reported. This is not a guarantee of safety.'));warnings.append(ul);
    const exif=object(d.exiftool_data);if(exif.available || exif.error)rows(section('exif','Extended metadata','Optional metadata extraction','Availability depends on the parser and file format.'),exif);
  }
  function filter(){const query=$('evidence-search').value.trim().toLowerCase();let shown=0;root.querySelectorAll('.fw-detail').forEach(detail=>{detail.hidden=!!query&&!detail.textContent.toLowerCase().includes(query);if(!detail.hidden)shown++;});$('evidence-empty').hidden=shown>0;root.querySelectorAll('.fw-report-nav a').forEach(a=>{const target=document.getElementById(a.hash.slice(1));a.hidden=!!target?.hidden;});}
  $('evidence-search').addEventListener('input',filter);
  $('expand-all').addEventListener('click',()=>root.querySelectorAll('.fw-detail:not([hidden])').forEach(d=>{d.open=true;}));
  $('collapse-all').addEventListener('click',()=>root.querySelectorAll('.fw-detail').forEach(d=>{d.open=false;}));
  root.querySelectorAll('.fw-report-nav a').forEach(a=>a.addEventListener('click',()=>{const target=document.getElementById(a.hash.slice(1));if(target)target.open=true;}));
  $('export-json').addEventListener('click',()=>{
    if(!lastResult)return;const blob=new Blob([JSON.stringify(Object.fromEntries(Object.entries(lastResult).filter(([key])=>key !== '_pdf_receipt')),null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=node('a','');
    a.href=url;a.download='myscanner-file-'+text(lastResult.filename || 'report').replace(/[^a-z0-9._-]/gi,'_').slice(0,100)+'.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);feedback('Report export requested.');
  });
  $('export-pdf').addEventListener('click',async()=>{
    if (!lastResult || typeof lastResult._pdf_receipt !== 'string' || $('export-pdf').disabled) return;
    $('export-pdf').disabled=true; $('export-pdf').textContent='Preparing PDF…';
    const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),30000);
    try {
      const response=await fetch('/api/file-report/pdf',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({receipt:lastResult._pdf_receipt}),signal:controller.signal});
      if(!response.ok || !response.headers.get('Content-Type')?.includes('application/pdf')) {
        feedback(response.status===400?'PDF export expired or unavailable. Start a new file scan.':'PDF export unavailable. Check your session and try again.');return;
      }
      const url=URL.createObjectURL(await response.blob()),a=node('a','');
      a.href=url;a.download='myscanner-file-report.pdf';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
      feedback('PDF download requested.');
    } catch (_) {feedback('PDF export could not finish. Check your connection and try again.');}
    finally {clearTimeout(timeout);$('export-pdf').textContent='Download PDF';$('export-pdf').disabled=!lastResult || typeof lastResult._pdf_receipt!=='string';}
  });
  $('copy-report').addEventListener('click',()=>{if(!lastResult)return;const d=lastResult,s=scorePresentation(d);copy(['MyScanner · File evidence report','File: '+text(d.filename),'Verdict: '+text(d.verdict),'Coverage: '+(s.incomplete?'Limited':'Configured checks returned'),'Evidence index: '+(s.available?s.value+'%':'Not assigned'),'MalwareBazaar: '+text(provider(d).status || 'Not verified'),'SHA256: '+text(object(d.hashes).sha256 || 'Not reported'),'Scope: Static inspection only; no execution or guarantee of safety.','Missing checks: '+list(d.missing_checks).join('; ')].join('\n'),'Report summary copied.');});
  let printState=[];
  function preparePrint(){printState=Array.from(root.querySelectorAll('details.fw-detail, .fw-detail details')).map(el=>[el,el.open,el.hidden]);printState.forEach(([el])=>{el.open=true;el.hidden=false;});}
  function restorePrint(){printState.forEach(([el,open,hidden])=>{el.open=open;el.hidden=hidden;});printState=[];}
  window.addEventListener('beforeprint',preparePrint);window.addEventListener('afterprint',restorePrint);
  $('print-report').addEventListener('click',()=>{if(lastResult)window.print();});
})();
