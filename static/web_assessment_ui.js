/* All provider/target strings are rendered through textContent, never HTML. */
(function (global) {
  'use strict';
  const text = value => typeof value === 'string' || typeof value === 'number' ? String(value) : '—';
  const list = value => Array.isArray(value) ? value : [];
  const statuses = {completed:'Completed',partial:'Partially completed',unavailable:'Unavailable',blocked:'Blocked by network policy',not_requested:'Not requested',not_applicable:'Not applicable',invalid:'Validation failed',no_record:'No record',not_found:'Name does not resolve'};
  const statusText = value => Object.hasOwn(statuses,value) ? statuses[value] : text(value);
  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = text(value);
    return node;
  }
  function button(label, callback) {
    const node = element('button', 'action-btn', label); node.type = 'button';
    node.addEventListener('click', callback); return node;
  }
  function panel(root, title) {
    const box = element('section', 'evidence-panel'); box.appendChild(element('h3', '', title)); root.appendChild(box); return box;
  }
  function pair(root, label, value) {
    const row = element('div', 'evidence-row'); row.appendChild(element('span', 'evidence-label', label)); row.appendChild(element('span', 'evidence-value', value)); root.appendChild(row);
  }
  function download(data, name, mime='application/json') {
    const blob = new Blob([data], {type:mime}); const url = URL.createObjectURL(blob);
    const anchor = element('a'); anchor.href = url; anchor.download = name; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function render(root, data) {
    root.replaceChildren();
    const titles = {clean:'No threat indicators observed', suspicious:'Indicators need your attention', malicious:'Threat indicators reported', unknown:'Assessment is inconclusive'};
    const verdict = Object.hasOwn(titles, data.verdict) ? data.verdict : 'unknown';
    const summary = element('section', 'assessment-summary assessment-'+verdict);
    summary.appendChild(element('span', 'coverage-badge', data.assessment_status === 'completed' ? 'Assessment returned' : 'Limited coverage'));
    summary.appendChild(element('h2', '', titles[verdict])); summary.appendChild(element('p', '', data.summary || 'Available checks cannot confirm safety.'));
    root.appendChild(summary);
    const stats = data.stats || {};
    const grid = element('div', 'evidence-metrics');
    for (const [label,value] of [['Checks completed',text(stats.checks_completed)+' / '+text(stats.checks_total)],['Warnings observed',stats.warning_count],['Redirects followed',stats.redirect_count]]) {
      const cell=element('div', 'evidence-metric'); cell.appendChild(element('strong','',value)); cell.appendChild(element('span','',label)); grid.appendChild(cell);
    }
    root.appendChild(grid);
    const coverage=panel(root,'Analysis coverage');
    for(const check of list(data.checks).slice(0,20)) pair(coverage,check.name,statusText(check.status));
    const structure=data.structure || {}; const target=panel(root,'URL details');
    for(const [label,key] of [['Hostname','hostname'],['Protocol','scheme'],['Port','port'],['Path','path'],['Query parameters','query_parameter_count']]) pair(target,label,structure[key]);
    const route=panel(root,'Redirect chain');
    for(const hop of list(data.http?.chain).slice(0,6)) pair(route,hop.status_code,hop.url);
    if(data.http?.reason) route.appendChild(element('p','evidence-note',data.http.reason));
    if(data.http?.final_url) pair(route,'Final URL',data.http.final_url);
    const tls=panel(root,'TLS certificate'); const certificate=data.tls || {};
    pair(tls,'Result',statusText(certificate.status));
    for(const [label,key] of [['Issuer','issuer'],['Expires','expires_at'],['Days remaining','days_remaining'],['TLS version','tls_version'],['Cipher','cipher']]) if(certificate[key] !== undefined) pair(tls,label,certificate[key]);
    if(certificate.reason) tls.appendChild(element('p','evidence-note',certificate.reason));
    const dns=panel(root,'DNS records');
    for(const kind of ['A','AAAA','CNAME','MX','NS','TXT']) {
      const record=data.dns?.[kind]; if(record) pair(dns,kind+' · '+statusText(record.status),list(record.values).join('\n') || record.reason || 'No record');
    }
    const page=panel(root,'Page observations'); pair(page,'Inspection',statusText(data.content?.status));
    if(data.content?.title) pair(page,'Page title',data.content.title);
    for(const form of list(data.content?.forms).slice(0,20)) pair(page,form.password_input ? 'Password form destination' : 'Form destination',form.action);
    if(data.content?.note) page.appendChild(element('p','evidence-note',data.content.note));
    const headers=panel(root,'Security headers');
    for(const key of ['Strict-Transport-Security','Content-Security-Policy','X-Content-Type-Options','Referrer-Policy','X-Frame-Options']) pair(headers,key,data.http?.status==='completed' ? data.http.security_headers?.[key] || 'Not observed' : 'Not assessed');
    headers.appendChild(element('p','evidence-note','Missing headers are configuration observations, not proof of phishing or malware.'));
    const findings=panel(root,'Findings and reasons');
    if(!list(data.findings).length) findings.appendChild(element('p','evidence-note','No local warning indicators observed. Missing coverage still limits the conclusion.'));
    for(const finding of list(data.findings).slice(0,40)) {
      const box=element('article','evidence-finding'); box.appendChild(element('h4','',finding.title)); box.appendChild(element('p','',finding.detail)); findings.appendChild(box);
    }
    const provider=panel(root,'Optional external analysis');
    pair(provider,data.provider?.name || 'url.vet',statusText(data.provider?.status || 'not_requested'));
    if(data.provider?.reason) provider.appendChild(element('p','evidence-note',data.provider.reason));
    if(data.provider?.verdict) pair(provider,'Provider verdict',data.provider.verdict);
    for(const reason of list(data.provider?.red_flags).slice(0,20)) provider.appendChild(element('p','evidence-note',typeof reason==='string' ? reason : JSON.stringify(reason)));
    const limits=panel(root,'Scope and limitations');
    for(const note of list(data.limitations).slice(0,20)) limits.appendChild(element('p','evidence-note',note));
    const actions=element('div','action-buttons'); actions.appendChild(button('Export assessment JSON',()=>download(JSON.stringify(data,null,2),'web-assessment.json'))); root.appendChild(actions);
  }
  function csvCell(value) {
    let cell=text(value); if(/^[\s]*[=+\-@\t\r]/.test(cell)) cell="'"+cell;
    return '"'+cell.replace(/"/g,'""')+'"';
  }
  function renderDiscovery(root, data, onInspect) {
    root.replaceChildren();
    const summary=element('section','assessment-summary assessment-unknown');
    summary.appendChild(element('span','coverage-badge',data.assessment_status==='completed' ? 'Selected checks completed' : 'Limited discovery coverage'));
    summary.appendChild(element('h2','',text(data.total_found)+' DNS names found'));
    summary.appendChild(element('p','',text(data.candidates_selected)+' candidates selected · '+text(data.dns_error_count)+' unresolved checks · Web inspection limited to '+text(data.limits?.web_probe_limit)+' hosts'));
    root.appendChild(summary);
    const sources=panel(root,'Discovery sources');
    for(const source of list(data.sources)) { pair(sources,source.name,statusText(source.status)); if(source.reason) sources.appendChild(element('p','evidence-note',source.reason)); }
    pair(sources,'Wildcard DNS',data.wildcard?.status === 'completed' ? data.wildcard?.detected ? 'Detected; matching rows are marked' : 'Not observed in two probes' : 'Probe incomplete');
    const toolbar=element('div','discovery-toolbar');
    const search=element('input','discovery-search'); search.type='search'; search.placeholder='Search hostname, IP or source'; search.setAttribute('aria-label','Search discovered domains');
    const filter=element('select','discovery-filter'); filter.setAttribute('aria-label','Filter by observed status');
    for(const [key,label] of [['all','All observations'],['active','Responding'],['redirect','Redirect response'],['http_error','HTTP error response'],['dns_only','DNS only / web unavailable'],['blocked','Network policy blocked'],['wildcard','Possible wildcard']]) {const option=element('option','',label); option.value=key; filter.appendChild(option);}
    toolbar.appendChild(search); toolbar.appendChild(filter); root.appendChild(toolbar);
    const rowsRoot=element('div','discovery-results'); root.appendChild(rowsRoot);
    function update() {
      rowsRoot.replaceChildren(); const term=(search.value || '').toLowerCase(); const selected=filter.value || 'all';
      const rows=list(data.results).filter(row=>[row.full_domain,...list(row.addresses),...list(row.sources)].join(' ').toLowerCase().includes(term) && (selected==='all' || selected==='wildcard' && row.possible_wildcard || row.verdict===selected));
      if(!rows.length) rowsRoot.appendChild(element('p','evidence-note','No matching results. A completed search does not prove that no other subdomains exist.'));
      for(const row of rows.slice(0,100)) {
        const card=element('article','discovery-row'); const description=element('div','discovery-description');
        description.appendChild(element('h3','',row.full_domain)); description.appendChild(element('p','evidence-note',list(row.addresses).join(' · ') || 'CNAME record; address unavailable'));
        description.appendChild(element('p','evidence-note','Sources: '+list(row.sources).join(', ')));
        if(row.possible_wildcard) description.appendChild(element('span','coverage-badge','Possible wildcard match'));
        pair(description,'HTTP observation',row.http?.status==='completed' ? text(row.http.status_code)+' · '+text(row.http.url) : row.http?.reason || statusText(row.http?.status));
        if(row.http?.location) pair(description,'Redirect destination (not followed)',row.http.location);
        pair(description,'TLS observation',statusText(row.tls?.status));
        if(row.tls?.issuer) pair(description,'Certificate issuer',row.tls.issuer);
        if(row.tls?.expires_at) pair(description,'Certificate expires',row.tls.expires_at);
        if(list(row.dns?.CNAME?.values).length) pair(description,'CNAME',row.dns.CNAME.values.join(', '));
        card.appendChild(description); const inspect=button('Inspect URL',()=>onInspect(row.subdomain,row.full_domain)); inspect.className='scan-subdomain'; inspect.disabled=!row.public_addresses; card.appendChild(inspect); rowsRoot.appendChild(card);
      }
    }
    search.addEventListener('input',update); filter.addEventListener('change',update); update();
    const errors=list(data.unresolved); if(errors.length) { const box=panel(root,'DNS checks that could not be completed'); for(const row of errors.slice(0,100)) pair(box,row.full_domain,'Lookup unavailable; absence not established'); }
    const limits=panel(root,'Scope and limitations'); for(const note of list(data.limitations)) limits.appendChild(element('p','evidence-note',note));
    const actions=element('div','action-buttons');
    actions.appendChild(button('Export JSON',()=>download(JSON.stringify(data,null,2),'subdomains.json')));
    actions.appendChild(button('Export CSV',()=>{
      const rows=[['Hostname','Addresses','Sources','HTTP observation','TLS','Possible wildcard'],...list(data.results).map(row=>[row.full_domain,list(row.addresses).join('; '),list(row.sources).join('; '),row.http?.status==='completed' ? row.http.status_code : row.http?.status,row.tls?.status,row.possible_wildcard ? 'yes' : 'no'])];
      download(rows.map(row=>row.map(csvCell).join(',')).join('\r\n'),'subdomains.csv','text/csv;charset=utf-8');
    }));
    actions.appendChild(button('Copy names',async()=>{try {await navigator.clipboard.writeText(list(data.all_subdomains).join('\n')); actions.appendChild(element('span','evidence-note','Names copied'));}catch {actions.appendChild(element('span','evidence-note','Copy unavailable; use JSON or CSV export'));}})); root.appendChild(actions);
  }
  global.WebAssessmentUI=Object.freeze({render,renderDiscovery,csvCell});
})(window);
