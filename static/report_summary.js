/* Deterministic evidence narrative. Provider strings remain inert text. */
(function(root){
'use strict';
const obj=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
const arr=v=>Array.isArray(v)?v:[];
const finite=v=>typeof v==='number'&&Number.isFinite(v);
function lines(kind,raw){
 const d=obj(raw),a=obj(d.assessment),m=obj(d.metadata),mb=obj(d.malwarebazaar),ft=obj(d.file_type);
 let out=[];
 if(kind==='file'){
  out.push(ft.actual_type?`The observed file format is ${String(ft.actual_type).toUpperCase()}; this describes its structure, not its safety.`:'The file format was not established by the reported checks.');
  if(m.is_archive===true){out.push(finite(m.num_files)?`The archive directory contains ${m.num_files} entries; member payloads and nested archives were not inspected.`:'The archive directory could not be fully enumerated.');out.push(m.encrypted===true||arr(m.encrypted_members).length?'Encrypted members were reported; their contents remain unverified.':m.contains_script===true?'Script files appear in the directory; their presence alone is not a malware finding.':'Member payloads and nested archives were not inspected.');}
  else out.push(m.error||m.metadata_error?'Local metadata could not be verified.':'The report contains static observations only; no file execution or sandbox test was performed.');
  out.push(mb.status==='matched'&&mb.is_malicious===true||d.verdict==='malicious'?'A malicious verdict or confirmed hash match was reported. Keep the file unexecuted.':mb.status==='not_found'?'The queried hash was not found in MalwareBazaar; this is not a clean-file verdict.':'A verified MalwareBazaar hash result is unavailable.');
  out.push(finite(a.score)?`The evidence index is ${a.score}/100, with ${finite(a.coverage_penalty)?a.coverage_penalty:0} coverage points deducted. It is not a probability of safety.`:'No evidence index was recorded; missing checks do not establish safety.');
 }else if(kind==='url'){
  const x=obj(d.analysis),v=obj(x.urlvet),tls=obj(v.ssl_info),content=obj(v.content),assessment=obj(x.aggregate_assessment);
  out.push('This report assesses the submitted URL using the observations returned by its configured checks.');
  out.push(tls.has_tls===true&&tls.chain_valid===true?'URLVet reported TLS with a valid certificate chain at scan time.':tls.chain_valid===false?'URLVet reported an invalid TLS certificate chain.':'TLS validity was not established in the available URLVet evidence.');
  out.push(content.has_login_form===true?'A login form was reported; verify the destination before entering credentials.':content.has_payment_form===true?'A payment form was reported; verify the destination before entering payment information.':'The purpose of this website was not established; no business category is inferred.');
  out.push(['malicious','high_risk'].includes(assessment.verdict)?'The combined assessment reports threat or high-risk evidence; review the source findings.':v.phishing_status==='unverified'?'An unverified phishing submission was reported; it does not establish phishing or safety.':'Use the source findings to assess risk; a high index alone does not establish safety.');
  out.push(arr(assessment.missing_checks).length?`${assessment.missing_checks.length} coverage gaps were reported. Review the missing-check section before relying on the index.`:'Read the recorded scope: this report is not a guarantee of safety.');
 }else if(kind==='email'){
  const dns=obj(d.dns_evidence),rep=obj(d.reputation_evidence),smtp=obj(d.smtp_details);
  out.push('This report describes email-domain configuration and the checks actually performed; it does not establish ownership.');
  out.push(obj(dns.mx).exists===true?'Mail-routing MX records were reported.':obj(dns.mx).exists===false?'No MX records were reported by the DNS check.':'Mail routing was not verified.');
  out.push(d.blacklisted===true||rep.is_blacklisted===true?'A blocklist match was reported; review the source and its scope.':rep.coverage_status==='completed'?'No match was reported in the checked MX-address datasets; mailbox reputation was not established.':'Blocklist coverage is incomplete or unavailable.');
  out.push(smtp.valid===true?'The SMTP probe reported recipient acceptance; delivery and mailbox ownership are not guaranteed.':'Mailbox acceptance was not confirmed by the reported SMTP evidence.');
  out.push('Published SPF/DMARC configuration is separate from message authentication; DKIM and breach checks require their own evidence.');
 }else if(kind==='ssl'){
  out.push('This report covers the connection certificate and TLS observations, not the trustworthiness of the website.');
  out.push(d.valid===true?'The certificate check reported a valid result at scan time.':d.valid===false?'The certificate check reported an invalid result.':'Certificate validity was not established.');
  out.push(finite(d.days_remaining)?`The reported certificate lifetime is ${d.days_remaining} days remaining.`:'Certificate expiration evidence was not available.');
  out.push(d.tls_version?`The observed TLS version is ${String(d.tls_version).slice(0,80)}.`:'No negotiated TLS version was reported.');
  out.push('A valid certificate encrypts the connection; it does not prove that the site is legitimate or harmless.');
 }else if(kind==='ip'){
  out.push('This report separates IP network metadata from the reputation dataset result.');
  out.push(d.is_hosting===true?'The metadata identifies a hosting network; hosting alone is not malicious.':d.is_proxy===true?'Proxy-related metadata was reported; this is not by itself a threat finding.':'No network role is inferred beyond the reported metadata.');
  out.push(d.verdict==='not_found'?'No reports matched in the checked reputation dataset; this is not a safety verdict.':['malicious','suspicious','high_risk'].includes(d.verdict)?'The reputation assessment reports risk; review the source reports.':'The reputation result does not establish a clean address.');
  out.push(d.coverage_status==='completed'?'Configured metadata checks returned; active service vulnerability testing was not performed.':'Some checks are unavailable or partial; review coverage before relying on the result.');
  out.push('Location and provider metadata do not identify the person using an address or establish safety.');
 }else if(kind==='domain'){
  out.push('This report describes domain registration and DNS observations; it does not determine the website’s business purpose.');
  out.push(d.registrar?'A registration provider was reported; this does not establish the owner’s legitimacy.':'Registration-provider evidence was unavailable.');
  out.push(arr(d.nameservers).length?'Nameserver records were reported in the domain metadata.':'Nameserver information was not established.');
  out.push(d.coverage_status==='completed'?'Configured metadata sources returned results.':'Metadata coverage is limited; missing sources must not be interpreted as clean findings.');
  out.push('Domain age and DNS configuration are contextual evidence, not guarantees against phishing or malware.');
 }else{
  const ssl=obj(d.ssl),headers=obj(d.security_headers);
  out.push('This website report summarizes general configuration observations; active vulnerability exploitation was not performed.');
  out.push(ssl.valid===true?'The TLS check reported a valid certificate.':ssl.valid===false?'The TLS check reported an invalid certificate.':'TLS validity was not established in the returned checks.');
  out.push(headers.status==='unavailable'||headers.error?'Security-header evidence was unavailable.':'Review the individual security-header findings; configuration alone does not establish safety.');
  out.push(d.verdict==='insecure'?'The assessment reports security concerns requiring review.':'Use the reported findings and recommendations to assess the observed configuration.');
  out.push('Performance, SEO and mobile compatibility are separate from threat reputation and application security.');
 }
 return out.slice(0,5);
}
function mount(kind,d,selector){
 const target=document.querySelector(selector);if(!target||target.hidden||target.style.display==='none')return;
 target.querySelector('[data-report-summary]')?.remove();
 const section=document.createElement('section');section.className='report-summary';section.dataset.reportSummary=kind;
 const label=document.createElement('span');label.className='report-summary-label';label.textContent='REPORT BRIEF';
 const title=document.createElement('h3');title.textContent='What this report tells you';
 const body=document.createElement('div');
 for(const sentence of lines(kind,d)){const p=document.createElement('p');p.textContent=sentence;body.appendChild(p);}
 section.append(label,title,body);
 const anchor=target.querySelector('.fw-assessment, #verdict-banner, .verdict-banner');
 if(anchor&&anchor.parentNode===target)anchor.after(section);else target.insertBefore(section,target.firstElementChild?.nextSibling||null);
}
const api={lines,mount,schedule:(kind,d,selector)=>queueMicrotask(()=>mount(kind,d,selector))};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.ReportSummary=api;
})(typeof globalThis!=='undefined'?globalThis:this);
