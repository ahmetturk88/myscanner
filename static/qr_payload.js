/* QR payloads are data. Never execute, navigate or turn them into HTML. */
(function(root){
'use strict';
function fields(value){const out={};let part='',escape=false;const parts=[];for(const ch of value){if(escape){part+=ch;escape=false;}else if(ch==='\\'){escape=true;}else if(ch===';'){parts.push(part);part='';}else part+=ch;}if(part)parts.push(part);for(const p of parts){const i=p.indexOf(':');if(i>0)out[p.slice(0,i)]=p.slice(i+1);}return out;}
function classify(raw){
 if(typeof raw!=='string'||raw.length===0||raw.length>8192)throw new Error('QR content must contain 1–8,192 characters.');
 const result={type:'text',label:'Text payload',raw,display:raw,details:[],warnings:[],inspectable:false,private:false};
 const value=raw.trim();
 if(/^https?:\/\//i.test(value)){
  result.type='url';result.label='Web link';
  try{const u=new URL(value);if(raw.length>2048||raw.includes('\\')||u.username||u.password||/[\u0000-\u0020\u007f]/.test(raw)||!u.hostname)throw new Error();result.url=u.href;result.inspectable=true;result.details=[['Protocol',u.protocol.replace(':','')],['Hostname',u.hostname],['Port',u.port||'Default'],['Query parameters',String([...u.searchParams].length)]];if(u.protocol==='http:')result.warnings.push('This link uses HTTP without transport encryption.');if(u.hostname.includes('xn--'))result.warnings.push('Internationalized hostname: review the exact destination.');if(u.search)result.warnings.push('Query parameters may contain private tokens. Inspect only if you intend to send this URL.');}
  catch{result.warnings.push('Malformed or oversized web link, embedded credentials or whitespace: URL inspection is disabled.');}
 }else if(/^WIFI:/i.test(value)){
  const f=fields(value.slice(5));result.type='wifi';result.label='Wi-Fi configuration';result.private=true;result.display='Wi-Fi credentials hidden';result.details=[['Network name',f.S||'Not reported'],['Authentication',f.T||'Not reported'],['Hidden network',f.H==='true'?'Yes':'No / not reported'],['Password',f.P?'Hidden':'Not provided']];result.warnings.push('A QR code does not establish who operates this network. Credentials are hidden and excluded from exports.');
 }else if(/^mailto:/i.test(value)){
  result.type='email';result.label='Email action';const u=new URL(value);result.details=[['Recipient',u.pathname],['Subject',u.searchParams.get('subject')||'Not provided']];result.warnings.push('This describes an email action; mailbox ownership and delivery were not verified.');
 }else if(/^(tel:|sms:|smsto:)/i.test(value)){
  result.type=/^tel:/i.test(value)?'phone':'sms';result.label=result.type==='phone'?'Phone action':'SMS action';result.details=[['Destination',value.slice(value.indexOf(':')+1).split('?')[0]]];result.warnings.push('No call or message was initiated. Review the destination and potential charges.');
 }else if(/^BEGIN:VCARD/i.test(value)||/^MECARD:/i.test(value)){
  result.type='contact';result.label='Contact card';result.private=true;result.display='Contact details hidden';result.warnings.push('Personal contact data is hidden and excluded from exports. No contact was imported.');
 }else if(/^geo:/i.test(value)){
  result.type='location';result.label='Location payload';result.details=[['Coordinates',value.slice(4).split('?')[0]]];result.warnings.push('Coordinates are decoded text, not a verified physical location.');
 }else if(/^[a-z][a-z0-9+.-]*:/i.test(value)){
  result.type='action';result.label='Application / custom action';result.details=[['Scheme',value.slice(0,value.indexOf(':'))]];result.warnings.push('Application actions and scripts are not executed. Only HTTP and HTTPS URLs can be inspected.');
 }
 return result;
}
function coverage(data){const checks=Array.isArray(data?.checks)?data.checks.filter(c=>c&&typeof c==='object'&&!['not_requested','not_applicable'].includes(c.status)):[];const completed=checks.filter(c=>['completed','invalid'].includes(c.status)).length;return {completed,total:checks.length,score:checks.length?Math.round(completed*100/checks.length):null};}
function summary(payload,data,attempted=false){const p=payload;const lines=[`The QR image contains ${p.label.toLowerCase()}.`];if(p.type==='url'){lines.push(`The decoded destination is ${p.details.find(d=>d[0]==='Hostname')?.[1]||'not valid for inspection'}.`);if(data){const c=coverage(data);lines.push(`${c.completed} of ${c.total} selected evidence checks completed; this measures coverage, not safety.`);lines.push(typeof data.summary==='string'?data.summary:'Read the available findings and source states below.');lines.push('DNS, TLS and static page observations cannot guarantee that a destination is trustworthy.');}else{lines.push(attempted?'URL inspection was attempted but no current assessment is available.':'Network inspection has not been performed.');lines.push('Review the destination before requesting a read-only assessment.');lines.push('Decoding a QR code does not establish that the link is safe.');}}else{lines.push(p.private?'Sensitive content is hidden by default.':'The content is displayed as literal text.');lines.push('No link, application action, call or configuration was opened.');lines.push('Payload recognition does not verify its author or authenticity.');lines.push('Only decoded web links support network evidence inspection.');}return lines;}
function report(payload,data,attempted=false){return {schema_version:1,created_at:new Date().toISOString(),payload:{type:payload.type,label:payload.label,content:payload.private?'[Sensitive payload excluded]':payload.raw,details:payload.details,warnings:payload.warnings},assessment:data||null,inspection_status:data?'returned':attempted?'unavailable':'not_requested',summary:summary(payload,data,attempted),scope:'Single decoded QR payload; no action executed. Coverage is not a safety probability.'};}
const api={classify,coverage,summary,report};root.QRPayload=Object.freeze(api);if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
