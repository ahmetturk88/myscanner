'use strict';
const assert=require('node:assert/strict');const {lines}=require('../static/report_summary.js');
const d={file_type:{actual_type:'zip'},metadata:{is_archive:true,num_files:5,contains_script:true},malwarebazaar:{status:'not_found'},assessment:{score:60,coverage_penalty:40}};
const file=lines('file',d);assert.equal(file.length,5);assert(file.join(' ').includes('60/100'));assert(file.join(' ').includes('not a clean-file verdict'));assert(file.join(' ').includes('presence alone'));
assert(lines('file',{...d,malwarebazaar:{status:'matched',is_malicious:true}}).join(' ').includes('confirmed hash match'));
assert(lines('file',{...d,metadata:{is_archive:true,encrypted:true}}).join(' ').includes('Encrypted members'));
for(const kind of ['url','email','ssl','ip','domain','site']){const result=lines(kind,{});assert(result.length>=4&&result.length<=5);assert(!result.join(' ').includes('valid certificate chain at scan time'));}
assert(lines('url',{analysis:{urlvet:{ssl_info:{has_tls:true,chain_valid:true},content:{has_login_form:true}}}}).join(' ').includes('login form'));
assert(lines('ssl',{valid:'true'}).join(' ').includes('not established'));
assert(lines('email',{blacklisted:true}).join(' ').includes('blocklist match'));
// Provider strings are inserted only as text, never markup.
const hostile=lines('ssl',{tls_version:'<img onerror=alert(1)>'});assert(hostile.some(s=>s.includes('<img')));
const fs=require('node:fs');const source=fs.readFileSync(require.resolve('../static/report_summary.js'),'utf8');assert(!source.includes('.innerHTML'));assert(source.includes('p.textContent=sentence'));
console.log('PASS: seven narratives, unknown evidence, threat precedence and text-only rendering');
