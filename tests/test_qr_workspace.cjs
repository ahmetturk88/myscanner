const assert=require('node:assert/strict'),fs=require('node:fs');
const {classify,coverage,summary,report}=require('../static/qr_payload.js');
const jsQR=require('../static/vendor/jsQR-1.4.0.js');
const fixtures=require('./qr_decode_fixtures.json');
let checks=0;
function check(fn){fn();checks++;}
function pixels(matrix,invert=false,rotate=false){const width=matrix.length*4,rgba=new Uint8ClampedArray(width*width*4);for(let y=0;y<width;y++)for(let x=0;x<width;x++){const yy=rotate?width-1-x:y,xx=rotate?y:x;const bit=matrix[Math.floor(yy/4)][Math.floor(xx/4)]==='1';const v=(invert?!bit:bit)?0:255;const i=(y*width+x)*4;rgba[i]=rgba[i+1]=rgba[i+2]=v;rgba[i+3]=255;}return {rgba,width};}
for(const fixture of fixtures)for(const [invert,rotate] of [[false,false],[true,false],[false,true]])check(()=>{const {rgba,width}=pixels(fixture.matrix,invert,rotate);const code=jsQR(rgba,width,width,{inversionAttempts:'attemptBoth'});assert.equal(code?.data,fixture.value);});
check(()=>{const white=new Uint8ClampedArray(80*80*4).fill(255);assert.equal(jsQR(white,80,80),null);});
check(()=>assert.equal(classify('https://example.com/?x=1').inspectable,true));
for(const value of ['javascript:alert(1)','data:text/html,<svg>','https://u:p@example.com/','https://example.com/\n'])check(()=>assert.equal(classify(value).inspectable,false));
for(const [value,type] of [['WIFI:S:A;P:secret;;','wifi'],['mailto:a@example.com','email'],['tel:+123','phone'],['SMSTO:+123:Hello','sms'],['geo:10,20','location'],['MECARD:N:Name;;','contact'],['Plain text','text']])check(()=>assert.equal(classify(value).type,type));
check(()=>{const p=classify(fixtures.find(f=>f.name==='wifi').value);assert.equal(p.details[0][1],'Lab;Network');assert.ok(!p.display.includes('never-export'));assert.ok(!JSON.stringify(report(p)).includes('never-export'));});
check(()=>assert.ok(!JSON.stringify(report(classify('BEGIN:VCARD\nFN:PrivateName\nEND:VCARD'))).includes('PrivateName')));
check(()=>assert.equal(coverage({checks:[{status:'completed'},{status:'invalid'},{status:'unavailable'},{status:'not_requested'},{status:'not_applicable'}]}).score,67));
check(()=>assert.equal(coverage({checks:[]}).score,null));
for(const f of fixtures)check(()=>assert.equal(summary(classify(f.value),null).length,5));
check(()=>assert.throws(()=>classify('x'.repeat(8193))));check(()=>assert.throws(()=>classify('')));
console.log(`PASS: ${checks} QR decode, payload classification, privacy and coverage assertions`);
