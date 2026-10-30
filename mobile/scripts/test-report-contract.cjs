const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const ts = require('typescript');
const filename = require('node:path').resolve(__dirname, '../src/lib/report-contract.ts');
const code = ts.transpileModule(fs.readFileSync(filename, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const mod = new Module(filename, module);
mod._compile(code, filename);
const { heroTone, state, hasPlain, reportOf, withoutPlain } = mod.exports;
for (const tone of ['danger', 'caution', 'unknown', 'safe', 'info']) {
  const plain = { tone, headline: '<img src=x onerror=alert(1)>', summary: 'Evidence before trust' };
  const report = { plain, assessment: { policy_version: 'test-v1', score: 17 }, verdict: 'unknown' };
  assert.equal(heroTone(tone), tone);
  assert.equal(reportOf({ status: 'completed', result: report }), report);
  assert.equal(reportOf(report), report);
  assert.equal(hasPlain(plain), true);
  assert.equal(reportOf(report).plain.headline, plain.headline);
  assert.deepEqual(withoutPlain(report), { assessment: report.assessment, verdict: 'unknown' });
}
for (const key of ['constructor', 'toString', '__proto__', '', null, {}, 100]) {
  assert.equal(heroTone(key), 'unknown');
  assert.equal(state(key), 'na');
}
for (const value of [null, [], 'x', { headline: 9 }]) assert.equal(hasPlain(value), false);
console.log('PASS: mobile preserves server report decisions, evidence and literal text; prototype keys rejected');
