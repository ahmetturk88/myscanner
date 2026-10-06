const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const code = fs.readFileSync(path.join(__dirname, '../static/proxy_check.js'), 'utf8');
async function run(normal, tested, failure = false) {
  let click;
  const nodes = {'proxy-run': {addEventListener: (_, cb) => {click = cb;}}, 'proxy-status': {dataset: {}}, 'proxy-details': {}};
  for (const node of Object.values(nodes)) Object.defineProperty(node, 'innerHTML', {set() {throw Error('Unsafe HTML sink');}});
  const calls = [];
  vm.runInNewContext(code, {document: {getElementById: id => nodes[id]}, fetch: async (url, options) => {
    calls.push({url, options});
    if (failure) throw Error('offline');
    return {ok: true, json: async () => calls.length === 1 ? normal : tested};
  }});
  await click();
  assert.equal(nodes['proxy-run'].disabled, false);
  for (const call of calls) {
    assert.equal(call.url, '/admin/proxy-info');
    assert.equal(call.options.cache, 'no-store');
    assert.equal(call.options.credentials, 'same-origin');
    assert.equal(call.options.redirect, 'error');
  }
  if (!failure) assert.equal(calls[1].options.headers['CF-Connecting-IP'], '198.51.100.77');
  return nodes;
}
(async () => {
  const normal = {edge_candidate: '8.8.8.8', cf_connecting_ip: '8.8.8.8', forwarded_for: '<script>evil</script>'};
  let nodes = await run(normal, normal);
  assert.equal(nodes['proxy-status'].dataset.state, 'pass');
  assert.ok(nodes['proxy-details'].textContent.includes('<script>evil</script>'));
  for (const tested of [{edge_candidate: null, cf_connecting_ip: '198.51.100.77'}, {edge_candidate: '1.1.1.1', cf_connecting_ip: '1.1.1.1'}]) {
    nodes = await run(normal, tested);
    assert.equal(nodes['proxy-status'].dataset.state, 'review');
  }
  nodes = await run({edge_candidate: null}, {edge_candidate: null});
  assert.equal(nodes['proxy-status'].dataset.state, 'review');
  nodes = await run(normal, normal, true);
  assert.equal(nodes['proxy-status'].dataset.state, 'review');
  console.log('Diagnostic button checks passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
