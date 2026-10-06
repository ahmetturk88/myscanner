const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const code = fs.readFileSync(path.join(__dirname, '../static/proxy_check.js'), 'utf8');
const normal = {client_ip: '127.0.0.1', edge_candidate: '8.8.8.8', cf_connecting_ip: '8.8.8.8', forwarded_for: '<script>evil</script>'};
const ok = data => ({ok: true, json: async () => data});
const rejected = (status, body) => ({ok: false, status, text: async () => body});
const edgeError = rejected(403, '<title>DNS points to prohibited IP | example.invalid | Cloudflare</title><script>evil</script>');
async function run(responses) {
  let click;
  const nodes = {'proxy-run': {addEventListener: (_, cb) => {click = cb;}}, 'proxy-status': {dataset: {}}, 'proxy-details': {textContent: 'stale'}};
  for (const node of Object.values(nodes)) Object.defineProperty(node, 'innerHTML', {set() {throw Error('Unsafe HTML sink');}});
  const calls = [];
  vm.runInNewContext(code, {document: {getElementById: id => nodes[id]}, fetch: async (url, options) => {
    const response = responses[calls.length];
    calls.push({url, options});
    if (response instanceof Error) throw response;
    assert.ok(response, 'Unexpected additional request');
    return response;
  }});
  await click();
  assert.equal(nodes['proxy-run'].disabled, false);
  for (const call of calls) {
    assert.equal(call.url, '/admin/proxy-info');
    assert.equal(call.options.cache, 'no-store');
    assert.equal(call.options.credentials, 'same-origin');
    assert.equal(call.options.redirect, 'error');
  }
  assert.equal(Object.keys(calls[0].options.headers).length, 0);
  if (calls.length > 1) {
    assert.equal(Object.keys(calls[1].options.headers).length, 1);
    assert.equal(calls[1].options.headers['X-Forwarded-For'], '198.51.100.77');
    assert.equal(Object.keys(calls[2].options.headers).length, 1);
    assert.equal(calls[2].options.headers['CF-Connecting-IP'], '198.51.100.77');
  }
  return {nodes, calls, result: JSON.parse(nodes['proxy-details'].textContent)};
}
(async () => {
  let r = await run([ok(normal), ok(normal), ok(normal)]);
  assert.equal(r.nodes['proxy-status'].dataset.state, 'pass');
  assert.equal(r.result.edge_header_preserved, true);
  assert.ok(r.nodes['proxy-details'].textContent.includes('<script>evil</script>'));
  for (const tested of [{...normal, edge_candidate: null, cf_connecting_ip: '198.51.100.77'}, {...normal, edge_candidate: '1.1.1.1', cf_connecting_ip: '1.1.1.1'}]) {
    r = await run([ok(normal), ok(normal), ok(tested)]);
    assert.equal(r.nodes['proxy-status'].dataset.state, 'review');
    assert.equal(r.result.edge_header_preserved, false);
  }
  r = await run([ok({...normal, edge_candidate: null}), ok(normal), ok(normal)]);
  assert.equal(r.result.edge_header_preserved, false);
  for (const responses of [[ok(normal), ok(normal), edgeError], [ok(normal), edgeError, ok(normal)]]) {
    r = await run(responses);
    assert.equal(r.calls.length, 3);
    assert.equal(r.result.normal.cf_connecting_ip, '8.8.8.8');
    assert.equal(r.result.edge_header_preserved, false);
    assert.equal(r.nodes['proxy-status'].dataset.state, 'review');
    assert.match(r.nodes['proxy-status'].textContent, /Cloudflare rejected/);
    assert.ok(!r.nodes['proxy-details'].textContent.includes('<title>'));
    assert.ok(!r.nodes['proxy-status'].textContent.includes('Confirm you are signed in'));
  }
  r = await run([ok(normal), new Error('offline'), ok(normal)]);
  assert.equal(r.calls.length, 3);
  assert.equal(r.result.forwarded_for_probe.outcome, 'request_failed');
  assert.equal(r.result.normal.client_ip, '127.0.0.1');
  for (const response of [new Error('offline'), rejected(403, '{"error":"Forbidden"}'), ok({}), {ok: true, json: async () => {throw Error('invalid JSON');}}]) {
    r = await run([response]);
    assert.equal(r.calls.length, 1);
    assert.equal(r.nodes['proxy-status'].dataset.state, 'review');
    assert.ok(!r.nodes['proxy-details'].textContent.includes('stale'));
  }
  r = await run([ok(normal), ok(normal), rejected(403, '<title>Some other error</title>')]);
  assert.equal(r.result.connecting_ip_probe.outcome, 'http_error');
  assert.ok(!r.nodes['proxy-status'].textContent.includes('Cloudflare rejected'));
  console.log('Diagnostic button regression checks passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
