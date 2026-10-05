// Run with node; mocks the browser context and never sends network requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const origin = 'https://myscanner.example';
class BrowserRequest extends Request {
    constructor(input, init) {
        super(typeof input === 'string' ? new URL(input, origin) : input, init);
    }
}
let token = 'page-token';
const window = { location: { origin }, fetch: async request => request };
const document = { querySelector: () => token ? { content: token } : null };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../static/csrf.js'), 'utf8'), {
    window, document, Request: BrowserRequest, Headers, URL, Set
});
(async () => {
    let checks = 0;
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const request = await window.fetch('/api/scan', { method });
        assert.equal(request.headers.get('X-CSRFToken'), token);
        checks++;
    }
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
        const request = await window.fetch('/api/scan', { method });
        assert.equal(request.headers.get('X-CSRFToken'), null);
        checks++;
    }
    const external = await window.fetch('https://external.example/scan', { method:'POST' });
    assert.equal(external.headers.get('X-CSRFToken'), null); checks++;
    const headers = new Headers({ 'Content-Type':'application/json', 'X-Custom':'keep' });
    const request = await window.fetch('/api/scan', { method:'POST', headers, body:'{}' });
    assert.equal(request.headers.get('X-CSRFToken'), token);
    assert.equal(request.headers.get('X-Custom'), 'keep');
    assert.equal(await request.text(), '{}');
    assert.equal(headers.get('X-CSRFToken'), null); checks++;
    const pairs = await window.fetch('/api/scan', {method:'POST', headers:[['X-Custom','keep']]});
    assert.equal(pairs.headers.get('X-Custom'), 'keep');
    assert.equal(pairs.headers.get('X-CSRFToken'), token); checks++;
    const input = new BrowserRequest('/api/scan', {method:'POST', headers:{'X-Custom':'original'}, body:'data'});
    const fromRequest = await window.fetch(input);
    assert.equal(fromRequest.headers.get('X-CSRFToken'), token);
    assert.equal(fromRequest.headers.get('X-Custom'), 'original');
    assert.equal(await fromRequest.text(), 'data'); checks++;
    const overridden = await window.fetch(new BrowserRequest('/api/scan', {method:'POST'}), {method:'GET'});
    assert.equal(overridden.headers.get('X-CSRFToken'), null); checks++;
    const fd = new FormData(); fd.append('file', new Blob(['test-only']), 'sample.pdf');
    const upload = await window.fetch('/api/file', {method:'POST', body:fd});
    assert.equal(upload.headers.get('X-CSRFToken'), token);
    assert.match(upload.headers.get('Content-Type'), /^multipart\/form-data; boundary=/);
    assert.match(await upload.text(), /sample\.pdf/); checks++;
    token = '';
    assert.equal((await window.fetch('/api/scan', {method:'POST'})).headers.get('X-CSRFToken'), null); checks++;
    console.log(`${checks} browser fetch checks passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
