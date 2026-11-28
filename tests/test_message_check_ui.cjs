const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../static/message_check.js'), 'utf8');

function page(saved) {
  const storage = new Map(saved ? [['myscanner.messageCheck', JSON.stringify(saved)]] : []);
  const elements = new Map();
  const requests = [];
  const replies = [];
  let reportVisible = false;
  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id, listeners: {}, files: [], hidden: true, value: '', textContent: '', innerHTML: '', dataset: {},
        classList: {add() {}, remove() {}, toggle() {}}, click() { this.clicked = true; },
        addEventListener(event, listener) { this.listeners[event] = listener; },
        querySelectorAll() { return []; }, scrollIntoView() {}, focus() { this.focused = true; },
      });
    }
    return elements.get(id);
  }
  vm.runInNewContext(script, {
    document: { documentElement: { lang: 'tr' }, getElementById: element, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} },
    sessionStorage: { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: (k) => storage.delete(k) },
    location: { search: '', pathname: '/message-check' }, history: { replaceState() {} },
    window: { PlainReport: { mount() { reportVisible = true; }, unmount() { reportVisible = false; } } },
    FormData: class { fields = new Map(); append(name, value) { this.fields.set(name, value); } },
    URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
    async fetch(url, options) {
      requests.push({ url, ...options });
      const reply = replies.shift() || { status: 200, body: { plain: { tone: 'caution' } } };
      return { ok: reply.status < 300, status: reply.status, json: async () => reply.body };
    },
    setTimeout: (fn) => { fn(); return 0; }, clearTimeout() {},
  });
  return { element, requests, replies, storage, report: () => reportVisible };
}

test('a screenshot waits for its link scans, then links open our saved reports, never the message links', async () => {
  const { element, requests, replies, report } = page();
  replies.push({ status: 202, body: { status: 'scanning', token: 'signed' } },
    { status: 202, body: { status: 'scanning', done: 0, total: 1 } },
    { status: 200, body: { plain: { tone: 'danger' }, signals: ['payment'], text: 'Pay: examp1e[.]test',
      links: [{ shown: 'examp1e[.]test', state: 'bad', scan_id: 7, notes: ['listed as dangerous by a threat list'] },
              { shown: 'javascript:alert(1)', state: 'ok', scan_id: '8', notes: [] }] } });
  const picker = element('mc-image');
  picker.files = [{ name: 'shot.png', type: 'image/png', size: 100 }];
  await picker.listeners.change();
  assert.equal(requests[0].body.fields.get('image').name, 'shot.png');
  assert.deepEqual(requests.slice(1).map((r) => [r.url, JSON.parse(r.body).token]),
    [['/api/check-message/finish', 'signed'], ['/api/check-message/finish', 'signed']]);
  assert.equal(report(), true);
  const links = element('mc-link-list').innerHTML;
  assert.match(links, /href="\/result\/7"/);
  assert.match(links, /tehlikeli olarak geçiyor/);
  assert.doesNotMatch(links, /href="(?!\/result\/7")/);  // only our own report is a link; a non-numeric id is not
  assert.equal(element('mc-read-text').dataset.text, 'Pay: examp1e[.]test');
  assert.match(element('mc-read-text').innerHTML, /<div dir="auto">Pay: examp1e\[\.\]test<\/div>/);
});

test('coming back from a link report shows the last result again', () => {
  const saved = { plain: { tone: 'danger' }, links: [{ shown: 'x[.]top', state: 'bad', scan_id: 3 }] };
  const { element, report } = page(saved);
  assert.equal(report(), true);
  assert.match(element('mc-link-list').innerHTML, /href="\/result\/3"/);
  assert.equal(element('mc-form').hidden, true);
});

test('an original email goes up as an email, not as an image', async () => {
  const { element, requests } = page();
  const picker = element('mc-image');
  picker.files = [{ name: 'message.eml', type: '', size: 100 }];
  await picker.listeners.change();
  assert.equal(requests[0].body.fields.get('email').name, 'message.eml');
  assert.equal(requests[0].body.fields.has('image'), false);
});

test('the text read from a screenshot can be corrected and checked again without the image', async () => {
  const { element, requests, replies } = page();
  replies.push({ status: 200, body: { plain: { tone: 'caution' }, text: 'Pay here: examp1e.test' } });
  const picker = element('mc-image');
  picker.files = [{ name: 'shot.png', type: 'image/png', size: 100 }];
  await picker.listeners.change();
  element('mc-edit-read').listeners.click();
  const edit = element('mc-read-edit');
  assert.equal(edit.value, 'Pay here: examp1e.test');
  assert.equal(edit.hidden, false);
  assert.equal(edit.focused, true);
  edit.value = 'Pay here: example.test';
  await element('mc-recheck').listeners.click();
  assert.equal(requests[1].url, '/api/check-message');
  assert.equal(requests[1].headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[1].body), { text: 'Pay here: example.test', lang: 'tr' });
});

test('an original email sent after a screenshot builds on that check', async () => {
  const { element, requests, replies } = page();
  replies.push({ status: 200, body: { plain: { tone: 'danger' }, hidden_link: true, token: 'first-check' } },
    { status: 200, body: { plain: { tone: 'danger' }, source: 'email', with_email: true, text: 'Email from: x',
      links: [{ shown: 'x[.]piluflua[.]biz/a', state: 'warn', scan_id: 4, same_site: 10 }] } });
  const picker = element('mc-image');
  picker.files = [{ name: 'shot.png', type: 'image/png', size: 100 }];
  await picker.listeners.change();
  assert.equal(element('mc-eml').hidden, false);
  picker.files = [{ name: 'message.eml', type: 'message/rfc822', size: 100 }];
  await picker.listeners.change();
  assert.equal(requests[1].body.fields.get('previous'), 'first-check');
  assert.equal(element('mc-eml').hidden, true);
  assert.equal(element('mc-with-email').hidden, false);
  assert.equal(element('mc-edit-read').hidden, true);
  assert.match(element('mc-link-list').innerHTML, /Aynı siteye 10 bağlantı daha/);
});
