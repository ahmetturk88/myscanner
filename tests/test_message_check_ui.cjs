const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../static/message_check.js'), 'utf8');

test('editing screenshot text resubmits the correction without the image', async () => {
  const elements = new Map();
  const requests = [];
  const screenshot = { name: 'message.png' };
  const extracted = 'Pay here: examp1e.test';

  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        listeners: {},
        files: [],
        hidden: true,
        value: '',
        addEventListener(event, listener) { this.listeners[event] = listener; },
        querySelectorAll() { return []; },
        focus() { this.focused = true; },
      });
    }
    return elements.get(id);
  }

  const picker = element('mc-image');
  Object.defineProperty(picker, 'value', {
    set(value) { if (value === '') this.files = []; },
  });
  picker.files = [screenshot];

  let reportVisible = false;
  vm.runInNewContext(script, {
    document: { documentElement: { lang: 'tr' }, getElementById: element, querySelector: () => null },
    window: {
      PlainReport: {
        mount() { reportVisible = true; },
        unmount() { reportVisible = false; },
      },
    },
    FormData: class {
      fields = new Map();
      append(name, value) { this.fields.set(name, value); }
    },
    async fetch(url, options) {
      requests.push({ url, ...options });
      return {
        ok: true,
        json: async () => ({ plain: { tone: 'caution' }, text: requests.length === 1 ? extracted : undefined }),
      };
    },
  });

  const submit = () => element('mc-form').listeners.submit({ preventDefault() {} });
  picker.listeners.change();
  await submit();
  assert.equal(requests[0].body.fields.get('image'), screenshot);
  assert.equal(element('mc-read-text').textContent, extracted);
  assert.equal(reportVisible, true);

  element('mc-edit-read').listeners.click();
  const input = element('mc-text');
  assert.equal(input.value, extracted);
  assert.equal(input.focused, true);
  assert.deepEqual(picker.files, []);
  assert.equal(element('mc-picked').hidden, true);
  assert.equal(reportVisible, false);
  assert.equal(requests.length, 1);

  input.value = 'Pay here: example.test';
  await submit();
  assert.equal(requests[1].url, '/api/check-message');
  assert.equal(requests[1].headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[1].body), { text: input.value, lang: 'tr' });
  assert.equal(element('mc-read').hidden, true);
});
