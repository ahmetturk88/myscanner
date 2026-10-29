// The "next step" card on reports: the right next check, and Pro never next to a dangerous verdict.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const ctx = {console};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'static', 'plain_report.js'), 'utf8'), ctx);
const {PlainReport} = ctx;

function html(tone, href, extra) {
  const box = {dataset: {}, querySelector: () => null, querySelectorAll: () => [], hidden: true, innerHTML: ''};
  const plain = {tone, label: 'X', headline: 'Y', summary: 'Z', reasons: [], actions: [], checks: [], share_text: 'share'};
  assert.equal(PlainReport.render(box, plain, Object.assign({again: {href, label: 'Again'}}, extra)), true);
  return box.innerHTML;
}

test('each tool points to the other checks, never to itself', () => {
  const file = html('safe', '/file-scanner');
  assert.match(file, /Where did this file come from\?/);
  assert.match(file, /href="\/dashboard">Check a link/);
  assert.match(file, /href="\/email-check">Check a sender/);
  assert.doesNotMatch(file, /href="\/file-scanner">Check a file/);
  assert.match(html('caution', '/email-check'), /Did the email have a link or a file\?/);
  assert.match(html('safe', '/ip-check'), /Got a suspicious message\?/);
});

test('Pro is shown on safe and careful reports, with its source, but never on dangerous ones', () => {
  assert.match(html('safe', '/file-scanner'), /href="\/pro\?ref=report-file">Get notified/);
  assert.match(html('caution', '/dashboard'), /\/pro\?ref=report-url/);
  assert.match(html('unknown', '/qr-scanner'), /\/pro\?ref=report-qr/);
  const danger = html('danger', '/file-scanner');
  assert.match(danger, /Next step/);
  assert.doesNotMatch(danger, /\/pro|Pro · coming soon/);
});

test('no card on a password check or inside a dialog', () => {
  assert.doesNotMatch(html('safe', '/password-check'), /Next step/);
  assert.doesNotMatch(html('safe', '/dashboard', {buttons: false}), /Next step/);
});
