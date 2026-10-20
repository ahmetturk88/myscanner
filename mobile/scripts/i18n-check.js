#!/usr/bin/env node
/**
 * Checks the Turkish dictionary against the code:
 *  - every string literal passed to t(...) under src/ has an entry in src/lib/i18n-tr.ts;
 *  - each entry keeps the same {placeholders} as its English key;
 *  - t() is only called with a plain string literal (so it can be checked).
 * Unused entries are listed as a warning. Exits with 1 on any error.
 * Usage: npm run i18n:check
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..', 'src');
const dictFile = path.join(root, 'lib', 'i18n-tr.ts');
const skip = new Set([dictFile, path.join(root, 'lib', 'i18n.ts')]);

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return files(full);
    return /\.tsx?$/.test(e.name) && !skip.has(full) ? [full] : [];
  });
}

// The dictionary is one object literal: evaluate it as plain JavaScript.
const source = fs.readFileSync(dictFile, 'utf8');
const start = source.indexOf('{', source.indexOf('TR'));
const end = source.lastIndexOf('}');
const TR = vm.runInNewContext(`(${source.slice(start, end + 1)})`);

/** Reads the string literal that starts at `i`; returns [value, endIndex] or null. */
function literal(text, i) {
  const quote = text[i];
  if (quote !== "'" && quote !== '"') return null;
  let j = i + 1;
  while (j < text.length && text[j] !== quote) {
    if (text[j] === '\\') j++;
    if (text[j] === '\n') return null;
    j++;
  }
  return [vm.runInNewContext(text.slice(i, j + 1)), j + 1];
}

const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
const errors = [];
const unique = () => [...new Set(errors)];
const used = new Set();
let calls = 0;

for (const file of files(root)) {
  const text = fs.readFileSync(file, 'utf8');
  const rel = path.relative(path.join(root, '..'), file);
  for (const m of text.matchAll(/(?<![\w.$])t\(\s*/g)) {
    const at = m.index + m[0].length;
    const line = text.slice(0, m.index).split('\n').length;
    const found = literal(text, at);
    if (!found) {
      errors.push(`${rel}:${line}  t() is called with something other than a string literal: ${text.slice(at, at + 40).split('\n')[0]}`);
      continue;
    }
    const after = text.slice(found[1]).trimStart()[0];
    if (after !== ')' && after !== ',') {
      errors.push(`${rel}:${line}  t() argument is not a single string literal`);
      continue;
    }
    calls++;
    const key = found[0];
    used.add(key);
    if (!(key in TR)) errors.push(`${rel}:${line}  missing Turkish text for ${JSON.stringify(key)}`);
    else if (placeholders(key) !== placeholders(TR[key])) errors.push(`${rel}:${line}  placeholders differ for ${JSON.stringify(key)}`);
  }
}

const unused = Object.keys(TR).filter((k) => !used.has(k));
for (const k of unused) console.warn(`warning: unused entry ${JSON.stringify(k)}`);
for (const e of unique()) console.error(e);
console.log(`${calls} t() calls, ${used.size} distinct strings, ${Object.keys(TR).length} Turkish entries, ${unique().length} problems, ${unused.length} unused.`);
process.exit(errors.length ? 1 : 0);
