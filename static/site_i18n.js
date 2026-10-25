/* Translates text that page scripts add after load (results, messages,
   buttons), using the same catalog the server uses for the page itself
   (services/site_i18n.py). Loaded only when the page language is not English,
   after /i18n/<lang>.js has set window.MYSCANNER_I18N. Text without an entry
   is left as it is; nothing inside scripts, styles, inputs or
   [translate="no"] is touched. */
(function () {
  'use strict';
  const data = window.MYSCANNER_I18N;
  if (!data || !data.words) return;
  const words = data.words;
  const patterns = (data.patterns || []).map(([source, target]) => [new RegExp(source), target]);
  const months = data.months || {};
  const monthWord = new RegExp('\\b(' + Object.keys(months).sort((a, b) => b.length - a.length).join('|') + ')\\b', 'g');
  const ATTRIBUTES = ['placeholder', 'aria-label', 'title', 'alt'];
  const SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'CODE', 'PRE', 'NOSCRIPT']);

  function lookup(text) {
    const key = text.replace(/\s+/g, ' ').trim();
    if (!key) return null;
    if (Object.prototype.hasOwnProperty.call(words, key)) return words[key];
    if (!/^[\p{L}\p{N}]/u.test(key)) {
      // "✓ Valid", "⚠️ Detected", "🌐 DNS Records": keep the symbol, translate the words.
      const lead = key.match(/^[^\p{L}\p{N}(]+(?=[\p{L}\p{N}])/u);
      if (!lead) return null;
      const rest = lookup(key.slice(lead[0].length));
      return rest === null ? null : lead[0] + rest;
    }
    for (const [pattern, target] of patterns) {
      if (pattern.test(key)) {
        const out = key.replace(pattern, target);
        return Object.keys(months).length ? out.replace(monthWord, m => months[m] || m) : out;
      }
    }
    return null;
  }

  function skipped(element) {
    for (let node = element; node && node !== document.body; node = node.parentElement) {
      if (SKIP.has(node.tagName) || node.getAttribute('translate') === 'no') return true;
    }
    return false;
  }

  function translateText(node) {
    const found = lookup(node.nodeValue);
    if (found === null || skipped(node.parentElement)) return;
    const value = node.nodeValue;
    const lead = value.match(/^\s*/)[0], trail = value.match(/\s*$/)[0];
    const next = lead + found + trail;
    // Writing an unchanged value still fires the observer below: an entry that
    // translates to itself ("Port") would loop forever and freeze the page.
    if (next !== value) node.nodeValue = next;
  }

  function translateAttributes(element) {
    if (SKIP.has(element.tagName) && element.tagName !== 'INPUT' && element.tagName !== 'TEXTAREA') return;
    for (const name of ATTRIBUTES) {
      const value = element.getAttribute(name);
      if (!value) continue;
      const found = lookup(value);
      if (found !== null && found !== value) element.setAttribute(name, found);
    }
  }

  function walk(root) {
    if (root.nodeType === Node.TEXT_NODE) { translateText(root); return; }
    if (root.nodeType !== Node.ELEMENT_NODE || SKIP.has(root.tagName) && root.tagName !== 'INPUT' && root.tagName !== 'TEXTAREA') {
      if (root.nodeType === Node.ELEMENT_NODE) translateAttributes(root);
      return;
    }
    translateAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (node.nodeType === Node.TEXT_NODE) translateText(node); else translateAttributes(node);
    }
  }

  function start() {
    walk(document.body);
    new MutationObserver(records => {
      for (const record of records) {
        if (record.type === 'characterData') translateText(record.target);
        else if (record.type === 'attributes') translateAttributes(record.target);
        else record.addedNodes.forEach(walk);
      }
    }).observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRIBUTES });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
