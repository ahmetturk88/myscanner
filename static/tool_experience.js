/* Inspection-page helpers: "/" focuses the main input; recent targets are kept
   only in this browser (never for passwords, emails or files). Text only. */
(function () {
  'use strict';
  const rail = document.querySelector('.tx-rail');
  if (!rail) return;
  const input = rail.dataset.input ? document.querySelector(rail.dataset.input) : null;
  const key = 'myscanner:recent:' + rail.dataset.tool;
  const remember = rail.dataset.remember === 'true' && input;

  document.addEventListener('keydown', event => {
    if (event.key !== '/' || !input || event.ctrlKey || event.metaKey || event.altKey) return;
    const active = document.activeElement;
    if (active && (active.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName))) return;
    if (document.querySelector('dialog[open]')) return;
    event.preventDefault();
    input.focus();
    input.select && input.select();
  });

  if (!remember) return;
  const box = rail.querySelector('.tx-recent'), list = rail.querySelector('.tx-recent-list');
  function load() { try { const v = JSON.parse(localStorage.getItem(key) || '[]'); return Array.isArray(v) ? v.filter(x => typeof x === 'string').slice(0, 6) : []; } catch (e) { return []; } }
  function save(items) { try { localStorage.setItem(key, JSON.stringify(items)); } catch (e) { /* storage unavailable */ } }
  function render() {
    const items = load();
    box.hidden = items.length === 0;
    const fragment = document.createDocumentFragment();
    items.forEach(value => {
      const chip = document.createElement('button');
      chip.type = 'button'; chip.className = 'tx-chip'; chip.textContent = value; chip.title = 'Use ' + value;
      chip.addEventListener('click', () => { input.value = value; input.dispatchEvent(new Event('input', {bubbles: true})); input.focus(); });
      fragment.appendChild(chip);
    });
    list.replaceChildren(fragment);
  }
  function record() {
    const value = (input.value || '').trim();
    if (!value || value.length > 300) return;
    save([value, ...load().filter(item => item !== value)].slice(0, 6));
    render();
  }
  const form = rail.dataset.form ? document.querySelector(rail.dataset.form) : null;
  if (form) form.addEventListener('submit', record);
  const trigger = rail.dataset.trigger ? document.querySelector(rail.dataset.trigger) : null;
  if (trigger) trigger.addEventListener('click', record);
  rail.querySelector('.tx-recent-clear').addEventListener('click', () => { save([]); render(); });
  render();
})();
