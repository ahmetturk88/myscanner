/* Message check page: sends the pasted text to /api/check-message and shows the plain report,
   the AI review and the links (defanged, never as clickable links). */
(function () {
  'use strict';
  const form = document.getElementById('mc-form');
  if (!form) return;
  const text = document.getElementById('mc-text');
  const count = document.getElementById('mc-count');
  const button = document.getElementById('mc-submit');
  const loading = document.getElementById('mc-loading');
  const error = document.getElementById('mc-error');
  const extra = document.getElementById('mc-extra');
  const tr = document.documentElement.lang === 'tr';
  const say = (en, trText) => (tr ? trText : en);
  const STATE = {bad: say('LISTED', 'LİSTEDE'), warn: say('SUSPICIOUS', 'ŞÜPHELİ'), ok: say('NOT LISTED', 'LİSTEDE YOK'), na: say('NOT CHECKED', 'KONTROL EDİLEMEDİ')};
  const NOTES = {
    'listed as dangerous by a threat list': say('listed as dangerous by a threat list', 'bir tehdit listesinde tehlikeli olarak geçiyor'),
    'short link: the real address is hidden': say('short link: the real address is hidden', 'kısaltılmış bağlantı: gerçek adres gizli'),
  };
  const note = (n) => NOTES[n] || (/^Possible typosquatting of /.test(n) ? say(n, n.replace('Possible typosquatting of ', '') + ' adını taklit ediyor olabilir') : n);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const update = () => { count.textContent = `${text.value.length} / 6000`; };
  text.addEventListener('input', update);

  document.getElementById('mc-paste').addEventListener('click', async () => {
    try { text.value = (await navigator.clipboard.readText()).slice(0, 6000); update(); text.focus(); }
    catch (e) { text.focus(); }
  });

  function hide() {
    error.hidden = true; extra.hidden = true;
    if (window.PlainReport) window.PlainReport.unmount('mc');
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!text.value.trim()) { text.focus(); return; }
    hide(); button.disabled = true; loading.hidden = false;
    try {
      const token = document.querySelector('meta[name="csrf-token"]');
      const response = await fetch('/api/check-message', {method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json', ...(token ? {'X-CSRFToken': token.content} : {})},
        body: JSON.stringify({text: text.value, lang: tr ? 'tr' : 'en'})});
      const data = await response.json().catch(() => ({}));
      if (response.status === 429) throw Error(say('Today’s message-check allowance is used up. It resets at 00:00 UTC.', 'Bugünkü mesaj kontrolü hakkın doldu. 00:00 UTC’de yenilenir.'));
      if (!response.ok || data.error) throw Error(typeof data.error === 'string' ? data.error : say('The check is unavailable right now. Please retry.', 'Kontrol şu an yapılamıyor. Lütfen tekrar dene.'));
      if (window.PlainReport) window.PlainReport.mount('mc', data.plain, {again: {href: '/message-check', label: say('Check another message', 'Başka bir mesaj kontrol et')}});
      const ai = (data.plain && data.plain.ai_reasons) || [];
      document.getElementById('mc-ai').hidden = !ai.length;
      document.getElementById('mc-ai-list').innerHTML = ai.map((r) => `<li>${esc(r)}</li>`).join('');
      const links = data.links || [];
      document.getElementById('mc-links').hidden = !links.length;
      document.getElementById('mc-link-list').innerHTML = links.map((l) => `<div class="mc-link"><code>${esc(l.shown)}</code>`
        + `<span>${esc((l.notes || []).map(note).join(' · '))}</span><b class="mc-state ${esc(l.state)}">${esc(STATE[l.state] || '')}</b></div>`).join('');
      extra.hidden = !ai.length && !links.length;
      const plain = document.getElementById('mc-plain');
      if (plain && !plain.hidden) plain.scrollIntoView({behavior: 'smooth', block: 'start'});
    } catch (e) {
      error.textContent = e.message; error.hidden = false;
    } finally {
      button.disabled = false; loading.hidden = true;
    }
  });
})();
