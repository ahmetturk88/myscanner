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
  const STATE = {bad: say('LISTED', 'LİSTEDE'), warn: say('SUSPICIOUS', 'ŞÜPHELİ'), ok: say('NOT LISTED', 'LİSTEDE YOK'), official: say('OFFICIAL SITE', 'RESMİ SİTE'), na: say('NOT CHECKED', 'KONTROL EDİLEMEDİ')};
  const NOTES = {
    'listed as dangerous by a threat list': say('listed as dangerous by a threat list', 'bir tehdit listesinde tehlikeli olarak geçiyor'),
    'short link: the real address is hidden': say('short link: the real address is hidden', 'kısaltılmış bağlantı: gerçek adres gizli'),
  };
  const note = (n) => NOTES[n] || (/^Possible typosquatting of /.test(n) ? say(n, n.replace('Possible typosquatting of ', '') + ' adını taklit ediyor olabilir') : n);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const update = () => { count.textContent = `${text.value.length} / 6000`; };
  text.addEventListener('input', update);
  const picker = document.getElementById('mc-image');
  const picked = document.getElementById('mc-picked');
  picker.addEventListener('change', () => {
    const file = picker.files && picker.files[0];
    picked.hidden = !file;
    document.getElementById('mc-picked-name').textContent = file ? `🖼 ${file.name}` : '';
  });
  document.getElementById('mc-unpick').addEventListener('click', () => { picker.value = ''; picked.hidden = true; });

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
    const file = picker.files && picker.files[0];
    if (!text.value.trim() && !file) { text.focus(); return; }
    hide(); button.disabled = true; loading.hidden = false;
    try {
      const token = document.querySelector('meta[name="csrf-token"]');
      let body, headers = token ? {'X-CSRFToken': token.content} : {};
      if (file) {
        body = new FormData(); body.append('image', file); body.append('text', text.value); body.append('lang', tr ? 'tr' : 'en');
      } else {
        body = JSON.stringify({text: text.value, lang: tr ? 'tr' : 'en'}); headers = {...headers, 'Content-Type': 'application/json'};
      }
      const response = await fetch('/api/check-message', {method: 'POST', credentials: 'same-origin', cache: 'no-store', headers, body});
      const data = await response.json().catch(() => ({}));
      const BUSY = {too_fast: say('Too many checks in a row. Please wait a minute and try again.', 'Arka arkaya çok fazla kontrol yaptın. Bir dakika bekleyip tekrar dene.'),
        ocr_busy: say('Many screenshots are being read right now. Please try again in a moment.', 'Şu an çok sayıda ekran görüntüsü okunuyor. Birazdan tekrar dene.')};
      if (BUSY[data.code]) throw Error(BUSY[data.code]);
      if (response.status === 429) throw Error(say('Today’s message-check allowance is used up. It resets at 00:00 UTC.', 'Bugünkü mesaj kontrolü hakkın doldu. 00:00 UTC’de yenilenir.'));
      if (!response.ok || data.error) throw Error(typeof data.error === 'string' ? data.error : say('The check is unavailable right now. Please retry.', 'Kontrol şu an yapılamıyor. Lütfen tekrar dene.'));
      if (window.PlainReport) window.PlainReport.mount('mc', data.plain, {plainShare: true, again: {href: '/message-check', label: say('Check another message', 'Başka bir mesaj kontrol et')}});
      const risky = data.plain && (data.plain.tone === 'danger' || data.plain.tone === 'caution');
      document.getElementById('mc-help').hidden = !risky;
      const ai = (data.plain && data.plain.ai_reasons) || [];
      document.getElementById('mc-ai').hidden = !ai.length;
      document.getElementById('mc-ai-list').innerHTML = ai.map((r) => `<li>${esc(r)}</li>`).join('');
      const links = data.links || [];
      document.getElementById('mc-links').hidden = !links.length;
      document.getElementById('mc-link-list').innerHTML = links.map((l) => `<div class="mc-link"><code>${esc(l.shown)}</code>`
        + `<span>${esc((l.notes || []).map(note).join(' · '))}</span><b class="mc-state ${esc(l.state)}">${esc(STATE[l.state] || '')}</b></div>`).join('');
      const read = document.getElementById('mc-read');
      read.hidden = !data.text;
      document.getElementById('mc-read-text').textContent = data.text || '';
      extra.hidden = !ai.length && !links.length && !data.text && !risky;
      const plain = document.getElementById('mc-plain');
      if (plain && !plain.hidden) plain.scrollIntoView({behavior: 'smooth', block: 'start'});
    } catch (e) {
      error.textContent = e.message; error.hidden = false;
    } finally {
      button.disabled = false; loading.hidden = true;
    }
  });
})();
