/* Message check page: a screenshot goes to /api/check-message; while the links in it are scanned in the
   isolated browser, /api/check-message/finish is asked until the verdict is ready. Then the plain report,
   the AI review, the links (each with a coloured dot and its saved report) and the next steps. Links from
   the message are never made clickable: only our own reports and our own list of official sites are. */
(function () {
  'use strict';
  const form = document.getElementById('mc-form');
  if (!form) return;
  const picker = document.getElementById('mc-image');
  const drop = document.getElementById('mc-drop');
  const loading = document.getElementById('mc-loading');
  const steps = document.getElementById('mc-steps');
  const error = document.getElementById('mc-error');
  const extra = document.getElementById('mc-extra');
  const fb = document.getElementById('mc-fb');
  const tr = document.documentElement.lang === 'tr';
  const say = (en, trText) => (tr ? trText : en);
  const TYPES = ['image/png', 'image/jpeg', 'image/webp'];
  const STEPS = [say('Reading the screenshot', 'Ekran görüntüsü okunuyor'), say('Hiding personal data', 'Kişisel veriler gizleniyor'),
    say('Scanning the links in our isolated browser', 'Bağlantılar yalıtılmış tarayıcımızda taranıyor'),
    say('Our AI is reviewing the message', 'Yapay zekâmız mesajı inceliyor'), say('Putting the result together', 'Sonuç hazırlanıyor')];
  const STATE = {bad: say('DANGEROUS', 'TEHLİKELİ'), warn: say('SUSPICIOUS', 'ŞÜPHELİ'), ok: say('NO THREAT FOUND', 'TEHDİT YOK'),
    official: say('OFFICIAL SITE', 'RESMİ SİTE'), scanning: say('STILL SCANNING', 'TARANIYOR'), na: say('NOT CHECKED', 'KONTROL EDİLEMEDİ')};
  const NOTES = {
    'listed as dangerous by a threat list': say('listed as dangerous by a threat list', 'bir tehdit listesinde tehlikeli olarak geçiyor'),
    'short link: the real address is hidden': say('short link: the real address is hidden', 'kısaltılmış bağlantı: gerçek adres gizli'),
  };
  const note = (n) => NOTES[n] || (/^Possible typosquatting of /.test(n) ? say(n, n.replace('Possible typosquatting of ', '') + ' adresini taklit ediyor olabilir') : n);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const csrf = () => { const t = document.querySelector('meta[name="csrf-token"]'); return t ? {'X-CSRFToken': t.content} : {}; };
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  let last = null, busy = false, ticker = null;

  async function post(url, body, json) {
    const response = await fetch(url, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: json ? {...csrf(), 'Content-Type': 'application/json'} : csrf(), body: json ? JSON.stringify(body) : body});
    const data = await response.json().catch(() => ({}));
    const BUSY = {too_fast: say('Too many checks in a row. Please wait a minute and try again.', 'Arka arkaya çok fazla kontrol yaptın. Bir dakika bekleyip tekrar dene.'),
      ocr_busy: say('Many screenshots are being read right now. Please try again in a moment.', 'Şu an çok sayıda ekran görüntüsü okunuyor. Birazdan tekrar dene.')};
    if (BUSY[data.code]) throw Error(BUSY[data.code]);
    if (response.status === 429) throw Error(say('Today’s message-check allowance is used up. It resets at 00:00 UTC.', 'Bugünkü mesaj kontrolü hakkın doldu. 00:00 UTC’de yenilenir.'));
    if (!response.ok || data.error) throw Error(typeof data.error === 'string' ? data.error : say('The check is unavailable right now. Please retry.', 'Kontrol şu an yapılamıyor. Lütfen tekrar dene.'));
    return {status: response.status, data};
  }

  function reset() {
    error.hidden = true; extra.hidden = true;
    if (window.PlainReport) window.PlainReport.unmount('mc');
  }

  async function check(file) {
    if (busy || !file) return;
    if (!TYPES.includes(file.type)) { show(say('Send a PNG, JPEG or WebP screenshot.', 'PNG, JPEG ya da WebP bir ekran görüntüsü gönder.')); return; }
    if (file.size > 8 * 1024 * 1024) { show(say('The image is too large (8 MB at most).', 'Görsel çok büyük (en fazla 8 MB).')); return; }
    const body = new FormData(); body.append('image', file); body.append('lang', tr ? 'tr' : 'en');
    return run(body, false, file);
  }

  /** The text read from a screenshot, corrected by the reader: checked again without the image. */
  function recheck(text) {
    if (!text.trim()) return;
    return run({text: text.slice(0, 6000), lang: tr ? 'tr' : 'en'}, true, null);
  }

  async function run(body, json, file) {
    if (busy) return;
    busy = true; reset(); form.hidden = true; loading.hidden = false;
    const img = document.getElementById('mc-shot-img');
    if (file) { img.src = URL.createObjectURL(file); document.getElementById('mc-shot-name').textContent = file.name || ''; }
    document.getElementById('mc-shot').hidden = !file;
    let step = 0; steps.textContent = STEPS[0];
    ticker = setInterval(() => { step = Math.min(step + 1, STEPS.length - 1); steps.textContent = STEPS[step]; }, 2600);
    try {
      let {status, data} = await post('/api/check-message', body, json);
      // The links are being scanned: ask until every scan is done, at most about two minutes.
      for (let round = 0; status === 202 && data.token; round++) {
        const token = data.token;
        await wait(round < 10 ? 2500 : 4000);
        ({status, data} = await post('/api/check-message/finish', {token, final: round >= 32}, true));
        if (status === 202) data.token = token;
      }
      render(data);
    } catch (e) {
      show(e.message); form.hidden = false;
    } finally {
      clearInterval(ticker); busy = false; loading.hidden = true; picker.value = '';
      if (file) URL.revokeObjectURL(img.src);
    }
  }

  function show(message) { error.textContent = message; error.hidden = false; }

  function render(data) {
    const plain = data.plain || {};
    last = {tone: plain.tone, signals: Array.isArray(data.signals) ? data.signals : []};
    if (window.PlainReport) window.PlainReport.mount('mc', plain, {plainShare: true, again: {href: '/message-check', label: say('Check another screenshot', 'Başka bir ekran görüntüsü kontrol et')}});
    const ai = Array.isArray(plain.ai_reasons) ? plain.ai_reasons : [];
    document.getElementById('mc-ai').hidden = !ai.length;
    document.getElementById('mc-ai-list').innerHTML = ai.map((r) => `<p>${esc(r)}</p>`).join('');
    const links = Array.isArray(data.links) ? data.links : [];
    document.getElementById('mc-links').hidden = !links.length;
    document.getElementById('mc-link-list').innerHTML = links.map((l) => {
      const state = STATE[l.state] ? l.state : 'na';
      const notes = (Array.isArray(l.notes) ? l.notes : []).map(note).join(' · ');
      const inner = `<i class="mc-dot ${state}" aria-hidden="true"></i><code>${esc(l.shown)}</code><b class="mc-state ${state}">${esc(STATE[state])}</b>`
        + (notes ? `<span class="mc-notes">${esc(notes)}</span>` : '');
      return Number.isInteger(l.scan_id)
        ? `<a class="mc-link" href="/result/${l.scan_id}">${inner}<span class="mc-open">${esc(say('Open the report →', 'Raporu aç →'))}</span></a>`
        : `<div class="mc-link">${inner}<span>${esc(say('Quick check only', 'Yalnızca hızlı kontrol'))}</span></div>`;
    }).join('');
    const asks = Array.isArray(data.asks) ? data.asks : [];
    document.getElementById('mc-asks').hidden = !asks.length;
    document.getElementById('mc-asks-list').innerHTML = asks.map((a) => `<li>${esc(a)}</li>`).join('');
    const sources = Array.isArray(data.verify) ? data.verify : [];
    document.getElementById('mc-verify').hidden = !sources.length;
    document.getElementById('mc-verify-list').innerHTML = sources.map((v) => `<div class="mc-src"><b>${esc(v.name)}</b><span>${esc(v.how)}</span>`
      + (/^https:\/\/[a-z0-9.-]+\/?$/.test(v.url || '') ? `<a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer">${esc(say('Open the official site ↗', 'Resmi siteyi aç ↗'))}</a>` : '')
      + '</div>').join('');
    document.getElementById('mc-help').hidden = !(plain.tone === 'danger' || plain.tone === 'caution');
    read.hidden = !data.text; read.open = false;
    readText.textContent = data.text || ''; readText.hidden = false;
    readEdit.hidden = true; recheckButton.hidden = true; editButton.hidden = false;
    fb.querySelectorAll('button').forEach((x) => { x.disabled = false; });
    document.getElementById('mc-fb-done').hidden = true;
    extra.hidden = false;
    const box = document.getElementById('mc-plain');
    if (box && !box.hidden) box.scrollIntoView({behavior: 'smooth', block: 'start'});
  }

  const read = document.getElementById('mc-read');
  const readText = document.getElementById('mc-read-text');
  const readEdit = document.getElementById('mc-read-edit');
  const editButton = document.getElementById('mc-edit-read');
  const recheckButton = document.getElementById('mc-recheck');
  editButton.addEventListener('click', () => {
    readEdit.value = readText.textContent.slice(0, 6000);
    readText.hidden = true; readEdit.hidden = false; editButton.hidden = true; recheckButton.hidden = false;
    readEdit.focus();
  });
  recheckButton.addEventListener('click', () => recheck(readEdit.value));

  picker.addEventListener('change', () => check(picker.files && picker.files[0]));
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => check(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]));
  document.addEventListener('paste', (e) => {
    const item = [...((e.clipboardData && e.clipboardData.items) || [])].find((i) => i.kind === 'file' && TYPES.includes(i.type));
    if (item) { e.preventDefault(); check(item.getAsFile()); }
  });

  fb.querySelectorAll('[data-answer]').forEach((b) => b.addEventListener('click', async () => {
    if (!last) return;
    fb.querySelectorAll('button').forEach((x) => { x.disabled = true; });
    try { await post('/api/message-feedback', {tone: last.tone, answer: b.dataset.answer, signals: last.signals}, true); }
    catch (e) { /* nothing to tell the reader */ }
    document.getElementById('mc-fb-done').hidden = false;
  }));
})();
