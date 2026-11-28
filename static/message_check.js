/* Message check page. A screenshot (or an original .eml email) goes to /api/check-message; while the links in it are
   scanned in the isolated browser, /api/check-message/finish is asked until the verdict is ready. Then the plain
   report, the summary, the links (each with a coloured dot and its saved report) and the next steps.
   Links from the message are never made clickable: only our own reports and our own list of official sites are.
   The last result is kept in this tab (sessionStorage) so coming back from a link's report shows it again. */
(function () {
  'use strict';
  const form = document.getElementById('mc-form');
  if (!form) return;
  const $ = (id) => document.getElementById(id);
  const picker = $('mc-image');
  const drop = $('mc-drop');
  const loading = $('mc-loading');
  const error = $('mc-error');
  const extra = $('mc-extra');
  const fb = $('mc-fb');
  const tr = document.documentElement.lang === 'tr';
  const say = (en, trText) => (tr ? trText : en);
  const IMAGES = ['image/png', 'image/jpeg', 'image/webp'];
  const KEY = 'myscanner.messageCheck';
  const isEmail = (file) => /\.eml$/i.test(file.name || '') || file.type === 'message/rfc822';
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
  const store = {
    get() { try { return JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch (e) { return null; } },
    set(value) { try { sessionStorage.setItem(KEY, JSON.stringify(value)); } catch (e) { /* private mode: not kept */ } },
    clear() { try { sessionStorage.removeItem(KEY); } catch (e) { /* nothing kept */ } },
  };
  let last = null, busy = false, lastData = null;

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

  function step(n) {
    document.querySelectorAll('#mc-steps li').forEach((li) => {
      const i = Number(li.dataset.step);
      li.className = i < n ? 'done' : i === n ? 'now' : '';
      li.querySelector('i').textContent = i < n ? '✓' : '';
    });
  }

  function check(file) {
    if (busy || !file) return;
    const email = isEmail(file);
    if (!email && !IMAGES.includes(file.type)) { show(say('Send a PNG, JPEG or WebP screenshot, or an .eml email file.', 'PNG, JPEG ya da WebP bir ekran görüntüsü ya da .eml e-posta dosyası gönder.')); return; }
    if (file.size > 8 * 1024 * 1024) { show(say('The file is too large (8 MB at most).', 'Dosya çok büyük (en fazla 8 MB).')); return; }
    const body = new FormData(); body.append(email ? 'email' : 'image', file); body.append('lang', tr ? 'tr' : 'en');
    // The original email of the message just checked builds on that check instead of starting again.
    if (email && lastData && typeof lastData.token === 'string') body.append('previous', lastData.token);
    return run(body, false, email ? null : file);
  }

  /** The text read from a screenshot, corrected by the reader: checked again without the image. */
  function recheck(text) {
    if (!text.trim()) return;
    return run({text: text.slice(0, 6000), lang: tr ? 'tr' : 'en'}, true, null);
  }

  async function run(body, json, image) {
    if (busy) return;
    busy = true; reset(); store.clear(); form.hidden = true; loading.hidden = false;
    const frame = $('mc-frame'), img = $('mc-shot-img');
    frame.classList.toggle('doc', !image);
    img.hidden = !image;
    if (image) img.src = URL.createObjectURL(image);
    step(0);
    const ticker = setTimeout(() => step(1), 1800);
    try {
      let {status, data} = await post('/api/check-message', body, json);
      clearTimeout(ticker); step(status === 202 ? 2 : 3);
      // The links are being scanned: ask until every scan is done, at most about two minutes.
      for (let round = 0; status === 202 && data.token; round++) {
        const token = data.token;
        await wait(round < 10 ? 2500 : 4000);
        ({status, data} = await post('/api/check-message/finish', {token, final: round >= 32}, true));
        if (status === 202) data.token = token; else step(3);
      }
      render(data);
      store.set(data);
    } catch (e) {
      clearTimeout(ticker); show(e.message); form.hidden = false;
    } finally {
      busy = false; loading.hidden = true; picker.value = '';
      if (image) URL.revokeObjectURL(img.src);
    }
  }

  function show(message) { error.textContent = message; error.hidden = false; }

  function render(data) {
    lastData = data;
    const plain = data.plain || {};
    form.hidden = true;
    last = {tone: plain.tone, signals: Array.isArray(data.signals) ? data.signals : [], verify: Array.isArray(data.verify) && data.verify.length > 0};
    if (window.PlainReport) window.PlainReport.mount('mc', plain, {plainShare: true, again: {href: '/message-check?new=1', label: say('Check another screenshot', 'Başka bir ekran görüntüsü kontrol et')}});
    const reasons = Array.isArray(plain.ai_reasons) ? plain.ai_reasons : [];
    const lines = [plain.ai_summary].concat(reasons).filter((r) => typeof r === 'string' && r);
    $('mc-sum').hidden = !lines.length;
    $('mc-sum-text').innerHTML = lines.map((r) => `<p dir="auto">${esc(r)}</p>`).join('');
    $('mc-from').hidden = !data.sender;
    $('mc-from').textContent = data.sender ? say('Claims to be from: ', 'Gönderen olarak görünen: ') + data.sender : '';
    $('mc-eml').hidden = !data.hidden_link;
    const links = Array.isArray(data.links) ? data.links : [];
    $('mc-links').hidden = !links.length;
    $('mc-link-list').innerHTML = links.map((l) => {
      const state = STATE[l.state] ? l.state : 'na';
      const notes = (Array.isArray(l.notes) ? l.notes : []).map(note).join(' · ');
      const more = Number.isInteger(l.same_site) && l.same_site > 0
        ? say(`+${l.same_site} more links to the same site`, `Aynı siteye ${l.same_site} bağlantı daha`) : '';
      const shown = String(l.shown || '');
      const inner = `<i class="mc-dot ${state}" aria-hidden="true"></i><code title="${esc(shown)}">${esc(shown.length > 70 ? shown.slice(0, 69) + '…' : shown)}</code><b class="mc-state ${state}">${esc(STATE[state])}</b>`
        + (notes || more ? `<span class="mc-notes">${esc([notes, more].filter(Boolean).join(' · '))}</span>` : '');
      return Number.isInteger(l.scan_id)
        ? `<a class="mc-link" href="/result/${l.scan_id}">${inner}<span class="mc-open">${esc(say('Open the report →', 'Raporu aç →'))}</span></a>`
        : `<div class="mc-link">${inner}<span class="mc-notes">${esc(say('Quick check only', 'Yalnızca hızlı kontrol'))}</span></div>`;
    }).join('');
    const asks = Array.isArray(data.asks) ? data.asks : [];
    $('mc-asks').hidden = !asks.length;
    $('mc-asks-list').innerHTML = asks.map((a) => `<li>${esc(a)}</li>`).join('');
    const sources = Array.isArray(data.verify) ? data.verify : [];
    $('mc-verify').hidden = !sources.length;
    $('mc-verify-list').innerHTML = sources.map((v) => `<div class="mc-src"><b>${esc(v.name)}</b><span>${esc(v.how)}</span>`
      + (/^https:\/\/[a-z0-9.-]+\/?$/.test(v.url || '') ? `<a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer">${esc(say('Open the official site ↗', 'Resmi siteyi aç ↗'))}</a>` : '')
      + '</div>').join('');
    $('mc-help').hidden = !(plain.tone === 'danger' || plain.tone === 'caution');
    read.hidden = !data.text; read.open = false;
    readText.innerHTML = String(data.text || '').split('\n').map((line) => `<div dir="auto">${esc(line)}</div>`).join('');
    readText.dataset.text = data.text || '';
    readText.hidden = false; readEdit.hidden = true; recheckButton.hidden = true;
    editButton.hidden = data.source === 'email';  // an email file is read exactly; only a screenshot can be misread
    $('mc-with-email').hidden = !data.with_email;
    fb.querySelectorAll('button').forEach((x) => { x.disabled = false; x.hidden = false; });
    $('mc-fb-reply').hidden = true;
    extra.hidden = false;
    const box = $('mc-plain');
    if (box && !box.hidden) box.scrollIntoView({behavior: 'smooth', block: 'start'});
  }

  /** What the reader gets back for telling us whether the verdict was right. */
  function reply(answer) {
    const warned = last.tone === 'danger' || last.tone === 'caution';
    if (answer === 'scam' && !warned) {
      $('mc-help').hidden = false; $('mc-help').open = true;
      return say('Thank you, we will look into it to improve the check. If you already tapped, paid or shared a code, follow the steps above now.',
        'Teşekkürler, kontrolü iyileştirmek için inceleyeceğiz. Bağlantıya dokunduysan, ödeme yaptıysan ya da kod paylaştıysan yukarıdaki adımları hemen uygula.');
    }
    if (answer === 'real' && warned) {
      return say('Thank you, we will look into it. To be sure, open the company’s official app or site yourself, never through the message.',
        'Teşekkürler, inceleyeceğiz. Emin olmak için şirketin resmi uygulamasını ya da sitesini mesajdan değil, kendin aç.')
        + (last.verify ? say(' The official places are listed above.', ' Resmi adresler yukarıda.') : '');
    }
    return say('Thank you, that confirms the check got it right.', 'Teşekkürler, bu kontrolün doğru olduğunu gösteriyor.');
  }

  const read = $('mc-read');
  const readText = $('mc-read-text');
  const readEdit = $('mc-read-edit');
  const editButton = $('mc-edit-read');
  const recheckButton = $('mc-recheck');
  editButton.addEventListener('click', () => {
    readEdit.value = (readText.dataset.text || readText.textContent || '').slice(0, 6000);
    readText.hidden = true; readEdit.hidden = false; editButton.hidden = true; recheckButton.hidden = false;
    readEdit.focus();
  });
  recheckButton.addEventListener('click', () => recheck(readEdit.value));
  $('mc-eml-pick').addEventListener('click', () => picker.click());

  picker.addEventListener('change', () => check(picker.files && picker.files[0]));
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => check(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]));
  document.addEventListener('paste', (e) => {
    const item = [...((e.clipboardData && e.clipboardData.items) || [])].find((i) => i.kind === 'file' && IMAGES.includes(i.type));
    if (item) { e.preventDefault(); check(item.getAsFile()); }
  });

  fb.querySelectorAll('[data-answer]').forEach((b) => b.addEventListener('click', async () => {
    if (!last) return;
    fb.querySelectorAll('button').forEach((x) => { x.hidden = true; });
    $('mc-fb-reply').textContent = reply(b.dataset.answer);
    $('mc-fb-reply').hidden = false;
    try { await post('/api/message-feedback', {tone: last.tone, answer: b.dataset.answer, signals: last.signals}, true); }
    catch (e) { /* nothing to tell the reader */ }
  }));

  // Coming back from a link's report shows the same result; "Check another" starts clean.
  if (/[?&]new=1/.test(location.search || '')) {
    store.clear();
    try { history.replaceState(null, '', location.pathname); } catch (e) { /* keep the address */ }
  } else {
    const kept = store.get();
    if (kept && kept.plain) render(kept);
  }
})();
