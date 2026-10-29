/* Plain-language report summary shared by the URL and file reports.
   Every value comes from the server's summary builder and is escaped here. */
(function (root) {
  'use strict';
  const ICON = {
    bad: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    warn: '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4M12 17h.01"/>',
    ok: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    na: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  };
  const HERO = {
    danger: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>',
    caution: ICON.warn,
    unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5V14M12 17h.01"/>',
    safe: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    info: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
  };
  const SVG = (paths, size, width) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
  const SHARE = SVG('<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/>', 18, 2.2);
  const NO_CAMERA = SVG('<path d="M3 3l18 18"/><path d="M21 17V8a2 2 0 0 0-2-2h-3l-2-3H10M6.3 6H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h14"/><path d="M9.5 9.6A3.5 3.5 0 0 0 14.4 14.5"/>', 26, 1.8);
  const SEARCH = SVG('<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>', 18, 2.2);
  const STATES = ['bad', 'warn', 'ok', 'na', 'info'];
  // The next check that fits the tool just used. Scams come as a message plus a link, a file or a code.
  const CHECK_LINK = ['/dashboard', 'Check a link'], CHECK_FILE = ['/file-scanner', 'Check a file'], CHECK_SENDER = ['/email-check', 'Check a sender'];
  const NEXT = {
    '/dashboard': ['Who sent you this link?', 'Check the sender’s email address too, and any file that came with it.', [CHECK_SENDER, CHECK_FILE], 'url'],
    '/file-scanner': ['Where did this file come from?', 'Check the link or the email address it came with too.', [CHECK_LINK, CHECK_SENDER], 'file'],
    '/email-check': ['Did the email have a link or a file?', 'Check them before you open anything.', [CHECK_LINK, CHECK_FILE], 'email'],
    '/qr-scanner': ['Where did you find this code?', 'Codes on letters, parking meters and messages get swapped. Check who sent it too.', [CHECK_SENDER, CHECK_FILE], 'qr'],
  };
  const NEXT_OTHER = ['Got a suspicious message?', 'Check its link, file or sender before you act.', [CHECK_LINK, CHECK_FILE, CHECK_SENDER], 'other'];
  // Never on a password check, and Pro never next to a "dangerous" verdict: no selling to someone who may have just been scammed.
  function nextCard(href, tone) {
    if (href === '/password-check') return '';
    const [title, detail, links, ref] = NEXT[href] || NEXT_OTHER;
    const go = links.filter(([path]) => path !== href).map(([path, label]) => `<a class="rp-next-link" href="${path}">${esc(label)}</a>`).join('');
    const pro = tone === 'danger' ? '' : `<div class="rp-pro"><span class="rp-pro-tag">Pro · coming soon</span>
      <p>Got this in a message? Pro will check the whole message or a screenshot: every link, IBAN and QR code in it.</p>
      <a class="rp-pro-link" href="/pro?ref=report-${ref}">Get notified</a></div>`;
    return `<section class="rp-card rp-next"><h2>Next step</h2><strong>${esc(title)}</strong><p>${esc(detail)}</p><div class="rp-next-links">${go}</div>${pro}</section>`;
  }

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  }
  function own(map, key) { return Object.prototype.hasOwnProperty.call(map, key) ? key : null; }
  function icon(kind, size) {
    const k = own(ICON, kind) || 'na';
    return SVG(ICON[k], size, 2).replace('<svg ', `<svg class="rp-i rp-${k}" `);
  }
  function objects(value) { return Array.isArray(value) ? value.filter(x => x && typeof x === 'object') : []; }

  // options: again {href, label}, screenshot (a same-origin path or ''), checked (text),
  // feedback (element for share messages), h1 (the headline is the page's main heading),
  // plainShare (say "Share this warning" even when dangerous: nothing was "sent" to the user).
  // buttons: false hides the button row (inside a dialog).
  function render(box, plain, options) {
    if (!box || !plain || typeof plain !== 'object' || Array.isArray(plain)) return false;
    const opts = options || {};
    const tone = ['danger', 'caution', 'unknown', 'safe', 'info'].includes(plain.tone) ? plain.tone : 'unknown';
    const target = plain.url && typeof plain.url === 'object' ? plain.url : {};
    const reasons = objects(plain.reasons).map(r => `<li>${icon(r.tone, 22)}<div><strong>${esc(r.title)}</strong><span>${esc(r.detail)}</span></div></li>`).join('');
    const actions = (Array.isArray(plain.actions) ? plain.actions : []).filter(a => typeof a === 'string').map((a, i) => `<li><span class="rp-n">${i + 1}</span><span>${esc(a)}</span></li>`).join('');
    const checks = objects(plain.checks).map(c => {
      const state = STATES.includes(c.state) ? c.state : 'na';
      return `<li>${icon(state, 20)}<span class="rp-cn">${esc(c.name)}</span><span class="rp-cr rp-${state}">${esc(c.result)}</span></li>`;
    }).join('');
    const again = opts.again && /^\/[A-Za-z0-9/_-]*$/.test(opts.again.href || '') ? opts.again : {href: '/dashboard', label: 'Start a new scan'};
    const share = (cls, label) => `<button type="button" class="rp-btn ${cls}" data-rp-share>${SHARE}${esc(label)}</button>`;
    const another = cls => `<a class="rp-btn ${cls}" href="${esc(again.href)}">${SEARCH}${esc(again.label)}</a>`;
    // A summary without share text (a password check) never offers sharing.
    const buttons = typeof plain.share_text !== 'string' || !plain.share_text ? another('rp-primary')
      : tone === 'danger' || tone === 'caution'
      ? share('rp-primary', tone === 'danger' && !opts.plainShare ? 'Warn whoever sent it' : 'Share this warning') + another('rp-ghost')
      : another('rp-primary') + share('rp-ghost', 'Share report');
    const shot = /^\/api\/scan_screenshot\/\d+$/.test(opts.screenshot || '') ? opts.screenshot : '';
    // Without a screenshot, say why (bad certificate, a download, the site down…) instead of hiding the card.
    const why = typeof plain.no_preview === 'string' ? plain.no_preview : '';
    const missing = `<div class="rp-nopreview">${NO_CAMERA}<div><strong>No preview</strong><span>${esc(why)}</span></div></div>`;
    const preview = shot ? `<section class="rp-card rp-preview"><h2>Page preview</h2><img src="${esc(shot)}" alt="Screenshot of the scanned page" loading="lazy"><p>Taken in an isolated browser on our server. Your device never opened the page. A normal-looking page is not proof of safety.</p></section>`
      : why ? `<section class="rp-card rp-preview"><h2>Page preview</h2>${missing}</section>` : '';
    const checked = typeof opts.checked === 'string' ? opts.checked : typeof plain.checked === 'string' ? plain.checked : '';
    box.dataset.tone = tone;
    box.innerHTML = `<div class="rp-main">
      <section class="rp-hero"><div class="rp-ring">${SVG(HERO[tone], 42, 1.8)}</div>
        <div class="rp-hero-copy"><span class="rp-label">${esc(plain.label)}</span><${opts.h1 ? 'h1' : 'h2'} class="rp-headline">${esc(plain.headline)}</${opts.h1 ? 'h1' : 'h2'}><p>${esc(plain.summary)}</p>
        <div class="rp-url">${esc(target.prefix)}<b>${esc(target.host)}</b>${esc(target.rest)}</div><span class="rp-when">${esc(checked)}</span></div></section>
      <div class="rp-pair">${reasons ? `<section class="rp-why"><h2>${esc(typeof plain.why_title === 'string' ? plain.why_title : 'Why we think so')}</h2><ul>${reasons}</ul></section>` : ''}
      <section class="rp-card rp-do"><h2>${tone === 'safe' ? 'Good to know' : 'What to do'}</h2><ol>${actions}</ol></section></div>
      ${opts.buttons === false ? '' : `<div class="rp-buttons">${buttons}</div>`}<div class="rp-ai"></div></div>
    <aside class="rp-side"><section class="rp-card rp-checks"><div class="rp-head"><h2>What we checked</h2><span>${esc(plain.tally)}</span></div><ul>${checks}</ul></section>${preview}${opts.buttons === false ? '' : nextCard(again.href, tone)}
      <p class="rp-note">A scan checks known warning signs at one moment in time. It can’t guarantee that something is safe.</p></aside>`;
    const img = box.querySelector('.rp-preview img');
    if (img) img.addEventListener('error', () => {
      const card = img.closest('.rp-preview');
      if (!card) return;
      if (!why) { card.remove(); return; }
      card.innerHTML = `<h2>Page preview</h2>${missing}`;
    });
    box.querySelectorAll('[data-rp-share]').forEach(button => button.addEventListener('click', () => shareText(plain.share_text, opts.feedback)));
    box.hidden = false;
    return true;
  }

  function say(feedback, text) {
    if (!feedback) return;
    feedback.textContent = text;
    setTimeout(() => { if (feedback.textContent === text) feedback.textContent = ''; }, 4000);
  }
  async function shareText(text, feedback) {
    if (typeof text !== 'string' || !text) return;
    const nav = root.navigator || (typeof navigator !== 'undefined' ? navigator : {});
    if (nav.share) {
      try { await nav.share({text}); return; } catch (error) { if (error && error.name === 'AbortError') return; }
    }
    try { await nav.clipboard.writeText(text); say(feedback, 'Warning copied. Paste it into your chat.'); }
    catch (error) { say(feedback, 'Could not copy. Share the report yourself.'); }
  }

  // Pages that keep their evidence in #<key>-tech: show the summary in #<key>-plain,
  // reveal the evidence section and open it when there is no summary.
  function mount(key, plain, options) {
    const doc = root.document, tech = doc.getElementById(key + '-tech'), box = doc.getElementById(key + '-plain');
    const shown = render(box, plain, Object.assign({feedback: doc.getElementById(key + '-feedback')}, options));
    if (!shown && box) box.hidden = true;
    if (tech) { tech.hidden = false; tech.open = !shown; }
    return shown;
  }
  function unmount(key) {
    for (const suffix of ['-plain', '-tech']) { const node = root.document.getElementById(key + suffix); if (node) node.hidden = true; }
  }

  root.PlainReport = {render, mount, unmount, share: shareText, escape: esc};
})(typeof window !== 'undefined' ? window : globalThis);
