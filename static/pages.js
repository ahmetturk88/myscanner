/* Motion and small interactions for the About, Contact, Profile and Workspace pages.
   Text is only ever written with textContent; no HTML sinks. */
(function () {
  'use strict';
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const root = document.documentElement;
  root.classList.remove('no-js');

  function countUp(el) {
    const target = Number(el.dataset.count);
    if (!Number.isFinite(target)) return;
    const suffix = el.dataset.suffix || '';
    if (reduced || target === 0) { el.textContent = target + suffix; return; }
    const start = performance.now(), duration = 1400;
    (function frame(now) {
      const t = Math.min(1, (now - start) / duration), eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(target * eased) + suffix;
      if (t < 1) requestAnimationFrame(frame);
    })(start);
  }

  function fill(el) {
    const value = Math.max(0, Math.min(100, Number(el.dataset.fill) || 0));
    el.style.width = value + '%';
  }

  function activate(el) {
    el.classList.add('in');
    el.querySelectorAll('[data-count]').forEach(countUp);
    el.querySelectorAll('[data-fill]').forEach(fill);
    if (el.matches('[data-count]')) countUp(el);
    if (el.matches('[data-fill]')) fill(el);
    if (el.matches('[data-console]')) playConsole(el);
  }

  const watched = document.querySelectorAll('.pg-reveal, .pg-timeline, [data-console], .pg-stats, [data-meters]');
  if ('IntersectionObserver' in window && !reduced) {
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { activate(entry.target); observer.unobserve(entry.target); }
    }), {threshold: 0.18, rootMargin: '0px 0px -40px 0px'});
    watched.forEach(el => observer.observe(el));
  } else {
    watched.forEach(activate);
  }

  // Spotlight follows the pointer on glow cards.
  document.querySelectorAll('.pg-card.glow').forEach(card => {
    card.addEventListener('pointermove', event => {
      const box = card.getBoundingClientRect();
      card.style.setProperty('--mx', (event.clientX - box.left) + 'px');
      card.style.setProperty('--my', (event.clientY - box.top) + 'px');
    });
  });

  // Console: reveal prepared lines one by one, then loop.
  function playConsole(box) {
    if (box.dataset.playing) return;
    box.dataset.playing = '1';
    const lines = [...box.querySelectorAll('.pg-console-line')], verdict = box.querySelector('.pg-console-verdict');
    if (reduced) { lines.forEach(l => l.classList.add('on')); if (verdict) verdict.classList.add('on'); return; }
    let i = 0;
    (function step() {
      if (i < lines.length) { lines[i++].classList.add('on'); setTimeout(step, 520); return; }
      if (verdict) verdict.classList.add('on');
      setTimeout(() => { lines.forEach(l => l.classList.remove('on')); if (verdict) verdict.classList.remove('on'); i = 0; setTimeout(step, 700); }, 5200);
    })();
  }

  // Category filters: buttons carry data-filter, items carry data-category.
  document.querySelectorAll('[data-filter-group]').forEach(group => {
    const items = document.querySelectorAll(group.dataset.filterGroup);
    group.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {
      group.querySelectorAll('[data-filter]').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
      items.forEach(item => { item.hidden = button.dataset.filter !== 'all' && item.dataset.category !== button.dataset.filter; });
    }));
  });

  // Copy buttons.
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    const label = button.querySelector('span:last-child');
    const original = label ? label.textContent : '';
    try { await navigator.clipboard.writeText(button.dataset.copy); if (label) label.textContent = 'Copied'; }
    catch (error) { if (label) label.textContent = 'Copy unavailable'; }
    setTimeout(() => { if (label) label.textContent = original; }, 1800);
  }));

  // Local time in a fixed zone with an open/closed hint.
  document.querySelectorAll('[data-clock]').forEach(clock => {
    const zone = clock.dataset.clock, time = clock.querySelector('[data-clock-time]'), state = clock.querySelector('[data-clock-state]');
    function tick() {
      try {
        const now = new Date();
        time.textContent = new Intl.DateTimeFormat('en-GB', {timeZone: zone, hour: '2-digit', minute: '2-digit'}).format(now);
        const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {timeZone: zone, weekday: 'short', hour: 'numeric', hour12: false}).formatToParts(now).map(p => [p.type, p.value]));
        const hour = Number(parts.hour) % 24, day = parts.weekday;
        const open = (day !== 'Sun' && day !== 'Sat' && hour >= 9 && hour < 18) || (day === 'Sat' && hour >= 10 && hour < 16);
        if (state) { state.textContent = open ? 'Open now' : 'Outside business hours'; state.className = 'pg-pill ' + (open ? 'ok' : 'muted'); }
      } catch (error) { time.textContent = '--:--'; }
    }
    tick(); setInterval(tick, 30000);
  });

  // Greeting by local time.
  document.querySelectorAll('[data-greeting]').forEach(el => {
    const hour = new Date().getHours();
    el.textContent = hour < 5 ? 'Working late' : hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  });

  // Countdown to the next UTC midnight (daily allowance reset).
  document.querySelectorAll('[data-reset-countdown]').forEach(el => {
    function tick() {
      const now = new Date(), next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
      const minutes = Math.max(0, Math.floor((next - now.getTime()) / 60000));
      el.textContent = Math.floor(minutes / 60) + 'h ' + String(minutes % 60).padStart(2, '0') + 'm';
    }
    tick(); setInterval(tick, 30000);
  });
})();

/* Sign-in and registration helpers. */
(function () {
  'use strict';
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  document.querySelectorAll('[data-ticker]').forEach(box => {
    const lines = [...box.children];
    if (reduced) { lines.forEach(l => l.classList.add('on')); return; }
    let i = 0;
    (function step() {
      if (i < lines.length) { lines[i++].classList.add('on'); setTimeout(step, 700); return; }
      setTimeout(() => { lines.forEach(l => l.classList.remove('on')); i = 0; setTimeout(step, 600); }, 3200);
    })();
  });

  document.querySelectorAll('[data-toggle-password]').forEach(button => {
    const input = document.getElementById(button.dataset.togglePassword);
    if (!input) return;
    button.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
  });

  document.querySelectorAll('[data-capslock-for]').forEach(hint => {
    const input = document.getElementById(hint.dataset.capslockFor);
    if (!input) return;
    const check = event => { hint.hidden = !(event.getModifierState && event.getModifierState('CapsLock')); };
    input.addEventListener('keyup', check);
    input.addEventListener('keydown', check);
    input.addEventListener('blur', () => { hint.hidden = true; });
  });

  // Mirrors the server password policy in app.password_policy_errors.
  const RULES = {
    length: v => v.length >= 8, upper: v => /[A-Z]/.test(v), lower: v => /[a-z]/.test(v),
    number: v => /[0-9]/.test(v), special: v => /[!@#$%^&*(),.?":{}|<>]/.test(v)
  };
  document.querySelectorAll('[data-strength-for]').forEach(meter => {
    const input = document.getElementById(meter.dataset.strengthFor);
    const rules = document.querySelectorAll('[data-rule]');
    const label = document.querySelector('[data-strength-label]');
    if (!input) return;
    input.addEventListener('input', () => {
      const value = input.value;
      let met = 0;
      rules.forEach(item => { const ok = RULES[item.dataset.rule] && RULES[item.dataset.rule](value); item.classList.toggle('met', !!ok); if (ok) met++; });
      const level = !value ? 0 : met <= 2 ? 1 : met === 3 ? 2 : met === 4 ? 3 : (value.length >= 12 ? 4 : 3);
      meter.dataset.level = String(level);
      if (label) label.textContent = ['', 'Weak', 'Fair', 'Good', 'Strong'][level];
    });
  });

  document.querySelectorAll('[data-match-for]').forEach(note => {
    const [first, second] = note.dataset.matchFor.split(',').map(id => document.getElementById(id));
    if (!first || !second) return;
    const check = () => {
      if (!second.value) { note.textContent = ''; note.className = 'auth-match'; return; }
      const same = first.value === second.value;
      note.textContent = same ? 'Passwords match' : 'Passwords do not match yet';
      note.className = 'auth-match ' + (same ? 'ok' : 'bad');
    };
    first.addEventListener('input', check); second.addEventListener('input', check);
  });

  document.querySelectorAll('form[data-busy]').forEach(form => form.addEventListener('submit', () => {
    const button = form.querySelector('button[type=submit]');
    if (!button || !form.checkValidity()) return;
    setTimeout(() => { button.disabled = true; const label = button.querySelector('[data-label]'); if (label) label.textContent = form.dataset.busy; }, 0);
  }));
})();
