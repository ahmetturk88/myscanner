/* AI explanation and chat for reports, plus the site-wide assistant. Answers stream in and are inserted as text, never HTML. */
(function (root) {
  'use strict';
  const SECTIONS = [
    ['reasons', 'Why this result'],
    ['next_steps', 'What to do now'],
    ['not_checked', 'What was not confirmed'],
    ['technical_notes', 'Technical notes'],
  ];
  const LABELS = {'WHY THIS RESULT': 'reasons', 'WHAT TO DO NOW': 'next_steps', 'NOT CONFIRMED': 'not_checked', 'TECHNICAL NOTES': 'technical_notes'};
  const UNAVAILABLE = 'The AI assistant is unavailable right now. Please try again in a minute.';
  const LIMIT_REACHED = "Today's AI allowance is used up. It resets at 00:00 UTC.";
  let panel = null;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function token() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  }

  /** Same clean-up the server applies: no tags, no Markdown emphasis or headings. */
  function plain(text) {
    return String(text)
      .replace(/<[^>]{0,200}>/g, '')
      .replace(/\*\*|__|`/g, '')
      .replace(/^\s{0,3}#{1,6}\s+/gm, '')
      .replace(/^(\s*)[*•]\s+/gm, '$1- ')
      .trim();
  }

  /** Read the labelled explanation text as it arrives, mirroring the server's parser. */
  function parseExplanation(text) {
    const data = {headline: '', summary: '', reasons: [], next_steps: [], not_checked: [], technical_notes: []};
    let current = null;
    for (const raw of plain(text).split('\n')) {
      const line = raw.trim();
      const colon = line.indexOf(':');
      const label = colon < 0 ? '' : line.slice(0, colon).trim().toUpperCase();
      const rest = colon < 0 ? '' : line.slice(colon + 1).trim();
      if (label === 'HEADLINE' || label === 'SUMMARY') {
        current = label.toLowerCase();
        data[current] = rest;
      } else if (LABELS[label] && !rest) {
        current = LABELS[label];
      } else if (Array.isArray(data[current]) && line.startsWith('-')) {
        const item = line.replace(/^[-\s]+/, '');
        if (!item) continue;
        if (current === 'reasons') {
          const bar = item.indexOf('|');
          data.reasons.push(bar < 0 ? {point: item, evidence: ''} : {point: item.slice(0, bar).trim(), evidence: item.slice(bar + 1).trim()});
        } else {
          data[current].push(item);
        }
      } else if ((current === 'headline' || current === 'summary') && line) {
        data[current] = (data[current] + ' ' + line).trim();
      }
    }
    return data;
  }

  function failure(status, data) {
    if (status === 429) return new Error(typeof data.error === 'string' ? data.error : LIMIT_REACHED);
    const fromServer = typeof data.error === 'string' && (status < 500 || status === 503);
    return new Error(fromServer ? data.error : UNAVAILABLE);
  }

  /** POST and read a streamed answer. onText gets the whole text so far; resolves with the final event. */
  async function stream(url, body, onText) {
    const response = await fetch(url, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': token()},
      body: JSON.stringify(body),
    });
    const type = response.headers.get('Content-Type') || '';
    if (!type.includes('text/event-stream') || !response.body) {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw failure(response.status, data);
      return data;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let text = '';
    let final = null;
    for (;;) {
      const {value, done} = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
      let cut;
      while ((cut = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        for (const line of block.split('\n')) {
          if (!line.startsWith('data:')) continue;
          let event;
          try { event = JSON.parse(line.slice(5)); } catch (e) { continue; }
          if (typeof event.delta === 'string') { text += event.delta; onText(text); }
          else if (typeof event.error === 'string') throw new Error(event.error);
          else if (event.done) final = event;
        }
      }
      if (done) break;
    }
    if (!final) throw new Error('The answer was interrupted. Please try again.');
    return final;
  }

  function renderExplanation(target, data) {
    target.replaceChildren();
    if (data.headline) target.append(el('h3', 'ai-headline', data.headline));
    if (data.summary) target.append(el('p', 'ai-summary', data.summary));
    for (const [key, title] of SECTIONS) {
      const items = Array.isArray(data[key]) ? data[key] : [];
      if (!items.length) continue;
      const section = el('section', 'ai-section ai-' + key.replace('_', '-'));
      section.append(el('h4', '', title));
      const list = el('ul');
      for (const item of items) {
        const row = el('li');
        if (item && typeof item === 'object') {
          row.append(el('span', '', item.point));
          if (item.evidence) row.append(el('small', 'ai-evidence', item.evidence));
        } else {
          row.textContent = String(item);
        }
        list.append(row);
      }
      section.append(list);
      target.append(section);
    }
  }

  /** A "Copy" button placed right after an answer. */
  function copyButton(text) {
    const button = el('button', 'ai-copy', 'Copy');
    button.type = 'button';
    button.setAttribute('aria-label', 'Copy answer');
    button.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); } catch (e) { return; }
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = 'Copy'; }, 2000);
    });
    return button;
  }

  function explanationText(data) {
    const parts = [data.headline, data.summary].filter(Boolean);
    for (const [key, title] of SECTIONS) {
      const items = Array.isArray(data[key]) ? data[key] : [];
      if (!items.length) continue;
      parts.push('', title.toUpperCase());
      for (const item of items) parts.push('• ' + (item && typeof item === 'object' ? item.point + (item.evidence ? ' (' + item.evidence + ')' : '') : String(item)));
    }
    return parts.join('\n');
  }

  function typing() {
    const dots = el('span', 'ai-typing');
    dots.setAttribute('aria-label', 'Writing');
    dots.append(el('i'), el('i'), el('i'));
    return dots;
  }

  function addMessage(log, role, text) {
    const bubble = el('div', 'ai-msg ai-msg-' + role);
    bubble.dir = 'auto';
    if (text === null) bubble.append(typing());
    else bubble.textContent = text;
    log.append(bubble);
    log.scrollTop = log.scrollHeight;
    return bubble;
  }

  /** Send one chat message and stream the answer into a new bubble. Returns the final answer or throws. */
  async function ask(log, url, body) {
    const bubble = addMessage(log, 'assistant', null);
    try {
      const final = await stream(url, body, (text) => {
        bubble.textContent = plain(text);
        log.scrollTop = log.scrollHeight;
      });
      bubble.textContent = final.answer;
      bubble.after(copyButton(final.answer));
      return final.answer;
    } catch (error) {
      bubble.remove();
      throw error;
    }
  }

  function chatForm(placeholder, label) {
    const form = el('form', 'ai-form');
    const input = el('textarea');
    input.rows = 2;
    input.maxLength = 1000;
    input.placeholder = placeholder;
    input.setAttribute('aria-label', label);
    input.dir = 'auto';
    const send = el('button', 'ai-send', 'Ask');
    send.type = 'submit';
    form.append(input, send);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); form.requestSubmit(); }
    });
    return {form, input};
  }

  // ------------------------------------------------------------ report panel

  function build(tool, receipt, reportId) {
    const state = {tool, receipt: receipt || null, reportId: reportId || null, contextId: null};
    const box = el('section', 'ai-panel');
    box.setAttribute('aria-label', 'AI assistant');
    const head = el('div', 'ai-head');
    const title = el('div');
    title.append(el('span', 'ai-kicker', 'AI ASSISTANT'), el('h2', '', 'Understand this report'),
      el('p', 'ai-sub', 'A plain-language explanation of the evidence above. Ask follow-up questions in any language. Each new answer uses 1 of your 10 daily AI requests; reopening a saved explanation is free.'));
    head.append(el('span', 'ai-orb', '✦'), title);
    const buttons = el('div', 'ai-actions');
    const status = el('p', 'ai-status');
    status.setAttribute('role', 'status');
    const output = el('div', 'ai-output');
    output.hidden = true;

    const chat = el('div', 'ai-chat');
    chat.hidden = true;
    const log = el('div', 'ai-log');
    log.setAttribute('aria-live', 'polite');
    const {form, input} = chatForm('Ask about this report…', 'Ask the AI assistant about this report');
    chat.append(el('h4', 'ai-chat-title', 'Ask a follow-up question'), log, form);

    const note = el('p', 'ai-note', 'AI can make mistakes. The verdict comes from MyScanner\'s checks, not from the AI. Do not type passwords or personal information. This assistant is restricted to this report.');
    async function ensureContext() {
      if (state.contextId) return state.contextId;
      // Only server-made evidence: a saved report's number, or the receipt the server signed.
      const payload = {tool: state.tool};
      if (state.reportId) payload.report_id = state.reportId;
      else payload.receipt = state.receipt;
      const created = await stream('/api/ai/contexts', payload, () => {});
      state.contextId = created.id;
      return state.contextId;
    }

    function busy(on, message) {
      for (const button of box.querySelectorAll('button')) button.disabled = on;
      status.textContent = message || '';
      box.classList.toggle('ai-busy', on);
    }

    const explain = el('button', 'ai-explain', 'Explain this report');
    explain.type = 'button';
    explain.addEventListener('click', async () => {
      busy(true, 'Reading the evidence…');
      try {
        const id = await ensureContext();
        output.replaceChildren(typing());
        output.hidden = false;
        const final = await stream(`/api/ai/contexts/${encodeURIComponent(id)}/explain`, {language: document.documentElement.lang === 'tr' ? 'tr' : 'en'}, (text) => {
          status.textContent = '';
          renderExplanation(output, parseExplanation(text));
        });
        renderExplanation(output, final.explanation);
        output.append(copyButton(explanationText(final.explanation)));
        chat.hidden = false;
        busy(false, final.cached ? 'Saved explanation, not counted again.' : '');
      } catch (error) {
        if (!output.querySelector('.ai-headline')) output.hidden = true;
        busy(false, error.message);
      }
    });
    const askButton = el('button', 'ai-explain ai-ask-only', 'Ask a question');
    askButton.type = 'button';
    askButton.addEventListener('click', () => { chat.hidden = false; input.focus(); });
    buttons.append(explain, askButton);

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const message = input.value.trim();
      if (!message || box.classList.contains('ai-busy')) return;
      addMessage(log, 'user', message);
      input.value = '';
      busy(true, '');
      try {
        const id = await ensureContext();
        await ask(log, `/api/ai/contexts/${encodeURIComponent(id)}/chat`, {message});
        busy(false, '');
      } catch (error) {
        // The panel's status line sits above the explanation, out of view while
        // chatting, so failures looked like silence. Say it where the user is looking.
        addMessage(log, 'error', error.message);
        input.value = message;
        busy(false, '');
      }
    });

    box.append(head, buttons, status, output, chat, note);
    return box;
  }

  function receiptIn(evidence) {
    if (!evidence || typeof evidence !== 'object') return null;
    if (typeof evidence.ai_receipt === 'string') return evidence.ai_receipt;
    for (const value of Object.values(evidence)) {
      if (value && typeof value === 'object' && typeof value.ai_receipt === 'string') return value.ai_receipt;
    }
    return null;
  }

  /** Show the assistant for a finished report. Replaces any earlier panel on the page. */
  function attach(options) {
    // Report AI only for evidence the server vouches for: a saved report (reportId) or the
    // signed receipt that comes with every tool result (ai_receipt, here or one level down).
    if (root.MYSCANNER_AI !== true || !options || !options.mount) return null;
    const receipt = options.receipt || receiptIn(options.evidence);
    if (!options.reportId && !receipt) return null;
    const mount = typeof options.mount === 'string' ? document.querySelector(options.mount) : options.mount;
    if (!mount) return null;
    if (panel) panel.remove();
    panel = build(options.tool, receipt, options.reportId);
    if (options.after) mount.insertAdjacentElement('afterend', panel);
    else mount.append(panel);
    return panel;
  }

  // ------------------------------------------------------------ site-wide assistant

  const HISTORY_KEY = 'myscanner-ai-general';
  const GREETED_KEY = 'myscanner-ai-greeted';
  const SUGGESTIONS = [
    'I got a message asking me to verify my bank account. Is it a scam?',
    'How do I secure my email account?',
    'I clicked a suspicious link. What should I do now?',
    'Which MyScanner tool should I use for a QR code?',
  ];

  function stored(key, fallback) {
    try { const value = JSON.parse(root.sessionStorage.getItem(key)); return value === null ? fallback : value; } catch (e) { return fallback; }
  }
  function store(key, value) {
    try { root.sessionStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* storage blocked: keep it in memory only */ }
  }

  function widget() {
    const signedIn = typeof root.MYSCANNER_AI_USER === 'string' && root.MYSCANNER_AI_USER !== '';
    let history = signedIn ? stored(HISTORY_KEY, []) : [];
    if (!Array.isArray(history)) history = [];

    const fab = el('button', 'ai-fab');
    fab.type = 'button';
    fab.setAttribute('aria-haspopup', 'dialog');
    fab.setAttribute('aria-expanded', 'false');
    fab.append(el('span', 'ai-fab-orb', '✦'), el('span', 'ai-fab-label', 'Ask AI'));

    const dock = el('section', 'ai-dock');
    dock.hidden = true;
    dock.setAttribute('role', 'dialog');
    dock.setAttribute('aria-label', 'MyScanner AI assistant');
    const head = el('header', 'ai-dock-head');
    const titles = el('div');
    titles.append(el('strong', '', 'MyScanner AI'), el('small', '', 'Your security assistant'));
    const reset = el('button', 'ai-dock-icon', '↺');
    reset.type = 'button';
    reset.title = 'New conversation';
    reset.setAttribute('aria-label', 'Start a new conversation');
    const close = el('button', 'ai-dock-icon', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close the AI assistant');
    head.append(el('span', 'ai-orb ai-dock-orb', '✦'), titles, reset, close);

    const body = el('div', 'ai-dock-body');
    const log = el('div', 'ai-log ai-dock-log');
    log.setAttribute('aria-live', 'polite');
    const status = el('p', 'ai-status');
    status.setAttribute('role', 'status');
    const {form, input} = chatForm('Ask anything about online safety…', 'Ask the AI assistant');
    const foot = el('p', 'ai-note', 'AI can make mistakes and cannot scan anything by itself. It can explain MyScanner and online safety, but it cannot access secrets or administer the platform. Never share passwords or personal data. Each answer uses 1 of your 10 daily AI requests.');

    function intro() {
      const box = el('div', 'ai-dock-intro');
      box.append(el('p', 'ai-dock-hello', signedIn ? `Hi ${root.MYSCANNER_AI_USER}, how can I help you stay safe today?` : 'Ask MyScanner\'s AI about links, messages, scams and account security.'));
      if (!signedIn) {
        const actions = el('div', 'ai-dock-auth');
        const login = el('a', 'ai-send', 'Sign in to chat');
        login.href = root.MYSCANNER_AI_LOGIN || '/login';
        const register = el('a', 'ai-explain ai-ask-only', 'Create a free account');
        register.href = root.MYSCANNER_AI_REGISTER || '/register';
        actions.append(login, register);
        box.append(actions);
        return box;
      }
      const chips = el('div', 'ai-chips');
      for (const text of SUGGESTIONS) {
        const chip = el('button', 'ai-chip', text);
        chip.type = 'button';
        chip.addEventListener('click', () => { input.value = text; form.requestSubmit(); });
        chips.append(chip);
      }
      box.append(chips);
      return box;
    }

    function draw() {
      log.replaceChildren();
      if (!history.length) log.append(intro());
      for (const item of history) {
        const bubble = addMessage(log, item.role, item.text);
        if (item.role === 'assistant') bubble.after(copyButton(item.text));
      }
    }

    function busy(on, message) {
      form.querySelector('button').disabled = on;
      reset.disabled = on;
      status.textContent = message || '';
      dock.classList.toggle('ai-busy', on);
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const message = input.value.trim();
      if (!message || dock.classList.contains('ai-busy')) return;
      if (!history.length) log.replaceChildren();
      addMessage(log, 'user', message);
      input.value = '';
      busy(true, '');
      try {
        const answer = await ask(log, '/api/ai/assistant', {message, history: history.slice(-20)});
        history = history.concat({role: 'user', text: message}, {role: 'assistant', text: answer}).slice(-30);
        store(HISTORY_KEY, history);
        busy(false, '');
      } catch (error) {
        log.lastElementChild && log.lastElementChild.classList.contains('ai-msg-user') && log.lastElementChild.remove();
        if (!history.length) draw();
        input.value = message;
        busy(false, error.message);
      }
    });

    function open() {
      hint.remove();
      dock.hidden = false;
      fab.setAttribute('aria-expanded', 'true');
      fab.classList.add('ai-fab-open');
      draw();
      if (signedIn) input.focus(); else close.focus();
    }
    function shut() {
      dock.hidden = true;
      fab.setAttribute('aria-expanded', 'false');
      fab.classList.remove('ai-fab-open');
      fab.focus();
    }
    fab.addEventListener('click', () => (dock.hidden ? open() : shut()));
    close.addEventListener('click', shut);
    reset.addEventListener('click', () => { history = []; store(HISTORY_KEY, history); status.textContent = ''; draw(); input.focus(); });
    dock.addEventListener('keydown', (event) => { if (event.key === 'Escape') shut(); });

    if (signedIn) body.append(log, status, form, foot); else body.append(log, foot);
    dock.append(head, body);

    const hint = el('div', 'ai-fab-hint');
    hint.setAttribute('role', 'status');
    if (signedIn && !stored(GREETED_KEY, false)) {
      store(GREETED_KEY, true);
      hint.append(el('strong', '', `Hi ${root.MYSCANNER_AI_USER} 👋`), el('span', '', 'Got a strange link, message or email? Ask me.'));
      hint.addEventListener('click', open);
      setTimeout(() => hint.classList.add('ai-fab-hint-in'), 1200);
      setTimeout(() => hint.remove(), 12000);
    }

    const wrap = el('div', 'ai-widget');
    wrap.append(dock, hint, fab);
    document.body.append(wrap);
  }

  if (typeof document !== 'undefined' && root.MYSCANNER_AI_WIDGET === true) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', widget);
    else widget();
  }

  root.AIAssistant = {attach, renderExplanation, parseExplanation, plain};
})(typeof window !== 'undefined' ? window : globalThis);
