/* AI explanation and follow-up chat for a finished report. Every answer is inserted as text, never HTML. */
(function (root) {
  'use strict';
  const SECTIONS = [
    ['reasons', 'Why this result'],
    ['next_steps', 'What to do now'],
    ['not_checked', 'What was not confirmed'],
    ['technical_notes', 'Technical notes'],
  ];
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

  async function call(method, url, body) {
    const response = await fetch(url, {
      method, credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': token()},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const fallback = response.status === 429
        ? "Today's AI allowance is used up. It resets at 00:00 UTC."
        : 'The AI assistant is unavailable right now. Please try again in a minute.';
      const fromServer = typeof data.error === 'string' && (response.status < 500 || response.status === 503);
      throw new Error(fromServer ? data.error : fallback);
    }
    return data;
  }

  function renderExplanation(target, data) {
    target.replaceChildren();
    target.append(el('h3', 'ai-headline', data.headline), el('p', 'ai-summary', data.summary));
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

  function addMessage(log, role, text) {
    const bubble = el('div', 'ai-msg ai-msg-' + role, text);
    bubble.dir = 'auto';
    log.append(bubble);
    log.scrollTop = log.scrollHeight;
    return bubble;
  }

  function build(tool, evidence) {
    const state = {tool, evidence, contextId: null};
    const box = el('section', 'ai-panel');
    box.setAttribute('aria-label', 'AI assistant');
    const head = el('div', 'ai-head');
    const title = el('div');
    title.append(el('span', 'ai-kicker', 'AI ASSISTANT'), el('h2', '', 'Understand this report'),
      el('p', 'ai-sub', 'A plain-language explanation of the evidence above. Each new answer uses 1 of your 10 daily AI requests; reopening a saved explanation is free.'));
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
    const form = el('form', 'ai-form');
    const input = el('textarea');
    input.rows = 2;
    input.maxLength = 1000;
    input.placeholder = 'Ask about this report…';
    input.setAttribute('aria-label', 'Ask the AI assistant about this report');
    const send = el('button', 'ai-send', 'Ask');
    send.type = 'submit';
    form.append(input, send);
    chat.append(el('h4', 'ai-chat-title', 'Ask a follow-up question'), log, form);

    const note = el('p', 'ai-note', 'AI can make mistakes. The verdict comes from MyScanner\'s checks, not from the AI. Do not type passwords or personal information. Report evidence is sent to our AI provider to generate answers.');

    async function ensureContext() {
      if (state.contextId) return state.contextId;
      const created = await call('POST', '/api/ai/contexts', {tool: state.tool, evidence: state.evidence});
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
        const data = await call('POST', `/api/ai/contexts/${encodeURIComponent(id)}/explain`, {language: 'en'});
        renderExplanation(output, data.explanation);
        output.hidden = false;
        chat.hidden = false;
        busy(false, data.cached ? 'Saved explanation, not counted again.' : '');
      } catch (error) {
        busy(false, error.message);
      }
    });
    buttons.append(explain);
    const ask = el('button', 'ai-explain ai-ask-only', 'Ask a question');
    ask.type = 'button';
    ask.addEventListener('click', () => { chat.hidden = false; input.focus(); });
    buttons.append(ask);

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const message = input.value.trim();
      if (!message) return;
      addMessage(log, 'user', message);
      input.value = '';
      const pending = addMessage(log, 'assistant', '…');
      busy(true, '');
      try {
        const id = await ensureContext();
        const data = await call('POST', `/api/ai/contexts/${encodeURIComponent(id)}/chat`, {message});
        pending.textContent = data.answer;
        busy(false, '');
      } catch (error) {
        pending.remove();
        busy(false, error.message);
      }
    });
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); form.requestSubmit(); }
    });

    box.append(head, buttons, status, output, chat, note);
    return box;
  }

  /** Show the assistant for a finished report. Replaces any earlier panel on the page. */
  function attach(options) {
    if (!root.MYSCANNER_AI || !options || !options.mount || !options.evidence) return null;
    const mount = typeof options.mount === 'string' ? document.querySelector(options.mount) : options.mount;
    if (!mount) return null;
    if (panel) panel.remove();
    panel = build(options.tool, options.evidence);
    if (options.after) mount.insertAdjacentElement('afterend', panel);
    else mount.append(panel);
    return panel;
  }

  root.AIAssistant = {attach, renderExplanation};
})(typeof window !== 'undefined' ? window : globalThis);
