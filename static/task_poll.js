// Waits for analysis jobs that run in a background worker (HTTP 202 + task_id).
(function (root) {
  'use strict';
  const sleep = (ms, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(Object.assign(new Error('Aborted'), {name: 'AbortError'})); }, {once: true});
  });

  async function wait(taskId, options = {}) {
    const {signal, interval = 2000, timeout = 600000} = options;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const response = await fetch('/api/task-status/' + encodeURIComponent(taskId), {cache: 'no-store', credentials: 'same-origin', signal});
      let data = null;
      try { data = await response.json(); } catch (_) { data = null; }
      if (!response.ok || !data) throw new Error((data && data.error) || 'The analysis status is unavailable. Please retry.');
      if (data.state === 'FAILURE') throw new Error(data.error || 'Analysis failed. Please retry.');
      if (data.state === 'SUCCESS') {
        const payload = data.result;
        if (!payload || typeof payload !== 'object' || !('result' in payload)) throw new Error('The analysis returned no report. Please retry.');
        return payload.result;
      }
      await sleep(interval, signal);
    }
    throw new Error('The analysis is taking longer than expected. Please check again later.');
  }

  // Returns {response, data}; a queued job resolves to its finished report.
  async function resolve(response, options = {}) {
    let data = null;
    try { data = await response.json(); } catch (_) { data = null; }
    if (response.status !== 202) return {response, data};
    if (!data || typeof data.task_id !== 'string') throw new Error('The analysis could not be started.');
    const report = await wait(data.task_id, options);
    return {response: {ok: true, status: 200, redirected: false}, data: report};
  }

  root.MyScannerTasks = {wait, resolve};
  if (typeof module !== 'undefined') module.exports = root.MyScannerTasks;
})(typeof window !== 'undefined' ? window : globalThis);
