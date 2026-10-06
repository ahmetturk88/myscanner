(() => {
  'use strict';
  const button = document.getElementById('proxy-run');
  const status = document.getElementById('proxy-status');
  const details = document.getElementById('proxy-details');
  const testIP = '198.51.100.77';
  async function read(headers = {}) {
    try {
      const response = await fetch('/admin/proxy-info', {
        headers, cache: 'no-store', credentials: 'same-origin', redirect: 'error'
      });
      if (!response.ok) {
        // Inspect the error locally; never display upstream HTML or log it.
        const body = (await response.text()).slice(0, 8192);
        const cloudflare1000 = /<title>[^<]*DNS points to prohibited IP[^<]*Cloudflare[^<]*<\/title>/i.test(body);
        return {outcome: cloudflare1000 ? 'edge_rejected' : 'http_error', http_status: response.status,
          reason: cloudflare1000 ? 'cloudflare_1000' : 'request_rejected'};
      }
      const data = await response.json();
      if (!data || typeof data.client_ip !== 'string' || typeof data.cf_connecting_ip !== 'string' ||
          !(data.edge_candidate === null || typeof data.edge_candidate === 'string')) {
        return {outcome: 'invalid_response'};
      }
      return {outcome: 'received', data};
    } catch (error) {
      return {outcome: 'request_failed'};
    }
  }
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.dataset.state = '';
    status.textContent = 'Checking the normal request, then each test header separately…';
    details.textContent = 'Collecting request details…';
    try {
      const normal = await read();
      if (normal.outcome !== 'received') {
        details.textContent = JSON.stringify({normal}, null, 2);
        status.dataset.state = 'review';
        status.textContent = 'The normal diagnostic request could not complete. Check the request details; no client address was verified.';
        return;
      }
      // Keep each probe independent so one edge rejection does not hide the
      // normal result or prevent the other probe from being inspected.
      const forwardedFor = await read({'X-Forwarded-For': testIP});
      const connectingIP = await read({'CF-Connecting-IP': testIP});
      const preserved = Boolean(normal.data.edge_candidate) &&
        forwardedFor.outcome === 'received' && connectingIP.outcome === 'received' &&
        normal.data.edge_candidate === forwardedFor.data.edge_candidate &&
        normal.data.edge_candidate === connectingIP.data.edge_candidate &&
        connectingIP.data.cf_connecting_ip !== testIP;
      details.textContent = JSON.stringify({normal: normal.data,
        forwarded_for_probe: forwardedFor, connecting_ip_probe: connectingIP,
        edge_header_preserved: preserved}, null, 2);
      status.dataset.state = preserved ? 'pass' : 'review';
      if (forwardedFor.outcome === 'edge_rejected' || connectingIP.outcome === 'edge_rejected') {
        status.textContent = 'Cloudflare rejected a test request (error 1000). The normal request details are available below. This is not an administrator permission error; keep proxy trust unchanged until the results are reviewed.';
      } else if (preserved) {
        status.textContent = 'The edge address stayed consistent in both test requests. Review these samples before changing proxy trust; they do not verify every ingress path.';
      } else {
        status.textContent = 'The comparison could not confirm the edge address. The collected results are available below; keep proxy trust unchanged.';
      }
    } finally {
      button.disabled = false;
    }
  });
})();
