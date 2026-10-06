(() => {
  'use strict';
  const button = document.getElementById('proxy-run');
  const status = document.getElementById('proxy-status');
  const details = document.getElementById('proxy-details');
  const testIP = '198.51.100.77';
  async function read(headers = {}) {
    const response = await fetch('/admin/proxy-info', {headers, cache: 'no-store', credentials: 'same-origin', redirect: 'error'});
    if (!response.ok) throw new Error('The check could not read the admin diagnostic endpoint.');
    return response.json();
  }
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.dataset.state = '';
    status.textContent = 'Checking the normal request and a request with test headers…';
    try {
      const normal = await read();
      const tested = await read({'CF-Connecting-IP': testIP, 'CF-Connecting-IPv6': '2001:db8::77', 'X-Forwarded-For': testIP});
      const preserved = Boolean(normal.edge_candidate) &&
        normal.edge_candidate === tested.edge_candidate &&
        tested.cf_connecting_ip !== testIP;
      details.textContent = JSON.stringify({normal, tested, edge_header_preserved: preserved}, null, 2);
      status.dataset.state = preserved ? 'pass' : 'review';
      status.textContent = preserved
        ? 'The edge address stayed consistent despite the test headers. Review these results before enabling the Render setting.'
        : 'The edge address could not be confirmed. Leave edge identity handling disabled and review the request details.';
    } catch (error) {
      status.dataset.state = 'review';
      status.textContent = 'The check could not complete. Confirm you are signed in as an administrator, then try again.';
      details.textContent = 'No complete result was collected.';
    } finally {
      button.disabled = false;
    }
  });
})();
