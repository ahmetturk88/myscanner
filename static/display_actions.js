// Provider/account values are data, never event-handler source or arbitrary links.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-web-url]').forEach(link => {
    const url = window.ScanUI.webURL(link.dataset.webUrl);
    if (url) {
      link.href = url;
      link.rel = 'noopener noreferrer';
    } else {
      link.removeAttribute('href');
      link.setAttribute('aria-disabled', 'true');
      link.title = 'This saved value is not a valid HTTP or HTTPS link.';
    }
  });
  document.querySelectorAll('[data-delete-kind]').forEach(button => {
    button.addEventListener('click', () => {
      const {deleteKind: kind, deleteId: id, deleteLabel: label} = button.dataset;
      if (['user', 'scan'].includes(kind) && typeof id === 'string' && id === id.trim() && /^[1-9][0-9]*$/.test(id) && typeof window.confirmDelete === 'function') {
        window.confirmDelete(kind, id, label);
      }
    });
  });
  document.querySelectorAll('[data-check-scan]').forEach(button => {
    button.addEventListener('click', () => {
      const uuid = button.dataset.checkScan;
      if (typeof uuid === 'string' && uuid.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid) && typeof window.checkStatus === 'function') {
        window.checkStatus(uuid);
      }
    });
  });
});
