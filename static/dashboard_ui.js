// History data is text. Verdict classes come only from this fixed vocabulary.
window.DashboardUI = Object.freeze({
  normalizeScans(value) {
    const text = value => typeof value === 'string' ? value :
      (typeof value === 'number' && Number.isFinite(value) ? String(value) : '');
    const verdicts = new Set(['harmless', 'malicious', 'suspicious', 'unknown']);
    return Array.isArray(value) ? value.filter(scan => scan && typeof scan === 'object' && !Array.isArray(scan)).map(scan => ({
      id: text(scan.id), url: text(scan.url), summary: text(scan.summary), date: text(scan.date),
      verdict: verdicts.has(scan.verdict) ? scan.verdict : 'unknown'
    })) : [];
  },
  renderRows(tbody, scans) {
    const document = tbody.ownerDocument;
    const fragment = document.createDocumentFragment();
    for (const scan of this.normalizeScans(scans)) {
      const row = document.createElement('tr');
      const addCell = (value, className) => {
        const cell = document.createElement('td');
        cell.className = className;
        cell.textContent = value;
        row.appendChild(cell);
        return cell;
      };
      addCell('#' + (scan.id || '?'), 'history-id');
      addCell(scan.url || 'N/A', 'history-url');
      const verdict = addCell('', 'history-verdict');
      const badge = document.createElement('span');
      badge.className = 'verdict-badge v-' + scan.verdict;
      badge.textContent = scan.verdict.toUpperCase();
      verdict.appendChild(badge);
      addCell(scan.summary || '–', 'history-summary');
      addCell(scan.date || '–', 'history-date');
      fragment.appendChild(row);
    }
    tbody.replaceChildren(fragment);
  }
});
