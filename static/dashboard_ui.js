// History data is text. Verdict classes come only from this fixed vocabulary.
window.DashboardUI = Object.freeze({
  normalizeScans(value) {
    const text = value => typeof value === 'string' ? value :
      (typeof value === 'number' && Number.isFinite(value) ? String(value) : '');
    const verdicts = new Set(['harmless', 'malicious', 'suspicious', 'high_risk', 'unknown']);
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
      badge.textContent = scan.verdict.replace('_', ' ').toUpperCase();
      verdict.appendChild(badge);
      addCell(scan.summary || '–', 'history-summary');
      addCell(scan.date || '–', 'history-date');
      fragment.appendChild(row);
    }
    tbody.replaceChildren(fragment);
  },
  // Verdict donut and 7-day activity, drawn with CSS only (no chart library).
  tally(scans) {
    const list = this.normalizeScans(scans);
    const count = verdict => list.filter(scan => scan.verdict === verdict).length;
    const review = count('suspicious') + count('high_risk');
    return {total: list.length, harmless: count('harmless'), malicious: count('malicious'), review,
            unknown: list.length - count('harmless') - count('malicious') - review};
  },
  renderDonut(donut, total, scans) {
    const t = this.tally(scans);
    const parts = [['#fb7185', t.malicious], ['#fbbf24', t.review], ['#4ade80', t.harmless], ['#64748b', t.unknown]];
    let start = 0, stops = [];
    for (const [color, value] of parts) {
      if (!value) continue;
      const end = start + 100 * value / t.total;
      stops.push(color + ' ' + start.toFixed(2) + '% ' + end.toFixed(2) + '%');
      start = end;
    }
    donut.style.background = stops.length ? 'conic-gradient(' + stops.join(',') + ')' : 'conic-gradient(#2a3b52 0 100%)';
    total.textContent = String(t.total);
    return t;
  },
  renderBars(container, scans, today) {
    const document = container.ownerDocument, list = this.normalizeScans(scans);
    const now = today || new Date(), days = [];
    // Scan dates are stored in UTC, so the seven buckets are UTC days.
    for (let i = 6; i >= 0; i--) {
      const key = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i)).toISOString().slice(0, 10);
      days.push({key, label: key.slice(5), count: list.filter(scan => scan.date.startsWith(key)).length});
    }
    const peak = Math.max(1, ...days.map(day => day.count));
    const fragment = document.createDocumentFragment();
    for (const day of days) {
      const bar = document.createElement('div'); bar.className = 'pg-bar';
      const value = document.createElement('b'); value.textContent = String(day.count);
      const track = document.createElement('div'); track.className = 'pg-bar-track';
      const fill = document.createElement('div'); fill.className = 'pg-bar-fill' + (day.count ? '' : ' zero');
      fill.style.height = (day.count ? Math.max(6, 100 * day.count / peak) : 3) + '%';
      track.appendChild(fill);
      const label = document.createElement('small'); label.textContent = day.label;
      bar.appendChild(value); bar.appendChild(track); bar.appendChild(label);
      fragment.appendChild(bar);
    }
    container.replaceChildren(fragment);
    return days;
  }
});
