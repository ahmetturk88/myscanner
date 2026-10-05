// Helpers for displaying scanner/provider data as text, never executable markup.
window.ScanUI = Object.freeze({
    escape(value) {
        return String(value ?? '').replace(/[&<>"']/g, character => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[character]));
    },
    score(value) {
        const number = Number(value);
        return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
    },
    webURL(value) {
        if (typeof value !== 'string' || !value || /[\s\x00-\x1f\x7f]/.test(value)) return '';
        try {
            const url = new URL(value);
            return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : '';
        } catch (_) {
            return '';
        }
    }
});
