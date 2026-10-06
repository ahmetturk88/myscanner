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
    text(value, fallback = '—') {
        return typeof value === 'string' || typeof value === 'number' && Number.isFinite(value) ? String(value) : fallback;
    },
    number(value, minimum, maximum, fallback = 0) {
        if (!['number', 'string'].includes(typeof value) || typeof value === 'string' && !value.trim()) return fallback;
        const number = Number(value);
        return Number.isFinite(number) ? Math.max(minimum, Math.min(maximum, number)) : fallback;
    },
    list(value) {
        return Array.isArray(value) ? value : [];
    },
    countryFlag(value) {
        return typeof value === 'string' && value.length === 2 && /^[a-z]{2}$/i.test(value) ? 'https://flagcdn.com/24x18/' + value.toLowerCase() + '.png' : '';
    },
    mapURL(latitude, longitude) {
        function coordinate(value, bound) {
            if (!['number', 'string'].includes(typeof value) || typeof value === 'string' && !value.trim()) return null;
            const number = Number(value);
            return Number.isFinite(number) && Math.abs(number) <= bound ? number : null;
        }
        const lat = coordinate(latitude, 90), lon = coordinate(longitude, 180);
        if (lat === null || lon === null) return '';
        const url = new URL('https://www.openstreetmap.org/export/embed.html');
        url.searchParams.set('bbox', [Math.max(-180, lon-.05), Math.max(-90, lat-.05), Math.min(180, lon+.05), Math.min(90, lat+.05)].join(','));
        url.searchParams.set('layer', 'mapnik');
        url.searchParams.set('marker', lat + ',' + lon);
        return url.href;
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
