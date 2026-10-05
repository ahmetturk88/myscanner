// Send the page token only to this application's state-changing endpoints.
(() => {
    const originalFetch = window.fetch.bind(window);
    const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
    window.fetch = function(input, init) {
        const request = new Request(input, init);
        const target = new URL(request.url);
        if (target.origin === window.location.origin && !safeMethods.has(request.method.toUpperCase())) {
            const token = document.querySelector('meta[name="csrf-token"]')?.content;
            if (token) {
                const headers = new Headers(request.headers);
                headers.set('X-CSRFToken', token);
                return originalFetch(new Request(request, { headers }));
            }
        }
        return originalFetch(request);
    };
})();
