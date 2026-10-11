"""Baseline browser hardening headers for every MyScanner response.

A Content-Security-Policy is deliberately not set here yet: templates still
contain inline scripts and handlers, so a useful CSP needs those moved first.
"""

BASELINE = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    # The QR scanner may read the camera from our own origin only.
    'Permissions-Policy': 'camera=(self), microphone=(), geolocation=(), payment=(), usb=()',
}
HSTS = 'max-age=31536000'


def apply_security_headers(response, production, secure):
    for name, value in BASELINE.items():
        response.headers.setdefault(name, value)
    # HSTS only over HTTPS in production; subdomains/preload need an owner decision.
    if production and secure:
        response.headers.setdefault('Strict-Transport-Security', HSTS)
    return response


def init_security_headers(app):
    @app.after_request
    def _security_headers(response):
        from flask import request
        return apply_security_headers(response, app.config.get('SESSION_COOKIE_SECURE') is True,
                                      request.is_secure)
    return app
