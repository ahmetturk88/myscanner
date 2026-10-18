"""Optional error alerts through Sentry. Off unless SENTRY_DSN_FILE (or SENTRY_DSN) is set.

Reports the exception type, message and stack trace only: no local variables, request
bodies, cookies, headers, query strings, user details or log breadcrumbs, so scanned
targets and account data stay on our servers.
"""
import os

_started = False


def sentry_dsn():
    path = os.environ.get('SENTRY_DSN_FILE', '')
    if path:
        try:
            with open(path, encoding='utf-8') as secret:
                value = secret.read(4096).strip()
        except (OSError, UnicodeError):
            return None
    else:
        value = os.environ.get('SENTRY_DSN', '').strip()
    return value if value.startswith('https://') and not any(c.isspace() for c in value) else None


def scrub(event, hint=None):
    """Keep only the method and the path of a request; drop everything that identifies people or targets."""
    request = event.get('request')
    if isinstance(request, dict):
        url = request.get('url')
        event['request'] = {key: value for key, value in (('method', request.get('method')),
                            ('url', url.split('?', 1)[0] if isinstance(url, str) else None)) if value}
    for key in ('user', 'breadcrumbs', 'extra'):
        event.pop(key, None)
    return event


def init_error_reporting(component):
    """Start Sentry once per process; returns True when reporting is active."""
    global _started
    if _started:
        return True
    dsn = sentry_dsn()
    if not dsn:
        return False
    import sentry_sdk
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.flask import FlaskIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration
    sentry_sdk.init(dsn=dsn, send_default_pii=False, include_local_variables=False, max_request_body_size='never',
                    traces_sample_rate=0, environment=os.environ.get('APP_ENV', 'production'), server_name=component,
                    integrations=[FlaskIntegration(), CeleryIntegration(), LoggingIntegration(level=None, event_level=None)],
                    before_send=scrub, before_breadcrumb=lambda crumb, hint: None)
    _started = True
    return True


def report_exception(error, sensitive=False):
    """Report an error the code caught and turned into a friendly message.

    sensitive=True sends only the error type and where it happened, never its message
    (for inputs such as passwords that could appear in one).
    """
    if not _started:
        return
    import sentry_sdk
    if sensitive:
        frame = error.__traceback__
        while frame is not None and frame.tb_next is not None:
            frame = frame.tb_next
        where = f'{frame.tb_frame.f_code.co_filename.rsplit("/", 1)[-1]}:{frame.tb_lineno}' if frame else 'unknown'
        sentry_sdk.capture_message(f'{type(error).__name__} at {where}', level='error')
    else:
        sentry_sdk.capture_exception(error)
