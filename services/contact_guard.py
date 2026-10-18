"""Spam guard for the public contact form.

Bots that post the form get a normal-looking success reply and nothing is sent, so
they have no signal to adapt to. Three checks, none of which needs a third party:
- a hidden "website" field people never see; bots fill every field;
- a signed render time: posting under MIN_SECONDS after the page loaded is a script;
- per-address and per-sender limits in the shared rate-limit table (see app.contact).
"""
import time
from itsdangerous import BadSignature, URLSafeSerializer

TOPICS = ('General Inquiry', 'Technical Support', 'Security Report', 'Partnership', 'Feedback', 'Bug Report')
HONEYPOT = 'website'
MIN_SECONDS = 3
MAX_AGE = 6 * 3600
LIMITS = {'name': 120, 'email': 254, 'company': 120, 'phone': 40, 'message': 4000}


def _serializer(secret):
    return URLSafeSerializer(secret, salt='contact-form')


def form_token(secret, now=None):
    return _serializer(secret).dumps(int(time.time() if now is None else now))


def check_submission(form, secret, now=None):
    """'ok', 'bot' (drop silently), 'expired' (ask to reload) or 'invalid' (show an error)."""
    now = time.time() if now is None else now
    if form.get(HONEYPOT, '').strip():
        return 'bot'
    try:
        issued = _serializer(secret).loads(form.get('form_token', ''))
    except BadSignature:
        return 'bot'  # never rendered by us: a direct POST
    if not isinstance(issued, int) or now - issued < MIN_SECONDS:
        return 'bot'
    if now - issued > MAX_AGE:
        return 'expired'
    if form.get('subject', '') not in TOPICS:
        return 'invalid'
    if any(len(form.get(field, '')) > limit for field, limit in LIMITS.items()):
        return 'invalid'
    return 'ok'


def one_line(value, limit):
    """Collapse whitespace (no line breaks in email headers) and cap the length."""
    return ' '.join(value.split())[:limit]
