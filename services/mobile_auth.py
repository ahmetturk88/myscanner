"""Bearer tokens for the mobile app.

A token is a random secret shown to the app once; the database keeps only its
SHA-256 hash. Requests that carry `Authorization: Bearer <token>` are signed in
by that token alone: the session cookie is ignored for them and CSRF checks do
not apply, because browsers never attach this header on their own.
"""
import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from itsdangerous import BadData, URLSafeTimedSerializer

from extensions import db
from models import ApiToken, User

PREFIX = 'msk_'
TOKEN_DAYS = 90
TOKENS_PER_USER = 10
TOUCH_EVERY = timedelta(hours=1)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def bearer(header):
    """The token in an Authorization header, '' when the header is not a bearer token."""
    scheme, _, value = (header or '').partition(' ')
    return value.strip() if scheme.lower() == 'bearer' else ''


def issue(user, device=''):
    """Create a token for the user; return (raw token, expiry). Oldest tokens beyond the cap are removed."""
    now = _now()
    ApiToken.query.filter(ApiToken.expires_at <= now).delete(synchronize_session=False)
    keep = TOKENS_PER_USER - 1
    stale = [row.id for row in ApiToken.query.filter_by(user_id=user.id).order_by(ApiToken.created_at.desc())
             .offset(keep).with_entities(ApiToken.id).all()]
    if stale:
        ApiToken.query.filter(ApiToken.id.in_(stale)).delete(synchronize_session=False)
    raw = PREFIX + secrets.token_urlsafe(32)
    expires = now + timedelta(days=TOKEN_DAYS)
    db.session.add(ApiToken(user_id=user.id, token_hash=_hash(raw), device=str(device or '')[:80],
                            created_at=now, last_used_at=now, expires_at=expires))
    db.session.commit()
    return raw, expires


def authenticate(raw):
    """The user a valid, unexpired token belongs to, or None."""
    if not raw.startswith(PREFIX) or len(raw) > 100:
        return None
    row = ApiToken.query.filter_by(token_hash=_hash(raw)).first()
    now = _now()
    if row is None or row.expires_at <= now:
        return None
    user = db.session.get(User, row.user_id)
    if user is None or not user.is_verified:
        return None
    if now - row.last_used_at >= TOUCH_EVERY:
        row.last_used_at = now
        db.session.commit()
    return user


def revoke(raw):
    ApiToken.query.filter_by(token_hash=_hash(raw)).delete(synchronize_session=False)
    db.session.commit()


def revoke_all(user_id):
    """Sign every device out, e.g. after a password reset."""
    ApiToken.query.filter_by(user_id=user_id).delete(synchronize_session=False)


# ---------------------------------------------------------------- Google / GitHub sign-in for the app
#
# The app opens the website's normal provider sign-in in the phone's browser.
# The callback hands back a short-lived code instead of a website session; the
# app trades it for a token, proving with a PKCE verifier that it is the app
# that started the sign-in. The code alone is useless to anyone who sees it.

APP_REDIRECT = re.compile(r'^(myscanner://auth|exp://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/--/auth)$')
CHALLENGE = re.compile(r'^[A-Za-z0-9_-]{43,128}$')
CODE_SECONDS = 120


def _codes():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='mobile-oauth-code')


def oauth_code(user_id, challenge):
    return _codes().dumps({'u': user_id, 'c': challenge, 'n': secrets.token_urlsafe(12)})


def redeem_code(code, verifier):
    """The user a sign-in code belongs to, if the verifier matches and the code is fresh and unused."""
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    if not isinstance(code, str) or not isinstance(verifier, str) or not 43 <= len(verifier) <= 128 or len(code) > 400:
        return None
    try:
        data = _codes().loads(code, max_age=CODE_SECONDS)
    except BadData:
        return None
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    if not isinstance(data, dict) or not hmac.compare_digest(str(data.get('c', '')), expected):
        return None
    try:
        consume_limit('mobile-oauth-code', str(data.get('n')), 1, CODE_SECONDS * 2)  # each code works once
    except AuthRateLimited:
        return None
    user = db.session.get(User, data.get('u'))
    return user if user is not None and user.is_verified else None


def app_return(redirect_uri, **params):
    """The app's sign-in return address with the given query parameters."""
    from urllib.parse import urlencode
    return f'{redirect_uri}?{urlencode(params)}'
