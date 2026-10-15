"""Sign in with Google or GitHub (OAuth 2.0 authorization-code flow).

A provider is enabled only when both its client id and secret are
configured. Accounts are matched by an email address the provider says is
verified; an existing account that never verified its email is taken over
safely by replacing its unknown password, so whoever registered that address
without owning it loses access.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
from urllib.parse import urlencode

import requests

TIMEOUT = (5, 15)
PROVIDERS = {
    'google': {
        'label': 'Google',
        'authorize': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token': 'https://oauth2.googleapis.com/token',
        'userinfo': 'https://openidconnect.googleapis.com/v1/userinfo',
        'scope': 'openid email profile',
        'pkce': True,
    },
    'github': {
        'label': 'GitHub',
        'authorize': 'https://github.com/login/oauth/authorize',
        'token': 'https://github.com/login/oauth/access_token',
        'userinfo': 'https://api.github.com/user',
        'emails': 'https://api.github.com/user/emails',
        'scope': 'read:user user:email',
        'pkce': True,
    },
}


class OAuthError(Exception):
    """A user-safe failure; the message is shown as is."""


def _setting(name):
    value = os.environ.get(name, '').strip()
    if value:
        return value
    path = os.environ.get(name + '_FILE', '').strip()
    if path:
        try:
            with open(path, encoding='utf-8') as handle:
                return handle.read().strip()
        except OSError:
            return ''
    return ''


def credentials(provider):
    prefix = provider.upper()
    client_id, client_secret = _setting(prefix + '_CLIENT_ID'), _setting(prefix + '_CLIENT_SECRET')
    return (client_id, client_secret) if client_id and client_secret else None


def enabled_providers():
    return [name for name in PROVIDERS if credentials(name)]


def start(provider, redirect_uri, session):
    """Return the provider URL and remember state (and a PKCE verifier) in the session."""
    if provider not in PROVIDERS or not credentials(provider):
        raise OAuthError('This sign-in option is not available.')
    config, (client_id, _) = PROVIDERS[provider], credentials(provider)
    state = secrets.token_urlsafe(32)
    params = {'client_id': client_id, 'redirect_uri': redirect_uri, 'response_type': 'code',
              'scope': config['scope'], 'state': state}
    pending = {'provider': provider, 'state': state}
    if config['pkce']:
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        params.update(code_challenge=challenge, code_challenge_method='S256')
        pending['verifier'] = verifier
    # Both providers otherwise reuse the account already signed in at the provider,
    # so after signing out here the next click would silently pick it again.
    params['prompt'] = 'select_account'
    session['oauth_pending'] = pending
    return config['authorize'] + '?' + urlencode(params)


def finish(provider, args, redirect_uri, session, http=requests):
    """Validate the callback and return (email, display_name)."""
    pending = session.pop('oauth_pending', None)
    if not isinstance(pending, dict) or pending.get('provider') != provider:
        raise OAuthError('Your sign-in session expired. Please try again.')
    if args.get('error'):
        raise OAuthError('Sign-in was cancelled.')
    state, code = args.get('state', ''), args.get('code', '')
    if not code or not hmac.compare_digest(str(pending.get('state', '')), str(state)):
        raise OAuthError('Your sign-in session expired. Please try again.')
    creds = credentials(provider)
    if not creds:
        raise OAuthError('This sign-in option is not available.')
    config, (client_id, client_secret) = PROVIDERS[provider], creds
    data = {'client_id': client_id, 'client_secret': client_secret, 'code': code,
            'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
    if pending.get('verifier'):
        data['code_verifier'] = pending['verifier']
    try:
        token = http.post(config['token'], data=data, headers={'Accept': 'application/json'}, timeout=TIMEOUT).json()
        access = token.get('access_token') if isinstance(token, dict) else None
        if not access:
            raise OAuthError('The provider did not complete sign-in. Please try again.')
        headers = {'Authorization': 'Bearer ' + access, 'Accept': 'application/json'}
        profile = http.get(config['userinfo'], headers=headers, timeout=TIMEOUT).json()
        if provider == 'google':
            email = profile.get('email') if profile.get('email_verified') is True else None
            name = profile.get('name') or profile.get('given_name')
        else:
            emails = http.get(config['emails'], headers=headers, timeout=TIMEOUT).json()
            verified = [e for e in emails if isinstance(e, dict) and e.get('verified') is True and e.get('email')] if isinstance(emails, list) else []
            primary = [e for e in verified if e.get('primary') is True]
            email = (primary or verified or [{}])[0].get('email')
            name = profile.get('name') or profile.get('login')
    except OAuthError:
        raise
    except (requests.RequestException, ValueError, AttributeError, TypeError) as error:
        raise OAuthError('The provider could not be reached. Please try again.') from error
    if not isinstance(email, str) or '@' not in email or len(email) > 120:
        raise OAuthError('Your account has no verified email address with this provider.')
    return email.strip().lower(), (name if isinstance(name, str) else '')


def unique_username(name, email, taken):
    """A readable, unique username; `taken(candidate)` reports collisions."""
    base = re.sub(r'[^A-Za-z0-9_.-]+', '', (name or '').replace(' ', '_'))[:30] or re.sub(r'[^A-Za-z0-9_.-]+', '', email.split('@')[0])[:30] or 'user'
    candidate = base
    for _ in range(20):
        if not taken(candidate):
            return candidate
        candidate = f'{base[:24]}_{secrets.randbelow(10**5):05d}'
    return 'user_' + secrets.token_hex(6)
