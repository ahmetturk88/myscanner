"""Google Web Risk Lookup API: is this exact URL on Google's malware, phishing or unwanted-software lists?

Only the URL string is sent to Google; the target itself is never contacted by this check.
Optional: without a key the source reports not_configured and other evidence decides.
"""
import os

ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search'
THREAT_TYPES = ('MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE')
MESSAGES = {
    'SOCIAL_ENGINEERING': 'Google Web Risk lists this URL as phishing or social engineering.',
    'MALWARE': 'Google Web Risk lists this URL as distributing malware.',
    'UNWANTED_SOFTWARE': 'Google Web Risk lists this URL as distributing unwanted software.',
}


def web_risk_key():
    path = os.environ.get('WEB_RISK_API_KEY_FILE', '')
    if path:
        try:
            with open(path, encoding='utf-8') as secret:
                key = secret.read(4096).strip()
        except (OSError, UnicodeError):
            return None
    else:
        key = os.environ.get('WEB_RISK_API_KEY', '').strip()
    return key if key and len(key) < 4096 and not any(c.isspace() for c in key) else None


def google_reason(response):
    """Google's machine-readable error code (e.g. BILLING_DISABLED), never free text."""
    try:
        error = response.json().get('error') or {}
        codes = [d.get('reason') for d in error.get('details') or [] if isinstance(d, dict)] + [error.get('status')]
    except Exception:
        return None
    code = next((c for c in codes if isinstance(c, str) and c), None)
    return code if code and len(code) <= 64 and all(ch.isalnum() or ch == '_' for ch in code) else None


def check_web_risk(url, session, key=None):
    """{'status': matched|not_found|not_configured|unavailable, 'threat_types': [...], 'reason': ...}"""
    key = key if key is not None else web_risk_key()
    from services.source_switches import source_enabled
    if not source_enabled('web_risk'):
        return {'status': 'not_configured', 'threat_types': [], 'reason': 'disabled_by_operator'}
    if not key:
        return {'status': 'not_configured', 'threat_types': [], 'reason': 'api_key_not_configured'}
    params = [('threatTypes', t) for t in THREAT_TYPES] + [('uri', url), ('key', key)]
    try:
        response = session.get(ENDPOINT, params=params, allow_redirects=False, timeout=10)
    except Exception:
        # Never log the request: its query string carries the API key.
        return {'status': 'unavailable', 'threat_types': [], 'reason': 'connection_or_response_error'}
    if response.status_code != 200:
        reason = ('authentication_rejected' if response.status_code in (400, 401, 403)
                  else 'quota_exceeded' if response.status_code == 429 else 'http_error')
        return {'status': 'unavailable', 'threat_types': [], 'reason': reason, 'google_reason': google_reason(response)}
    try:
        data = response.json()
    except ValueError:
        return {'status': 'unavailable', 'threat_types': [], 'reason': 'invalid_response'}
    if not isinstance(data, dict):
        return {'status': 'unavailable', 'threat_types': [], 'reason': 'invalid_response'}
    threat = data.get('threat')
    if not threat:
        return {'status': 'not_found', 'threat_types': [], 'reason': None}  # {} means no list holds the URL
    types = threat.get('threatTypes') if isinstance(threat, dict) else None
    types = [t for t in types if t in THREAT_TYPES] if isinstance(types, list) else []
    if not types:
        return {'status': 'unavailable', 'threat_types': [], 'reason': 'invalid_response'}
    return {'status': 'matched', 'threat_types': types, 'reason': None,
            'expire_time': threat.get('expireTime') if isinstance(threat.get('expireTime'), str) else None}
