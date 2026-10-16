"""API for the MyScanner mobile app, under /api/mobile/v1.

Every route here except sign-in is authorised by an app token in the
`Authorization: Bearer` header and by nothing else: the session cookie is never
read, so a browser visiting another site cannot act through these routes. That
is why this blueprint, and only it, is exempt from the cookie-based CSRF check.

Tools reuse the website's own endpoints, so quotas, validation and ownership
rules are identical for the app and the site.
"""
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, redirect, request, session, url_for
from flask_login import current_user

from extensions import db
from logging_config import log_activity
from models import User
from services import mobile_auth

mobile_bp = Blueprint('mobile', __name__, url_prefix='/api/mobile/v1')
PUBLIC = {'mobile.login', 'mobile.oauth_start', 'mobile.oauth_exchange', 'mobile.providers'}

# The app's tool names, mapped to the website endpoints that do the work.
TOOLS = {
    'url': 'api_url_analyze', 'site': 'async_scan_site', 'file': 'async_scan_file', 'qr-url': 'api_scan_qr_url',
    'email': 'api_check_email', 'password': 'api_check_password', 'ip': 'api_check_ip',
    'domain': 'api_domain_lookup', 'subdomain': 'api_subdomain_finder', 'ssl': 'api_ssl_checker',
}


def _profile(user):
    from services.account_overview import daily_allowance
    return {'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role,
            'allowance': daily_allowance(user)}


@mobile_bp.before_request
def require_app_token():
    if request.endpoint in PUBLIC:
        return None
    user = mobile_auth.authenticate(mobile_auth.bearer(request.headers.get('Authorization')))
    if user is None:
        return jsonify(error='Your session has ended. Please sign in again.'), 401, {'WWW-Authenticate': 'Bearer'}
    g._login_user = user  # Flask-Login's current user for this request; the cookie is not consulted
    return None


def _call(endpoint, **kwargs):
    """Run a website endpoint for the signed-in app user."""
    return current_app.view_functions[endpoint](**kwargs)


# ---------------------------------------------------------------- account

@mobile_bp.route('/auth/login', methods=['POST'])
def login():
    from services.auth_rate_limit import AuthRateLimited, check_auth_request
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    email = str(data.get('email') or '').strip().lower()
    password = data.get('password')
    if not email or not isinstance(password, str) or not password:
        return jsonify(error='Enter your email and password.'), 400
    try:
        check_auth_request('login', request.remote_addr or 'unknown', email)
    except AuthRateLimited as limited:
        return jsonify(error='Too many sign-in attempts. Please wait and try again.'), 429, {'Retry-After': str(limited.retry_after)}
    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        current_app.logger.warning('Failed app sign-in attempt')
        return jsonify(error='Invalid email or password.'), 401
    if not user.is_verified:
        return jsonify(error='Please verify your email address first. Open the link we sent you, or sign in on the website to get a new one.'), 403
    token, expires = mobile_auth.issue(user, data.get('device'))
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_activity(user.username, 'login', 'Signed in to the mobile app')
    return jsonify(token=token, expires_at=expires.isoformat() + 'Z', user=_profile(user))


@mobile_bp.route('/auth/oauth/<provider>')
def oauth_start(provider):
    """Begin Google/GitHub sign-in in the phone's browser; the callback returns a code to the app."""
    from services.oauth_login import OAuthError, start
    redirect_uri = request.args.get('redirect', '')
    challenge = request.args.get('challenge', '')
    if not mobile_auth.APP_REDIRECT.match(redirect_uri) or not mobile_auth.CHALLENGE.match(challenge):
        return jsonify(error='Invalid sign-in request'), 400
    session['mobile_oauth'] = {'provider': provider, 'redirect': redirect_uri, 'challenge': challenge}
    try:
        return redirect(start(provider, url_for('oauth_callback', provider=provider, _external=True), session))
    except OAuthError as error:
        session.pop('mobile_oauth', None)
        return redirect(mobile_auth.app_return(redirect_uri, error=str(error)))


@mobile_bp.route('/auth/oauth/exchange', methods=['POST'])
def oauth_exchange():
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    user = mobile_auth.redeem_code(data.get('code'), data.get('verifier'))
    if user is None:
        return jsonify(error='Sign-in expired. Please try again.'), 401
    token, expires = mobile_auth.issue(user, data.get('device'))
    log_activity(user.username, 'login', 'Mobile app sign-in completed')
    return jsonify(token=token, expires_at=expires.isoformat() + 'Z', user=_profile(user))


@mobile_bp.route('/auth/providers')
def providers():
    from services.oauth_login import enabled_providers
    return jsonify(providers=enabled_providers())


@mobile_bp.route('/auth/logout', methods=['POST'])
def logout():
    mobile_auth.revoke(mobile_auth.bearer(request.headers.get('Authorization')))
    return jsonify(ok=True)


@mobile_bp.route('/me')
def me():
    return jsonify(user=_profile(current_user))


@mobile_bp.route('/account/delete', methods=['POST'])
def delete_account():
    from services.account_deletion import delete_account as remove, matches
    data = request.get_json(silent=True)
    if not matches(current_user, data.get('confirm_email') if isinstance(data, dict) else None):
        return jsonify(error='Type your account email address to confirm.'), 400
    user_id = current_user.id
    remove(user_id)
    log_activity(None, 'account_deleted', f'Account #{user_id} deleted from the mobile app')
    return jsonify(ok=True)


# ---------------------------------------------------------------- tools and reports

@mobile_bp.route('/tools/<name>', methods=['POST'])
def tool(name):
    if name not in TOOLS:
        return jsonify(error='Unknown tool'), 404
    return _call(TOOLS[name])


@mobile_bp.route('/scans/recent')
def recent_scans():
    return _call('api_recent_scans')


@mobile_bp.route('/scans/<int:scan_id>/status')
def scan_status(scan_id):
    return _call('api_scan_status', scan_id=scan_id)


@mobile_bp.route('/scans/<int:scan_id>')
def scan_result(scan_id):
    return _call('api_scan_result', scan_id=scan_id)


@mobile_bp.route('/scans/<int:scan_id>/analysis')
def scan_analysis(scan_id):
    return _call('api_url_analysis', scan_id=scan_id)


@mobile_bp.route('/tasks/<task_id>')
def task(task_id):
    return _call('task_status', task_id=task_id)


# ---------------------------------------------------------------- AI assistant

@mobile_bp.route('/ai/contexts', methods=['POST'])
def ai_create_context():
    return _call('api_ai_create_context')


@mobile_bp.route('/ai/contexts/<context_id>')
def ai_context(context_id):
    return _call('api_ai_get_context', context_id=context_id)


@mobile_bp.route('/ai/contexts/<context_id>/explain', methods=['POST'])
def ai_explain(context_id):
    return _call('api_ai_explain', context_id=context_id)


@mobile_bp.route('/ai/contexts/<context_id>/chat', methods=['POST'])
def ai_chat(context_id):
    return _call('api_ai_chat', context_id=context_id)


@mobile_bp.route('/ai/assistant', methods=['POST'])
def ai_assistant():
    return _call('api_ai_general')
