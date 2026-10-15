import os
from dotenv import load_dotenv
if os.getenv('APP_ENV', '').lower() != 'production' and os.getenv('RENDER', '').lower() != 'true':
    load_dotenv()

from extensions import db, login_manager, bcrypt
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.units import cm
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from io import BytesIO
import requests
import threading
import secrets
import time
import json
import hashlib
import hmac
import re
import socket
import dns.resolver
import smtplib
import Levenshtein
import redis
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from email_validator import validate_email, EmailNotValidError
from typing import Any
from services.domain_analyzer import DomainAnalyzer
from services.site_analyzer import SiteAnalyzer
from services.url_analyzer import URLDeepAnalyzer
from services.subdomain_finder import SubdomainFinder
from services.password_analyzer import PasswordAnalyzer
from models import User, Scan
from models import User, Scan, LogEntry
from services.ip_analyzer import IPAnalyzer
from services.domain_analyzer import DomainAnalyzer
from services.ssl_analyzer import SSLAnalyzer
from services.qr_analyzer import QRAnalyzer
from services.web_scan_request import validate_web_scan_request
from services.file_deep_analyzer import FileDeepAnalyzer  # ✅ صحيح
from werkzeug.utils import secure_filename
from celery.result import AsyncResult
from celery_app import celery, make_celery
import uuid
from tasks import scan_file_task, scan_site_task, batch_scan_task, scan_url_task, bulk_email_task
from services.permissions import check_permission, reserve_request_quota
from models.async_scan_task import AsyncScanTask
from services.safe_http import PublicHTTPSession, UnsafeTargetError
from services.task_dispatch import enqueue_owned_task
from services.upload_validation import (UploadValidationError, read_validated_upload,
    save_temporary_upload, remove_temporary_upload)
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timedelta, timezone
from logging_config import log_activity
from services.vulnerability_scanner.scan_orchestrator import get_orchestrator
from services.vulnerability_scanner.report_generator import get_report_generator
from models.vulnerability import VulnerabilityScan, Vulnerability, ScanConfig
import resend
from typing import Optional
from services.pdf_report_generator import generate_vulnerability_report


# ================================================================
# Initialization
# ================================================================
app = Flask(__name__)
from logging_config import setup_logging

# ================================================================
# CSRF Protection (أضيفي هذا هنا)
# ================================================================
from flask_wtf.csrf import CSRFProtect, CSRFError
csrf = CSRFProtect()
csrf.init_app(app)


# ================================================================
# Config
# ================================================================
from services.runtime_security import security_settings
app.config.update(security_settings())
from services.trusted_proxy import configure_trusted_proxy, render_edge_candidate
trusted_proxy = configure_trusted_proxy(app)
from services.security_headers import init_security_headers
init_security_headers(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Allow a 32 MB Sandbox file plus bounded multipart overhead.
app.config['MAX_CONTENT_LENGTH'] = 33 * 1024 * 1024

@app.errorhandler(CSRFError)
def csrf_failure(error):
    message = 'Your session security token is missing or expired. Refresh the page and try again.'
    if request.path.startswith(('/api/', '/vulnerability/')) or request.is_json:
        return jsonify({'error': message, 'code': 'csrf_failed'}), 400
    return render_template('csrf_error.html', message=message), 400

@app.errorhandler(UnsafeTargetError)
def unsafe_scan_target(error):
    return jsonify({"error": str(error)}), 400

@app.errorhandler(UploadValidationError)
def invalid_upload(error):
    return jsonify({'error': str(error)}), error.status_code

@app.errorhandler(RequestEntityTooLarge)
def oversized_request(error):
    return jsonify({'error': 'Upload request too large.'}), 413

ABSTRACT_API_KEY = os.getenv('ABSTRACT_API_KEY')
from services.provider_credentials import abuseipdb_key, resend_key
ABUSEIPDB_API_KEY = abuseipdb_key()
# Direct SMTP recipient probes need outbound port 25, which many hosts block.
SMTP_PROBE_ENABLED = os.getenv('EMAIL_SMTP_PROBE', 'on').strip().lower() in ('1', 'true', 'on', 'yes')
RESEND_API_KEY = resend_key()
# File Scanner Settings
UPLOAD_FOLDER = 'temp_uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z', 'js', 'py', 'ps1', 'sh', 'bat', 'vbs', 'scr', 'msi'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# ================================================================
# Email Checker Constants & Lists
# ================================================================
from constants import DISPOSABLE_DOMAINS, FREE_DOMAINS, BLACKLISTS
# ================================================================
# Advanced Email Checker Class
# ================================================================

from services.email_checker import AdvancedEmailChecker

# ================================================================
# Redis Cache Setup (Disabled - no Redis server)
# ================================================================
redis_client = None
print("[REDIS] Disabled - running without cache")
from logging_config import setup_logging, log_activity, log_performance, log_error
setup_logging(app)
# ================================================================
# Extensions
# ==============================================================

db.init_app(app)
make_celery(app)
from flask_migrate import Migrate    
migrate = Migrate(app, db)        
login_manager.init_app(app)
bcrypt.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def reset_daily_scans():
    from services.permissions import reset_daily_scans as reset_expired
    with app.app_context():
        return reset_expired()

# ================================================================
# Email Helper (Resend API)
# ================================================================

import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================================================================
# Email Helper (Resend API) - Updated Version
# ================================================================

import resend

# تأكد من تعيين مفتاح Resend
resend.api_key = RESEND_API_KEY

# ثوابت البريد الإلكتروني
FROM_EMAIL = os.getenv('FROM_EMAIL', 'info@myscanners.com')
FROM_NAME = os.getenv('FROM_NAME', 'MyScanner Security')


def send_email(to_email: str, subject: str, body: str,
               html_body: Optional[str] = None, reply_to: Optional[str] = None) -> bool:
    """
    إرسال إيميل عبر Resend API مع دعم HTML
    ملاحظة: تم تحويلها إلى إرسال متزامن (synchronous) بدلاً من thread منفصل،
    لأن الـ daemon thread كان يُقتل على Render قبل أن ينفّذ resend.Emails.send()
    عندما يُعاد تدوير الـ worker مباشرة بعد إرسال الاستجابة — وهذا كان يفسر
    عدم ظهور أي [EMAIL] أو [EMAIL ERROR] في اللوج رغم أن الكود يبدو صحيحاً.
    """
    try:
        params = {
            "from": f"{FROM_NAME} <{FROM_EMAIL}>",
            "to": [to_email],
            "subject": subject,
            "text": body,
        }
        if html_body:
            params["html"] = html_body
        if reply_to:
            params["reply_to"] = [reply_to]

        resp = resend.Emails.send(params)
        app.logger.info(f"[EMAIL] Sent to {to_email} | ID: {resp.get('id')}")
        return True

    except Exception as e:
        app.logger.error(f"[EMAIL ERROR] {to_email}: {str(e)}")
        return False


def send_verification_email(user):
    from services.email_templates import action_email
    token = serializer.dumps(user.email, salt='email-verify')
    base_url = os.getenv('BASE_URL', 'https://myscanners.com')
    link = f"{base_url}/verify/{token}"
    html_body, body = action_email(
        'Verify your email address', f'Welcome, {user.username}!',
        ['Confirm this address to activate your MyScanner account and start inspecting links, files and domains.'],
        'Verify my email', link, 'This link expires in 1 hour. If you did not create an account, you can ignore this email.')
    send_email(user.email, 'Verify your MyScanner account', body, html_body)

def _reset_fingerprint(user):
    # Binds a reset link to the current password hash: once the password
    # changes, every earlier link (including the one just used) is invalid.
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:32]


def password_policy_errors(password):
    errors = []
    if len(password) < 8:
        errors.append('at least 8 characters')
    if not re.search(r'[A-Z]', password):
        errors.append('at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('at least one lowercase letter')
    if not re.search(r'[0-9]', password):
        errors.append('at least one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('at least one special character')
    return errors


def send_reset_email(user):
    from services.email_templates import action_email
    token = serializer.dumps({'email': user.email, 'fp': _reset_fingerprint(user)}, salt='password-reset')
    base_url = os.getenv('BASE_URL', 'https://myscanners.com')
    link = f"{base_url}/reset-password/{token}"
    html_body, body = action_email(
        'Reset your password', f'Hello {user.username},',
        ['We received a request to reset the password for your MyScanner account. Choose a new one with the button below.'],
        'Choose a new password', link,
        'This link works once and expires in 30 minutes. If you did not ask for it, ignore this email: your password stays the same.')
    send_email(user.email, 'Reset your MyScanner password', body, html_body)


def send_password_changed_email(user):
    from services.email_templates import action_email
    base_url = os.getenv('BASE_URL', 'https://myscanners.com')
    html_body, body = action_email(
        'Your password was changed', f'Hello {user.username},',
        [f'The password for your MyScanner account was changed on {datetime.utcnow():%d %b %Y at %H:%M} UTC.'],
        'Sign in', f'{base_url}/login',
        'If this was not you, reset your password immediately from the sign-in page and contact info@myscanners.com.',
        tone='#fbbf24')
    send_email(user.email, 'Your MyScanner password was changed', body, html_body)

# ================================================================
# Database Models
# ================================================================


# ================================================================
# URL Scan in Background - الإصدار الجديد
# يستخدم: URLDeepAnalyzer + url.vet
# ================================================================



from routes.tip_routes import tip_bp
app.register_blueprint(tip_bp)

from routes.sandbox_routes import sandbox_bp
app.register_blueprint(sandbox_bp)

from routes.vuln_routes import vuln_bp
app.register_blueprint(vuln_bp)

from services.runtime_health import health_bp
app.register_blueprint(health_bp)
from routes.file_pdf import file_pdf_bp
app.register_blueprint(file_pdf_bp)

# ================================================================
# Auth Routes
# ================================================================

from services.auth_rate_limit import AuthRateLimited, check_auth_request, check_verification_send
from sqlalchemy.exc import SQLAlchemyError


@app.before_request
def protect_auth_requests():
    if request.method == 'POST' and request.endpoint in {'login', 'register', 'forgot_password'} and not current_user.is_authenticated:
        try:
            # Middleware applies forwarded addresses only for configured
            # trusted peers. Direct clients cannot spoof this identity.
            check_auth_request(request.endpoint, request.remote_addr or 'unknown',
                               request.form.get('email', '').strip().lower())
        except SQLAlchemyError:
            app.logger.error('Authentication rate-limit storage unavailable')
            return render_template('auth_rate_limit.html', unavailable=True, retry_after=60), 503, {'Retry-After': '60'}


@app.errorhandler(AuthRateLimited)
def auth_rate_limited(error):
    return render_template('auth_rate_limit.html', unavailable=False, retry_after=error.retry_after), 429, {'Retry-After': str(error.retry_after)}


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # التحقق من الحقول
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        # التحقق من تطابق كلمة المرور
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        # التحقق من قوة كلمة المرور
        password_errors = password_policy_errors(password)
        if password_errors:
            flash(f'Password must contain: {", ".join(password_errors)}', 'danger')
            return redirect(url_for('register'))

        # التحقق من وجود المستخدم
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))

        # إنشاء مستخدم جديد
        user = User(username=username, email=email)
        user.set_password(password)
        user.is_verified = False
        user.role = 'user'  # دور افتراضي
        
        # تعيين الحدود الافتراضية للمستخدم الجديد
        user.site_scan_remaining = 10
        user.file_scan_remaining = 5
        user.url_analyzer_remaining = 3
        user.email_check_remaining = 15
        user.ip_check_remaining = 15
        user.domain_lookup_remaining = 15
        user.ssl_check_remaining = 15
        user.qr_scan_remaining = 15
        user.subdomain_finder_remaining = 5
        user.password_check_remaining = 15
        user.ai_assistant_remaining = 10
        
        db.session.add(user)
        db.session.commit()
        check_verification_send(user.id)
        send_verification_email(user)

        flash('Account created! Please check your email to verify your account before logging in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except Exception:
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if user.is_verified:
        flash('Account already verified. Please log in.', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        logout_user()
        flash('Email verified! You can now log in.', 'success')

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        # التحقق من وجود البريد
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        # التحقق من كلمة المرور
        if not user.check_password(password):
            # تسجيل محاولة فاشلة
            app.logger.warning(f'Failed login attempt for email: {email}')
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        # ✅ التحقق من أن الحساب مفعّل
        # (تم إصلاح باگ الإزاحة هنا: كانت السطور التالية تنفذ دائماً
        # بغض النظر عن حالة is_verified، مما كان يمنع أي مستخدم من تسجيل
        # الدخول ويعيد إرسال إيميل التفعيل في كل مرة)
        if not user.is_verified:
            check_verification_send(user.id)
            flash('Please verify your email address before logging in. A new verification link has been sent to your email.', 'warning')
            send_verification_email(user)  # إعادة إرسال رابط التفعيل
            return redirect(url_for('login'))

        # تسجيل الدخول الناجح
        login_user(user, remember=remember)
        
        # تحديث آخر تسجيل دخول
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # تسجيل النشاط
        log_activity(user.username, 'login', f'Logged in from {request.remote_addr}')
        
        flash(f'Welcome back, {user.username}!', 'success')
        
        next_page = request.args.get('next')
        from services.login_redirect import safe_login_redirect
        return redirect(safe_login_redirect(next_page, url_for('dashboard')))

    return render_template('login.html')

@app.context_processor
def inject_oauth_providers():
    if request.endpoint in ('login', 'register'):
        from services.oauth_login import enabled_providers
        return {'oauth_providers': enabled_providers()}
    return {}


@app.route('/auth/<provider>/start')
def oauth_start(provider):
    from services.oauth_login import OAuthError, start
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    from services.login_redirect import safe_login_redirect
    session['oauth_next'] = safe_login_redirect(request.args.get('next'), url_for('dashboard'))
    try:
        return redirect(start(provider, url_for('oauth_callback', provider=provider, _external=True), session))
    except OAuthError as error:
        flash(str(error), 'warning')
        return redirect(url_for('login'))


@app.route('/auth/<provider>/callback')
def oauth_callback(provider):
    from services.oauth_login import OAuthError, finish, unique_username
    target = session.pop('oauth_next', None) or url_for('dashboard')
    try:
        email, name = finish(provider, request.args, url_for('oauth_callback', provider=provider, _external=True), session)
    except OAuthError as error:
        flash(str(error), 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(username=unique_username(name, email, lambda c: User.query.filter_by(username=c).first() is not None),
                    email=email, is_verified=True, role='user')
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
        log_activity(user.username, 'register', f'Account created with {provider}')
    elif not user.is_verified:
        # The provider proved ownership of this address; whoever set the
        # unverified account's password may not own it, so drop that password.
        user.is_verified = True
        user.set_password(secrets.token_urlsafe(32))
    user.last_login = datetime.utcnow()
    db.session.commit()
    login_user(user)
    log_activity(user.username, 'login', f'Signed in with {provider} from {request.remote_addr}')
    flash(f'Welcome, {user.username}!', 'success')
    from services.login_redirect import safe_login_redirect
    return redirect(safe_login_redirect(target, url_for('dashboard')))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user  = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
        # Same answer whether or not the account exists (no enumeration).
        session['reset_sent_to'] = mask_email(email)
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', sent_to=session.pop('reset_sent_to', None))


def mask_email(email):
    name, _, domain = (email or '').partition('@')
    if not name or not domain:
        return 'your inbox'
    return (name[:2] if len(name) > 2 else name[:1]) + '•' * max(2, min(len(name) - 2, 6)) + '@' + domain


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        payload = serializer.loads(token, salt='password-reset', max_age=1800)
    except Exception:
        payload = None
    user = None
    if isinstance(payload, dict) and isinstance(payload.get('email'), str):
        user = User.query.filter_by(email=payload['email']).first()
    if not user or not hmac.compare_digest(str(payload.get('fp', '')), _reset_fingerprint(user)):
        flash('Reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        password_errors = password_policy_errors(password)
        if password_errors:
            flash(f'Password must contain: {", ".join(password_errors)}', 'danger')
            return redirect(request.url)

        # ✅ استخدم bcrypt من extensions
        from extensions import bcrypt
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        send_password_changed_email(user)
        log_activity(user.username, 'password_reset', f'Password reset from {request.remote_addr}')

        flash('Password updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, account=mask_email(user.email))


@app.route('/profile')
@login_required
def profile():
    from services.account_overview import daily_allowance, scan_counts
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.date_posted.desc()).limit(10).all()
    return render_template('profile.html', scans=scans, counts=scan_counts(current_user.id),
                           allowance=daily_allowance(current_user))


# ================================================================
# Main Routes
# ================================================================

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return render_template('index.html')  # صفحة فحص الروابط
    return render_template('home.html')  # الصفحة الرئيسية العامة

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return redirect(url_for('dashboard'))
        
        from services.safe_http import normalize_url
        try:
            if len(url) > 500:
                raise ValueError('URL too long')
            normalize_url(url)
        except (ValueError, UnsafeTargetError):
            flash('Please provide a valid HTTP or HTTPS URL.', 'warning')
            return redirect(url_for('dashboard'))

        from celery_app import require_broker
        try:
            require_broker(celery)
        except RuntimeError:
            flash('URL analysis is temporarily unavailable. Please try again later.', 'warning')
            return redirect(url_for('dashboard'))

        failure = reserve_request_quota('url_analyzer')
        if failure is not None:
            response, status = failure
            if status == 429:
                flash('You have reached your daily URL scan limit.', 'warning')
                return redirect(url_for('dashboard'))
            return failure

        from services.url_scan_storage import enqueue_url_scan
        try:
            scan_id = enqueue_url_scan(scan_url_task, url, current_user.id)
        except Exception:
            db.session.rollback()
            app.logger.error('URL scan could not be queued')
            flash('URL analysis is temporarily unavailable. Please try again later.', 'warning')
            return redirect(url_for('dashboard'))
        return redirect(url_for('result_page', scan_id=scan_id))

    return render_template('index.html')

@app.route('/result/<int:scan_id>')
@login_required
def result_page(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('dashboard'))
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('result.html', scan=scan)


# ================================================================
# API Routes
# ================================================================

@app.route('/api/scan_status/<int:scan_id>')
@login_required
def api_scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404
    return jsonify({"id": scan.id, "status": scan.status, "verdict": scan.verdict})


@app.route('/api/scan_result/<int:scan_id>')
@login_required
def api_scan_result(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404

    raw = None
    if scan.raw_report:
        try:
            raw = json.loads(scan.raw_report)
        except Exception:
            raw = None

    if isinstance(raw, dict) and isinstance(raw.get('local_analysis'), dict) and isinstance(raw.get('deep_analysis'), dict):
        from services.url_assessment import saved_assessment
        raw['aggregate_assessment'] = saved_assessment(raw, raw['local_analysis'], raw['deep_analysis'])

    from services.url_screenshot import screenshot_path
    return jsonify({
        "id": scan.id, "url": scan.url,
        "status": scan.status, "verdict": scan.verdict,
        "result_html": scan.result, "raw_report": raw,
        "screenshot_url": f"/api/scan_screenshot/{scan.id}" if screenshot_path(scan.id).is_file() else None,
        "date": scan.date_posted.strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/api/scan_screenshot/<int:scan_id>')
@login_required
def api_scan_screenshot(scan_id):
    from services.url_screenshot import screenshot_path
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404
    path = screenshot_path(scan.id)
    if not path.is_file():
        return jsonify({"error": "Not found"}), 404
    response = send_file(path, mimetype='image/jpeg', max_age=0)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.route('/api/recent_scans')
@login_required
def api_recent_scans():
    limit = min(max(request.args.get('limit', 15, type=int) or 15, 1), 100)
    if current_user.is_admin:
        scans = Scan.query.order_by(Scan.date_posted.desc()).limit(limit).all()
    else:
        scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.date_posted.desc()).limit(limit).all()

    data = []
    for scan in scans:
        summary = ''
        if scan.result:
            soup = BeautifulSoup(scan.result, 'html.parser')
            summary = soup.get_text(strip=True)[:250]
        elif scan.raw_report:
            summary = 'Report available'
        else:
            summary = 'No summary available'
        
        data.append({
            "id": scan.id,
            "url": scan.url,
            "verdict": scan.verdict if scan.verdict else 'unknown',
            "summary": summary,
            "date": scan.date_posted.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return jsonify({"scans": data})

@app.route('/api/bulk-email-check', methods=['POST'])
@login_required
def api_bulk_email_check():
    """Queue up to 20 email checks; read the result from /api/task-status/<task_id>."""
    data = request.get_json(silent=True)
    emails = data.get('emails') if isinstance(data, dict) else None
    if not isinstance(emails, list) or not 1 <= len(emails) <= 20 or any(not isinstance(email, str) or not email.strip() or len(email) > 254 for email in emails):
        return jsonify(error='Provide 1-20 valid email strings'), 400
    failure = reserve_request_quota('email_check', len(emails))
    if failure is not None:
        return failure
    try:
        task_id = enqueue_owned_task(bulk_email_task, ([email.strip() for email in emails], current_user.id), current_user.id)
    except Exception:
        app.logger.exception('Failed to enqueue bulk email check')
        return jsonify(error='Unable to queue the email checks. Please try again later.'), 503
    return jsonify(task_id=task_id, total=len(emails), status='started',
                   status_url=url_for('task_status', task_id=task_id)), 202

# ================================================================
# File Scanner API
# ================================================================

# ================================================================
# File Scanner API - الإصدار الجديد
# ================================================================

from services.file_threat_intel import get_file_threat_intel

@app.route('/api/scan-file', methods=['POST'])
@login_required
def api_scan_file():
    """Queue the unified file scan (FileDeepAnalyzer + MalwareBazaar)."""
    return _queue_file_job('file_scan')


@app.route('/api/file-deep-analysis', methods=['POST'])
@login_required
def api_file_deep_analysis():
    """Queue static file analysis with exiftool metadata."""
    return _queue_file_job('file_deep')


def _queue_file_job(kind):
    filename, file_content = read_validated_upload(
        request.files.get('file'), ALLOWED_EXTENSIONS, MAX_FILE_SIZE
    )
    failure = reserve_request_quota('file_scan')
    if failure is not None:
        return failure
    from services.evidence_jobs import queue_evidence_job
    temp_path = save_temporary_upload(file_content, filename, UPLOAD_FOLDER)
    log_activity(current_user.username, 'file_scan', f'File scan queued: {filename}')
    return queue_evidence_job(kind, {'path': temp_path, 'filename': filename})


# ================================================================
# API: بدء فحص ملف غير متزامن
# ================================================================

@app.route('/api/async-scan-file', methods=['POST'])
@login_required
def async_scan_file():
    app.logger.info(f'📁 File scan started by {current_user.username}')
    """
    بدء فحص ملف في الخلفية (غير متزامن)
    يعود فوراً بـ task_id لتتبع التقدم
    """
    filename, file_content = read_validated_upload(
        request.files.get('file'), ALLOWED_EXTENSIONS, MAX_FILE_SIZE
    )
    failure = reserve_request_quota('file_scan')
    if failure is not None:
        return failure
    temp_path = save_temporary_upload(file_content, filename, UPLOAD_FOLDER)
    try:
        task_id = enqueue_owned_task(
            scan_file_task, (temp_path, filename, current_user.id), current_user.id
        )
    except Exception:
        remove_temporary_upload(temp_path)
        app.logger.exception('Failed to enqueue file scan')
        return jsonify({'error': 'Unable to queue file scan. Please try again later.'}), 503

    return jsonify({
        "task_id": task_id,
        "status": "started",
        "message": "File scan started in background"
    })


# ================================================================
# API: التحقق من حالة مهمة
# ================================================================

@app.route('/api/task-status/<task_id>')
@login_required
def task_status(task_id):
    app.logger.info(f'📊 Task status check: User={current_user.username}, Task={task_id}')
    """
    التحقق من حالة مهمة غير متزامنة
    """
    ownership = db.session.get(AsyncScanTask, task_id)
    if not ownership:
        return jsonify({'error': 'Task not found'}), 404
    if ownership.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    task = AsyncResult(task_id, app=celery)
    
    if task.state == 'PENDING':
        response = {
            'state': 'PENDING',
            'status': 'Task is waiting to start...',
            'progress': 0
        }
    elif task.state == 'STARTED':
        response = {
            'state': 'STARTED',
            'status': 'Task is running...',
            'progress': task.info.get('progress', 0) if task.info else 0
        }
    elif task.state == 'RUNNING':
        response = {
            'state': 'RUNNING',
            'status': task.info.get('status', 'Processing...'),
            'progress': task.info.get('progress', 0)
        }
    elif task.state == 'SUCCESS':
        result = task.result
        outcome = result.get('status') if isinstance(result, dict) else None
        if isinstance(outcome, str) and outcome in {'failed', 'error'}:
            # Only evidence jobs set user_error, from a fixed set of messages.
            message = result.get('user_error')
            response = {'state': 'FAILURE', 'outcome': 'failed',
                        'status': 'Task did not complete successfully',
                        'error': message if isinstance(message, str) and 0 < len(message) <= 200 else 'Analysis failed. Please retry.',
                        'progress': 0}
        else:
            messages = {'partial': 'Analysis finished with incomplete coverage',
                        'unavailable': 'Analysis unavailable'}
            response = {
                'state': 'SUCCESS',
                'outcome': outcome if isinstance(outcome, str) and outcome in messages else 'completed',
                'status': messages.get(outcome, 'Task completed successfully') if isinstance(outcome, str) else 'Task completed successfully',
                'result': result, 'progress': 100
            }
    elif task.state == 'FAILURE':
        response = {
            'state': 'FAILURE',
            'status': 'Task failed',
            'error': 'Analysis failed. Please retry.',
            'progress': 0
        }
    else:
        response = {
            'state': task.state,
            'status': 'Unknown state',
            'progress': 0
        }
    
    # Task results can contain scan reports; never let a browser or proxy cache them.
    return jsonify(response), 200, {'Cache-Control': 'no-store'}


# ================================================================
# API: بدء فحص موقع غير متزامن
# ================================================================

@app.route('/api/async-scan-site', methods=['POST'])
@login_required
def async_scan_site():
    app.logger.info(f'[INFO] Site scan requested by {current_user.username}')
    
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('domain'), str):
        return jsonify(error='Provide a valid domain'), 400
    domain = data['domain'].strip()
    
    if not domain:
        app.logger.warning(f'⚠️ No domain provided by {current_user.username}')
        return jsonify({"error": "No domain provided"}), 400
    
    if len(domain) > 253:
        return jsonify(error='Domain exceeds the allowed length'), 400
    failure = reserve_request_quota('site_scan')
    if failure is not None:
        return failure

    app.logger.info(f'[INFO] Starting async scan for domain: {domain}')
    
    # إنشاء سجل فحص جديد
    new_scan = Scan(
        url=f"https://{domain}", 
        verdict='pending', 
        result='pending', 
        user_id=current_user.id,
        status='queued'
    )
    db.session.add(new_scan)
    db.session.commit()
    
    # بدء المهمة في الخلفية
    task_id = enqueue_owned_task(
        scan_site_task, (domain, current_user.id, new_scan.id), current_user.id
    )
    
    app.logger.info(f'[SUCCESS] Async scan started for {domain} | Task ID: {task_id}')
    
    return jsonify({
        "task_id": task_id,
        "scan_id": new_scan.id,
        "status": "started",
        "message": "Site scan started in background"
    })


# ================================================================
# API: فحص عدة روابط دفعة واحدة
# ================================================================

@app.route('/api/batch-scan', methods=['POST'])
@login_required
def batch_scan():
    """
    فحص مجموعة من الروابط دفعة واحدة
    """
    data = request.get_json(silent=True)
    urls = data.get('urls') if isinstance(data, dict) else None
    if not isinstance(urls, list) or not 1 <= len(urls) <= 20 or any(not isinstance(url, str) or not url.strip() or len(url) > 2048 for url in urls):
        return jsonify(error='Provide 1-20 valid URL strings'), 400
    from services.safe_http import normalize_url
    try:
        for url in urls:
            normalize_url(url)
    except (ValueError, UnsafeTargetError):
        return jsonify(error='Provide valid HTTP or HTTPS URLs'), 400
    failure = reserve_request_quota('url_analyzer', len(urls))
    if failure is not None:
        return failure

    task_id = enqueue_owned_task(batch_scan_task, (urls, current_user.id), current_user.id)
    
    return jsonify({
        "task_id": task_id,
        "total_urls": len(urls),
        "status": "started",
        "message": f"Batch scan of {len(urls)} URLs started"
    })
    
# Removed redundant and broken scan-file route

# ================================================================
# Admin
# ================================================================

@app.route('/admin/proxy-check')
@login_required
def admin_proxy_check():
    if not current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403
    response = app.make_response(render_template('proxy_check.html'))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/admin/proxy-info')
@login_required
def admin_proxy_info():
    if not current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403
    response = jsonify({
        'peer_ip': request.environ.get('myscanner.proxy_peer', request.remote_addr),
        'client_ip': request.remote_addr,
        'scheme': request.scheme,
        'forwarded_for': request.headers.get('X-Forwarded-For', '')[:2048],
        'forwarded_proto': request.headers.get('X-Forwarded-Proto', '')[:100],
        'configured': trusted_proxy is not None,
        'applied': request.environ.get('myscanner.proxy_applied', False),
        'identity_source': request.environ.get('myscanner.identity_source', 'trusted-proxy' if request.environ.get('myscanner.proxy_applied') else 'direct'),
        'cf_connecting_ip': request.headers.get('CF-Connecting-IP', '')[:100],
        'cf_connecting_ipv6': request.headers.get('CF-Connecting-IPv6', '')[:100],
        'edge_candidate': render_edge_candidate(request.environ),
    })
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.date_joined.desc()).all()
    scans = Scan.query.order_by(Scan.date_posted.desc()).limit(50).all()
    return render_template('admin.html', users=users, scans=scans)
@app.route('/admin/logs')
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    page      = request.args.get('page', 1, type=int)
    action    = request.args.get('action', '').strip()
    user      = request.args.get('user', '').strip()
    ip        = request.args.get('ip', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()

    query = LogEntry.query

    if action:
        query = query.filter(LogEntry.action == action)
    if user:
        query = query.filter(LogEntry.username.ilike(f'%{user}%'))
    if ip:
        query = query.filter(LogEntry.ip_address.ilike(f'%{ip}%'))
    if date_from:
        try:
            query = query.filter(LogEntry.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import timedelta
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(LogEntry.timestamp < dt_to)
        except ValueError:
            pass

    logs = query.order_by(LogEntry.timestamp.desc()).paginate(page=page, per_page=50)

    stats = {
        'total':          LogEntry.query.count(),
        'logins':         LogEntry.query.filter_by(action='login').count(),
        'logouts':        LogEntry.query.filter_by(action='logout').count(),
        'site_scans':     LogEntry.query.filter_by(action='site_scan').count(),
        'ip_checks':      LogEntry.query.filter_by(action='ip_check').count(),
        'email_checks':   LogEntry.query.filter_by(action='email_check').count(),
        'domain_lookups': LogEntry.query.filter_by(action='domain_lookup').count(),
        'qr_scans':       LogEntry.query.filter_by(action='qr_scan').count(),
        'url_analyses':   LogEntry.query.filter_by(action='url_analysis').count(),
        'file_scans':     LogEntry.query.filter_by(action='file_scan').count(),
        'ssl_checks':     LogEntry.query.filter_by(action='ssl_check').count(),
        'subdomain_finds':LogEntry.query.filter_by(action='subdomain_finder').count(),
        'password_checks':LogEntry.query.filter_by(action='password_check').count(),
    }

    return render_template('admin_logs.html', logs=logs, stats=stats)


@app.route('/admin/logs/export')
@login_required
def admin_logs_export():
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403

    action    = request.args.get('action', '').strip()
    user      = request.args.get('user', '').strip()
    ip        = request.args.get('ip', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()

    query = LogEntry.query
    if action:
        query = query.filter(LogEntry.action == action)
    if user:
        query = query.filter(LogEntry.username.ilike(f'%{user}%'))
    if ip:
        query = query.filter(LogEntry.ip_address.ilike(f'%{ip}%'))
    if date_from:
        try:
            query = query.filter(LogEntry.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(LogEntry.timestamp < dt_to)
        except ValueError:
            pass

    logs = query.order_by(LogEntry.timestamp.desc()).limit(5000).all()

    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Level', 'Action', 'Username', 'IP Address', 'Message'])
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.level,
            log.action,
            log.username or '',
            log.ip_address or '',
            log.message or ''
        ])

    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=activity_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )

# ================================================================
# Admin Delete Functions
# ================================================================

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    """حذف مستخدم من قاعدة البيانات"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    if user_id == current_user.id:
        return jsonify({"error": "You cannot delete yourself"}), 400
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"success": True, "message": f"User {user.username} deleted"})


@app.route('/admin/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def admin_delete_scan(scan_id):
    """حذف فحص من قاعدة البيانات"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    from services.url_screenshot import remove_screenshot
    remove_screenshot(scan_id)
    
    return jsonify({"success": True, "message": f"Scan {scan_id} deleted"})


@app.route('/admin/toggle-admin/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_admin(user_id):
    """تبديل صلاحيات الأدمن لمستخدم"""
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_panel'))
    
    if user_id == current_user.id:
        flash('You cannot change your own admin status.', 'warning')
        return redirect(url_for('admin_panel'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "granted" if user.is_admin else "revoked"
    flash(f'Admin privileges {status} for {user.username}.', 'success')
    
    return redirect(url_for('admin_panel'))

@app.route('/email-check')
@login_required
def email_check():
    return render_template('email_check.html', smtp_probe_enabled=SMTP_PROBE_ENABLED)


@app.route('/api/check-email', methods=['POST'])
@login_required
@check_permission('email_check')
def api_check_email():
    app.logger.info(f'[INFO] Email check requested by {current_user.username}')

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('email', ''), str) or not isinstance(data.get('verify_smtp', False), bool):
        return jsonify(error='Invalid email request'), 400
    email = data.get('email', '').strip()

    if not email:
        app.logger.warning(f'[WARNING] No email provided by {current_user.username}')
        return jsonify({"error": "No email provided"}), 400

    app.logger.info(f'[INFO] Checking email: {email} | User: {current_user.username}')

    try:
        checker = AdvancedEmailChecker(redis_client)
        result = checker.check_all(email, verify_smtp=data.get("verify_smtp", False) and SMTP_PROBE_ENABLED)

        if not result.get("valid"):
            app.logger.warning(f'[WARNING] Invalid email format: {email}')
            return jsonify({
                "error": result.get("error", "Invalid email format"),
                "suggestions": result.get("suggestions", [])
            }), 400

        app.logger.info(
            f'[SUCCESS] Email check completed for {email} '
            f'| Verdict: {result.get("verdict")} '
            f'| Score: {result.get("quality_score")}'
        )
        log_activity(
            current_user.username,
            'email_check',
            f'Checked email: {email} | Verdict: {result.get("verdict")}'
        )

        return jsonify({
            "email": result["email"],
            "domain": result["domain"],
            "verdict": result["verdict"],
            "is_valid": result["valid"],
            "is_disposable": result["is_disposable"],
            "is_free": result["is_free"],
            "is_mx": result["dns"]["mx"]["exists"] if result["dns"]["mx"].get("status") != "unavailable" else None,
            "is_smtp": result["smtp"]["valid"],
            "deliverability": result["deliverability"],
            "quality_score": result["quality_score"] / 100,
            "address_risk": result["verdict"],
            "total_breaches": None,
            "last_breached": None,
            "breached_domains": [],
            "domain_age": result["domain_info"].get("age_days", 0),
            "registrar": result["domain_info"].get("registrar", "Unknown"),
            "spf_record": result["dns"]["spf"]["record"],
            "spf_valid": result["dns"]["spf"].get("audit", {}).get("configuration_valid"),
            "dkim_record": None,
            "dkim_valid": None,
            "dmarc_record": result["dns"]["dmarc"]["record"],
            "dmarc_valid": result["dns"]["dmarc"].get("audit", {}).get("configuration_valid"),
            "blacklisted": result["blacklist"]["is_blacklisted"],
            "blacklist_count": len(result["blacklist"].get("blacklisted_on", [])),
            "blacklist_results": result["blacklist"].get("blacklisted_on", []),
            "smtp_details": result["smtp"],
            "assessment": result.get("assessment"),
            "dns_evidence": result["dns"],
            "reputation_evidence": result["blacklist"],
            "domain_evidence": result["domain_info"],
            "checked_at": result.get("checked_at"),
            "quality_breakdown": {
                "score": result["quality_score"],
                "smtp_valid": result["smtp"]["valid"],
                "no_disposable": not result["is_disposable"],
                "not_blacklisted": not result["blacklist"]["is_blacklisted"],
                "spf_exists": result["dns"]["spf"]["exists"],
                "dmarc_exists": result["dns"]["dmarc"]["exists"]
            },
            "address_features": result.get("address_features", {}),
            "format_suggestions": result.get("format_suggestions", [])
        })

    except Exception:
        app.logger.error("Email assessment unavailable")
        return jsonify(error="Email assessment temporarily unavailable. Please retry."), 503


# ================================================================
# IP Check
# ================================================================

@app.route('/ip-check')
@login_required
def ip_check():
    return render_template('ip_check.html')


@app.route('/api/check-ip', methods=['POST'])
@login_required
@check_permission('ip_check')
def api_check_ip():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('ip'), str):
        return jsonify({'error': 'A public IPv4 or IPv6 address is required'}), 400
    try:
        result = IPAnalyzer().analyze_ip(data['ip'], ABUSEIPDB_API_KEY)
        if result.get('error'):
            return jsonify({'error': result['error']}), 400
        log_activity(current_user.username, 'ip_check', 'IP evidence lookup completed')
        response = jsonify(result)
        response.headers['Cache-Control'] = 'no-store'
        return response
    except Exception:
        app.logger.error('IP evidence lookup failed')
        return jsonify({'error': 'IP lookup is temporarily unavailable'}), 503


# ================================================================
# PDF Report
# ================================================================

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ================================================================
# PDF Report
# ================================================================

@app.route('/report/pdf/<int:scan_id>')
@login_required
def download_pdf(scan_id):
    """تحميل تقرير PDF احترافي"""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('dashboard'))
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        saved = json.loads(scan.raw_report or '{}')
    except (ValueError, TypeError):
        saved = {}
    if not isinstance(saved, dict) or not isinstance(saved.get('local_analysis'), dict):
        return jsonify(error='Saved analysis is unavailable. Start a new URL scan to generate a report.'), 409
    from services.url_scan_coverage import apply_url_coverage
    analysis = apply_url_coverage(saved['local_analysis'])
    from services.url_assessment import saved_assessment
    analysis['aggregate_assessment'] = saved_assessment(saved, saved['local_analysis'], saved.get('deep_analysis', {}))

    # توليد PDF
    buffer = generate_vulnerability_report(scan, analysis, current_user.username)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'MyScanner-Report-{scan.id}-{datetime.utcnow().strftime("%Y%m%d")}.pdf',
        mimetype='application/pdf'
    )
# ================================================================
# Site Scanner
# ================================================================
@app.route('/site-scanner')
@login_required
def site_scanner():
    return render_template('site_scanner.html')


@app.route('/api/site-scan', methods=['POST'])
@login_required
@check_permission('site_scan')
def api_site_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('domain'), str):
        return jsonify({'error': 'Provide an HTTP or HTTPS URL'}), 400
    if any(type(data.get(flag, False)) is not bool for flag in ('include_provider', 'include_discovery')):
        return jsonify({'error': 'Scan options must be true or false'}), 400
    from services.safe_http import reject_non_public_literal
    try:
        reject_non_public_literal(data['domain'].strip())
    except UnsafeTargetError:
        return jsonify({'error': 'The target could not be assessed under the public-network policy'}), 400
    from services.evidence_jobs import queue_evidence_job
    log_activity(current_user.username, 'site_scan', 'Read-only site evidence queued')
    return queue_evidence_job('site', {'domain': data['domain'], 'include_provider': data.get('include_provider', False),
                                       'include_discovery': data.get('include_discovery', False)})
# ================================================================
# Password Checker
# ================================================================

@app.route('/password-check')
@login_required
def password_check():
    return render_template('password_check.html')


@app.route('/api/check-password', methods=['POST'])
@login_required
def api_check_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('password'), str) or not data['password'].strip() or len(data['password']) > 128:
        return jsonify(error='Provide a password of 1-128 characters'), 400
    password = data['password']
    check_breaches = data.get('check_breaches', False)
    if not isinstance(check_breaches, bool):
        return jsonify(error='check_breaches must be true or false'), 400
    failure = reserve_request_quota('password_check')
    if failure is not None:
        return failure
    analyzer = None
    try:
        analyzer = PasswordAnalyzer()
        result = analyzer.comprehensive_analysis(password, check_breaches=check_breaches)
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        result.pop('password', None)
        log_activity(current_user.username, 'password_check', 'Checked password strength')
        return jsonify(result), 200, {'Cache-Control':'no-store'}
    except Exception:
        app.logger.error('Password analysis unavailable')
        return jsonify(error='Password analysis is temporarily unavailable. Please retry later.'), 503
    finally:
        if analyzer is not None:
            analyzer.close()

# ================================================================
# Subdomain Finder
# ================================================================

@app.route('/subdomain-finder')
@login_required
def subdomain_finder():
    return render_template('subdomain_finder.html')


@app.route('/api/subdomain-finder', methods=['POST'])
@login_required
@validate_web_scan_request('domain', 'include_ct', domain=True)
@check_permission('subdomain_finder')
def api_subdomain_finder():
    data = request.get_json(silent=True)
    from services.evidence_jobs import queue_evidence_job
    log_activity(current_user.username, 'subdomain_finder', 'Bounded domain discovery queued')
    return queue_evidence_job('subdomain_discovery', {'domain': data['domain'].strip(), 'include_ct': data.get('include_ct', True)})


# ================================================================
# Subdomain Scan API - الإصدار الجديد
# يستخدم: url.vet + التحليل المحلي
# ================================================================

@app.route('/api/scan-subdomain', methods=['POST'])
@login_required
@validate_web_scan_request('domain', 'include_provider', domain=True)
@check_permission('subdomain_finder')
def api_scan_subdomain():
    data = request.get_json(silent=True)
    from services.subdomain_finder import normalize_domain
    try:
        domain = normalize_domain(data['domain'].strip())
    except ValueError as error:
        return jsonify(error=str(error)), 400
    from services.evidence_jobs import queue_evidence_job
    log_activity(current_user.username, 'subdomain_scan', 'Read-only hostname assessment queued')
    return queue_evidence_job('subdomain_inspection', {'domain': domain, 'include_provider': data.get('include_provider', False)})

# ================================================================
# File Scanner  👈 👈 👈 أضف هنا
# ================================================================

@app.route('/file-scanner')
@login_required
def file_scanner():
    return render_template('file_scanner.html')


# ================================================================
# Other Pages
# ================================================================

@app.route('/search')
@login_required
def search():
    return render_template('search.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# ================================================================
# Contact Form Handler - Professional Version
# ================================================================

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # جلب البيانات من النموذج
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        company = request.form.get('company', '').strip()
        phone = request.form.get('phone', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        
        # التحقق من الحقول الإلزامية
        if not name or not email or not message or not subject:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('contact'))
        
        # بناء محتوى البريد الإلكتروني
        email_body = f"""
        ========================================
        NEW CONTACT MESSAGE FROM MyScanner
        ========================================
        
        📌 SUBJECT: {subject}
        
        👤 SENDER INFORMATION:
        ----------------------------------------
        Name:    {name}
        Email:   {email}
        Company: {company if company else 'Not provided'}
        Phone:   {phone if phone else 'Not provided'}
        IP:      {request.remote_addr}
        
        💬 MESSAGE:
        ----------------------------------------
        {message}
        
        ========================================
        Sent from MyScanner Contact Form
        ========================================
        """
        
        # إرسال البريد الإلكتروني
        try:
            # استخدم الدالة المساعدة التي لديك في app.py
            # send_email reports failure by returning False, not by raising.
            if not send_email(
                # Sent to the routed support address so replies default to it.
                to_email=os.getenv('CONTACT_INBOX', 'info@myscanners.com'),
                subject=f"[MyScanner Contact] {subject} from {name}",
                body=email_body,
                reply_to=email if re.fullmatch(r'[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+', email) and len(email) <= 254 else None
            ):
                raise RuntimeError('Contact email was not accepted by the mail provider.')
            # نعود برد JSON للنموذج (AJAX) بدلاً من إعادة التوجيه
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": True, "message": "Message sent successfully!"}), 200
            else:
                flash('Your message has been sent successfully! We will respond within 3 business days.', 'success')
                return redirect(url_for('contact'))
                
        except Exception as e:
            app.logger.error(f"Failed to send contact email: {e}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "error": "Failed to send message. Please try again later."}), 500
            else:
                flash('Failed to send message. Please try again later.', 'danger')
                return redirect(url_for('contact'))
    
    # عرض صفحة الاتصال (GET request)
    return render_template('contact.html')

@app.route('/domain-lookup')
@login_required
def domain_lookup():
    return render_template('domain_lookup.html')


@app.route('/api/domain-lookup', methods=['POST'])
@login_required
@check_permission('domain_lookup')
def api_domain_lookup():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('domain'), str):
        return jsonify({'error': 'A valid domain name is required'}), 400
    try:
        result = DomainAnalyzer().analyze_domain(data['domain'])
        if result.get('error'):
            return jsonify({'error': result['error']}), 400
        log_activity(current_user.username, 'domain_lookup', 'Domain metadata lookup completed')
        response = jsonify(result)
        response.headers['Cache-Control'] = 'no-store'
        return response
    except Exception:
        app.logger.error('Domain metadata lookup failed')
        return jsonify({'error': 'Domain lookup is temporarily unavailable'}), 503

@app.route('/qr-scanner')
@login_required
def qr_scanner():
    return render_template('qr_scanner.html')
@app.route('/api/scan-qr-url', methods=['POST'])
@login_required
@validate_web_scan_request('url', 'include_provider')
@check_permission('qr_scan')
def api_scan_qr_url():
    data = request.get_json(silent=True)
    try:
        result = QRAnalyzer().scan_url(data['url'], include_provider=data.get('include_provider', False))
        log_activity(current_user.username, 'qr_scan', 'Completed read-only QR URL assessment')
        return jsonify(result), 200, {'Cache-Control':'no-store'}
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except UnsafeTargetError:
        raise
    except Exception:
        app.logger.exception('QR URL assessment failed')
        return jsonify(error='QR assessment temporarily unavailable. Please retry.'), 503

@app.route('/ssl-checker')
@login_required
def ssl_checker():
    return render_template('ssl_checker.html')


@app.route('/api/ssl-checker', methods=['POST'])
@login_required
@check_permission('ssl_check')
def api_ssl_checker():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('domain'), str) or not data['domain'].strip() or len(data['domain']) > 2048:
        return jsonify(error='Provide a domain or HTTPS URL of at most 2048 characters'), 400
    try:
        result = SSLAnalyzer().analyze_certificate(data['domain'])
        log_activity(current_user.username, 'ssl_check', 'Completed TLS observation')
        return jsonify(result), 200, {'Cache-Control':'no-store'}
    except UnsafeTargetError:
        return jsonify(error='Target could not be assessed under the public-network policy'), 400
    except ValueError:
        return jsonify(error='Provide a valid public domain or website URL'), 400
    except Exception:
        app.logger.error('TLS observation unavailable')
        return jsonify(error='TLS observation is temporarily unavailable'), 503


@app.route('/dashboard-v2')
@login_required
def dashboard_v2():
    from services.account_overview import daily_allowance, scan_counts
    return render_template('dashboard-v2.html', counts=scan_counts(current_user.id),
                           allowance=daily_allowance(current_user))

# ================================================================
# AI assistant: explains saved report evidence; never decides verdicts
# ================================================================

AI_CONTEXT_DAYS = 30
AI_CONTEXTS_PER_USER = 50


@app.context_processor
def inject_ai_assistant():
    from services.ai_assistant import enabled
    return {'ai_assistant_enabled': current_user.is_authenticated and enabled()}


def _owned_ai_context(context_id):
    from models import AIContext
    if not isinstance(context_id, str) or len(context_id) != 36:
        return None
    context = db.session.get(AIContext, context_id)
    if context is None or context.user_id != current_user.id:
        return None
    return context


def _ai_json(value, default):
    try:
        data = json.loads(value or '')
    except (TypeError, ValueError):
        return default
    return data if isinstance(data, type(default)) else default


@app.route('/api/ai/contexts', methods=['POST'])
@login_required
def api_ai_create_context():
    from models import AIContext
    from services import ai_assistant
    if not ai_assistant.enabled():
        return jsonify(error='The AI assistant is not available right now.'), 503
    if (request.content_length or 0) > 1024 * 1024:
        return jsonify(error='This report is too large for the AI assistant.'), 413
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('tool') not in ai_assistant.TOOLS or not isinstance(data.get('evidence'), (dict, list)):
        return jsonify(error='Invalid AI request'), 400
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Retention: contexts expire after 30 days and each user keeps the newest 50.
    AIContext.query.filter(AIContext.created_at < now - timedelta(days=AI_CONTEXT_DAYS)).delete(synchronize_session=False)
    stale = [row.id for row in AIContext.query.filter_by(user_id=current_user.id).order_by(AIContext.created_at.desc())
             .offset(AI_CONTEXTS_PER_USER - 1).with_entities(AIContext.id).all()]
    if stale:
        AIContext.query.filter(AIContext.id.in_(stale)).delete(synchronize_session=False)
    context = AIContext(id=str(uuid.uuid4()), user_id=current_user.id, tool=data['tool'],
                        evidence=ai_assistant.sanitize_evidence(data['evidence']), explanations='{}', chat='[]', created_at=now)
    db.session.add(context)
    db.session.commit()
    return jsonify(id=context.id), 201


@app.route('/api/ai/contexts/<context_id>')
@login_required
def api_ai_get_context(context_id):
    context = _owned_ai_context(context_id)
    if context is None:
        return jsonify(error='Not found'), 404
    return jsonify(tool=context.tool, explanations=_ai_json(context.explanations, {}), chat=_ai_json(context.chat, []))


@app.route('/api/ai/contexts/<context_id>/explain', methods=['POST'])
@login_required
def api_ai_explain(context_id):
    from services import ai_assistant
    from services.daily_quota import refund_quota
    context = _owned_ai_context(context_id)
    if context is None:
        return jsonify(error='Not found'), 404
    data = request.get_json(silent=True)
    language = data.get('language') if isinstance(data, dict) else None
    if language not in ai_assistant.LANGUAGES:
        return jsonify(error='Choose Arabic or English'), 400
    explanations = _ai_json(context.explanations, {})
    if isinstance(explanations.get(language), dict):
        return jsonify(explanation=explanations[language], cached=True)
    failure = reserve_request_quota('ai_assistant')
    if failure:
        return failure
    try:
        explanation, provider = ai_assistant.explain(context.tool, context.evidence, language)
    except ai_assistant.AIUnavailable as error:
        app.logger.warning('AI explanation unavailable: %s', error)
        refund_quota(current_user.id, 'ai_assistant')
        return jsonify(error='The AI assistant could not answer right now. Your allowance was not used. Please try again in a minute.'), 503
    explanations[language] = explanation
    context.explanations = json.dumps(explanations, ensure_ascii=False)
    db.session.commit()
    log_activity(current_user.username, 'ai_assistant', f'AI explanation ({context.tool}, {language}, {provider})')
    return jsonify(explanation=explanation, cached=False)


@app.route('/api/ai/contexts/<context_id>/chat', methods=['POST'])
@login_required
def api_ai_chat(context_id):
    from services import ai_assistant
    from services.daily_quota import refund_quota
    context = _owned_ai_context(context_id)
    if context is None:
        return jsonify(error='Not found'), 404
    data = request.get_json(silent=True)
    message = data.get('message') if isinstance(data, dict) else None
    if not isinstance(message, str) or not message.strip():
        return jsonify(error='Write a question first'), 400
    message = message.strip()
    if len(message) > ai_assistant.CHAT_MESSAGE_LIMIT:
        return jsonify(error=f'Keep questions under {ai_assistant.CHAT_MESSAGE_LIMIT} characters'), 400
    history = _ai_json(context.chat, [])
    failure = reserve_request_quota('ai_assistant')
    if failure:
        return failure
    try:
        answer, provider = ai_assistant.chat(context.tool, context.evidence, history, message)
    except ai_assistant.AIUnavailable as error:
        app.logger.warning('AI chat unavailable: %s', error)
        refund_quota(current_user.id, 'ai_assistant')
        return jsonify(error='The AI assistant could not answer right now. Your allowance was not used. Please try again in a minute.'), 503
    history += [{'role': 'user', 'text': message}, {'role': 'assistant', 'text': answer}]
    context.chat = json.dumps(history[-40:], ensure_ascii=False)
    db.session.commit()
    log_activity(current_user.username, 'ai_assistant', f'AI chat ({context.tool}, {provider})')
    return jsonify(answer=answer)


@app.route('/api/url-analysis/<int:scan_id>')
@login_required
def api_url_analysis(scan_id):
    app.logger.info(f'[INFO] URL analysis requested for scan #{scan_id} by {current_user.username}')
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404
    
    url = scan.url
    domain = urlparse(url).netloc
    app.logger.info(f'[INFO] Reading saved URL analysis for scan #{scan_id}')
    
    from services.url_scan_coverage import apply_url_coverage
    try:
        saved = json.loads(scan.raw_report or '{}')
    except (ValueError, TypeError):
        saved = {}
    use_saved = isinstance(saved, dict) and isinstance(saved.get('local_analysis'), dict) and isinstance(saved.get('deep_analysis'), dict)
    if not use_saved:
        return jsonify(error='Saved analysis is unavailable. Start a new URL scan to generate a report.'), 409
    local_analysis = apply_url_coverage(saved['local_analysis'])
    deep_analysis = apply_url_coverage(saved['deep_analysis'])
    from services.url_assessment import saved_assessment
    aggregate = saved_assessment(saved, local_analysis, deep_analysis)
    app.logger.info(f'[SUCCESS] Saved URL analysis loaded for scan #{scan_id}')
    log_activity(current_user.username, 'url_analysis', f'Read saved URL report #{scan_id}')
    # تحليلات إضافية
    analysis = {
        "redirect_chain": [],
        "final_url": url,
        "cookies": [],
        "security_headers": local_analysis.get("security_headers", {}).get("headers", {}),
        "tech_stack": [],
        "whois": {},
        "geo": {},
        "similar_sites": [],
        "history_scans": [],
        # ميزات التحليل السريع
        "url_structure": local_analysis.get("structure", {}),
        "phishing_indicators": local_analysis.get("phishing", {}),
        "ssl_info": local_analysis.get("ssl", {}),
        "dns_records": local_analysis.get("dns", {}),
        "is_shortened": local_analysis.get("is_shortened", False),
        "security_score": local_analysis.get("security_score", 0),
        "aggregate_assessment": aggregate,
        "assessment_status": aggregate["coverage"],
        "assessment_warning": "; ".join(aggregate["missing_checks"]),
        "verdict": aggregate["verdict"],
        "local_verdict": local_analysis.get("local_verdict", "unknown"),
        "recommendations": local_analysis.get("recommendations", []),
        "urlvet": local_analysis.get("urlvet", {}),
        # ميزات التحليل العميق
        "deep_analysis": {
            "page_content": deep_analysis.get("page_content", {}),
            "behavior": deep_analysis.get("behavior", {}),
            "whois_deep": deep_analysis.get("whois", {}),
            "osint": deep_analysis.get("osint", {}),
            "overall_risk_score": deep_analysis.get("overall_risk_score", 0),
            "deep_verdict": deep_analysis.get("verdict", "unknown"),
            "deep_recommendations": deep_analysis.get("recommendations", [])
        }
    }
    
    return jsonify(analysis)
# ================================================================
# URL Analyzer API (Direct URL Scan)
# ================================================================

@app.route('/api/url-analyze', methods=['POST'])
@login_required
def api_url_analyze():
    """Queue a URL scan; poll status_url and read the report at result_url."""
    data = request.get_json(silent=True)
    from services.url_scan_request import queue_url_scan
    return queue_url_scan(data.get('url') if isinstance(data, dict) else None)


# ================================================================
# Run
# ================================================================
if __name__ == '__main__':
    app.run(debug=app.config["DEBUG"])





