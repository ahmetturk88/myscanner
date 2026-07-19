from extensions import db, login_manager, bcrypt
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from io import BytesIO
import requests
import threading
import time
import json
import os
import hashlib
from dotenv import load_dotenv
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
from services.file_deep_analyzer import FileDeepAnalyzer  # ✅ صحيح
from werkzeug.utils import secure_filename
from celery.result import AsyncResult
from celery_config import celery
import uuid
from tasks import scan_file_task, scan_site_task, batch_scan_task
from services.permissions import check_permission
from datetime import datetime, timedelta, timezone
from logging_config import log_activity
from services.vulnerability_scanner.scan_orchestrator import get_orchestrator
from services.vulnerability_scanner.report_generator import get_report_generator
from models.vulnerability import VulnerabilityScan, Vulnerability, ScanConfig
import resend
from typing import Optional
load_dotenv()

# ================================================================
# Initialization
# ================================================================
app = Flask(__name__)
from logging_config import setup_logging

# ================================================================
# CSRF Protection (أضيفي هذا هنا)
# ================================================================
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect()
csrf.init_app(app)


# ================================================================
# Config
# ================================================================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABSTRACT_API_KEY = os.getenv('ABSTRACT_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
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
from tasks import celery
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
with app.app_context():
    db.create_all()
    from apscheduler.schedulers.background import BackgroundScheduler

def reset_daily_scans():
    with app.app_context():
        from services.permissions import DAILY_LIMITS
        users = User.query.all()
        for user in users:
            role = user.role if user.role in DAILY_LIMITS else 'user'
            limits = DAILY_LIMITS[role]
            
            user.site_scan_remaining = limits.get('site_scan', 10)
            user.file_scan_remaining = limits.get('file_scan', 5)
            user.url_analyzer_remaining = limits.get('url_analyzer', 20)
            user.email_check_remaining = limits.get('email_check', 15)
            user.ip_check_remaining = limits.get('ip_check', 15)
            user.domain_lookup_remaining = limits.get('domain_lookup', 15)
            user.ssl_check_remaining = limits.get('ssl_check', 15)
            user.qr_scan_remaining = limits.get('qr_scan', 15)
            user.subdomain_finder_remaining = limits.get('subdomain_finder', 5)
            user.password_check_remaining = limits.get('password_check', 20)
            user.sandbox_remaining = limits.get('sandbox_analysis', 5)
            user.scans_reset_date = datetime.now(timezone.utc)
        
        db.session.commit()
        print("[SCHEDULER] Daily scans reset for all services!")
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
resend.api_key = os.getenv('RESEND_API_KEY')

# ثوابت البريد الإلكتروني
FROM_EMAIL = os.getenv('FROM_EMAIL', 'info@myscanners.com')
FROM_NAME = os.getenv('FROM_NAME', 'MyScanner Security')


def send_email(to_email: str, subject: str, body: str,
               html_body: Optional[str] = None) -> bool:
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

        resp = resend.Emails.send(params)
        app.logger.info(f"[EMAIL] Sent to {to_email} | ID: {resp.get('id')}")
        return True

    except Exception as e:
        app.logger.error(f"[EMAIL ERROR] {to_email}: {str(e)}")
        return False


def send_verification_email(user):
    token = serializer.dumps(user.email, salt='email-verify')
    base_url = os.getenv('BASE_URL', 'https://myscanners.com')
    link = f"{base_url}/verify/{token}"
    
    subject = '✅ Verify your MyScanner account'
    
    # نسخة HTML احترافية
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0;padding:0;background:#0a0a14;font-family:'Segoe UI',Arial,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
                <td align="center" style="padding:40px 20px;">
                    <table width="600" cellpadding="0" cellspacing="0" style="background:#10101a;border-radius:16px;border:1px solid #2a2a45;overflow:hidden;">
                        <tr>
                            <td style="background:linear-gradient(135deg,#00c8ff20,#006aff10);padding:32px;text-align:center;border-bottom:1px solid #2a2a45;">
                                <div style="font-size:32px;margin-bottom:8px;">🛡️</div>
                                <h1 style="margin:0;color:#00c8ff;font-family:'Courier New',monospace;font-size:24px;">MyScanner</h1>
                                <p style="margin:4px 0 0;color:#6a6a90;font-size:13px;">Advanced Cybersecurity Platform</p>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:40px 32px;">
                                <h2 style="color:#dde0f0;margin:0 0 16px;font-size:20px;">Welcome, {user.username}! 👋</h2>
                                <p style="color:#6a6a90;line-height:1.7;margin:0 0 28px;">
                                    Please verify your email address to activate your MyScanner account 
                                    and start securing your digital assets.
                                </p>
                                <div style="text-align:center;margin:32px 0;">
                                    <a href="{link}" style="display:inline-block;background:#00c8ff;color:#000;padding:14px 36px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;">
                                        ✅ Verify My Email
                                    </a>
                                </div>
                                <div style="background:#18182a;border-radius:8px;padding:16px;">
                                    <p style="color:#6a6a90;font-size:12px;margin:0 0 8px;">Or copy this link:</p>
                                    <p style="color:#00c8ff;font-size:11px;word-break:break-all;margin:0;font-family:'Courier New',monospace;">{link}</p>
                                </div>
                                <p style="color:#6a6a90;font-size:12px;margin:24px 0 0;text-align:center;">
                                    ⏰ This link expires in <strong style="color:#ffd32a;">1 hour</strong>
                                    <br>If you didn't create this account, ignore this email.
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:20px 32px;border-top:1px solid #2a2a45;text-align:center;">
                                <p style="color:#6a6a90;font-size:11px;margin:0;">
                                    © 2025 MyScanner · <a href="https://myscanners.com" style="color:#00c8ff;text-decoration:none;">myscanners.com</a>
                                    <br>info@myscanners.com
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    body_text = f"""Hello {user.username},

Please verify your email: {link}

This link expires in 1 hour.

— MyScanner Team
info@myscanners.com
"""
    
    send_email(user.email, subject, body_text, html_body=html_body)


def send_reset_email(user):
    token = serializer.dumps(user.email, salt='password-reset')
    base_url = os.getenv('BASE_URL', 'https://myscanners.com')
    link = f"{base_url}/reset-password/{token}"
    subject = '🔑 Reset your MyScanner password'
    body = f"""Hello {user.username},

Click the link below to reset your password:

{link}

This link expires in 30 minutes.

— MyScanner Team
info@myscanners.com
"""
    send_email(user.email, subject, body)

# ================================================================
# Database Models
# ================================================================

# ================================================================
# VirusTotal Logic
# ================================================================

def perform_virustotal_scan(url, api_key):
    headers = {"x-apikey": api_key}
    try:
        resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if resp.status_code not in (200, 201):
            return {"error": f"Submission failed (HTTP {resp.status_code})"}
        url_id     = resp.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}

    for _ in range(20):
        try:
            r      = requests.get(report_url, headers=headers)
            report = r.json()
            if report["data"]["attributes"].get("status") == "completed":
                break
            time.sleep(3)
        except requests.exceptions.RequestException as e:
            return {"error": f"Polling error: {str(e)}"}
    else:
        return {"error": "Scan timeout."}

    stats      = report["data"]["attributes"].get("stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif harmless > 0:
        verdict = "harmless"
    else:
        verdict = "unknown"

    return {"verdict": verdict, "raw_report": report}


def scan_in_background(scan_id, url):
    with app.app_context():
        s = db.session.get(Scan, scan_id)
        if not s:
            return
        s.status = 'running'
        db.session.commit()

    res = perform_virustotal_scan(url, API_KEY)

    with app.app_context():
        s = db.session.get(Scan, scan_id)
        if not s:
            return
        if "error" in res:
            s.status     = 'error'
            s.verdict    = 'error'
            s.result     = f"<p>❌ {res['error']}</p>"
            s.raw_report = json.dumps(res)
        else:
            s.status     = 'completed'
            s.verdict    = res['verdict']
            s.result     = f"<p>Verdict: {res['verdict']}</p>"
            s.raw_report = json.dumps(res['raw_report'])
        db.session.commit()


from routes.tip_routes import tip_bp
app.register_blueprint(tip_bp)

from routes.sandbox_routes import sandbox_bp
app.register_blueprint(sandbox_bp)
csrf.exempt(sandbox_bp)

from routes.vuln_routes import vuln_bp
app.register_blueprint(vuln_bp)
csrf.exempt(vuln_bp)  # إذا واجهت مشاكل مع CSRF

# تهيئة مصادر TIP (مرة واحدة عند بدء التشغيل)
with app.app_context():
    try:
        from services.tip_collector import TIPCollector
        collector = TIPCollector()
        collector.initialize_default_sources()
        print("[TIP] Default sources initialized")
    except Exception as e:
        print(f"[TIP] Init error: {e}")
        
# ================================================================
# Auth Routes
# ================================================================

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
        password_errors = []
        if len(password) < 8:
            password_errors.append('at least 8 characters')
        if not re.search(r'[A-Z]', password):
            password_errors.append('at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            password_errors.append('at least one lowercase letter')
        if not re.search(r'[0-9]', password):
            password_errors.append('at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_errors.append('at least one special character')
        
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
        user.url_analyzer_remaining = 20
        user.email_check_remaining = 15
        user.ip_check_remaining = 15
        user.domain_lookup_remaining = 15
        user.ssl_check_remaining = 15
        user.qr_scan_remaining = 15
        user.subdomain_finder_remaining = 5
        user.password_check_remaining = 20
        
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)


        # إرسال إيميل تأكيد (معطل)
        print(f"[DEBUG] RESEND_API_KEY = '{RESEND_API_KEY}'")
        print(f"[DEBUG] Sending to: {user.email}")
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
        return redirect(next_page or url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
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
        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=1800)
    except Exception:
        flash('Reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(request.url)

        # ✅ استخدم bcrypt من extensions
        from extensions import bcrypt
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()

        flash('Password updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/profile')
@login_required
def profile():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.date_posted.desc()).limit(10).all()
    return render_template('profile.html', scans=scans)


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
        
        # ← التحقق من الفحوصات المتبقية (حقل قديم)
        if current_user.remaining_scans <= 0:
            flash('You have reached your daily scan limit.', 'warning')
            return redirect(url_for('dashboard'))
        
        new_scan = Scan(url=url, verdict='pending', result='Pending...', user_id=current_user.id)
        db.session.add(new_scan)
        
        # ← خصم فحص
        current_user.remaining_scans -= 1
        db.session.commit()
        
        t = threading.Thread(target=scan_in_background, args=(new_scan.id, url), daemon=True)
        t.start()
        return redirect(url_for('result_page', scan_id=new_scan.id))

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

    return jsonify({
        "id": scan.id, "url": scan.url,
        "status": scan.status, "verdict": scan.verdict,
        "result_html": scan.result, "raw_report": raw,
        "date": scan.date_posted.strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/api/recent_scans')
@login_required
def api_recent_scans():
    if current_user.is_admin:
        scans = Scan.query.order_by(Scan.date_posted.desc()).limit(15).all()
    else:
        scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.date_posted.desc()).limit(15).all()

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
    """فحص عدة إيميلات دفعة واحدة (Bulk Check)"""
    data = request.get_json()
    emails = data.get('emails', [])
    
    if not emails or not isinstance(emails, list):
        return jsonify({"error": "Please provide a list of emails"}), 400
    
    if len(emails) > 100:
        return jsonify({"error": "Maximum 100 emails per bulk request"}), 400
    
    checker = AdvancedEmailChecker(redis_client)
    results = []
    
    for email in emails[:20]:  # حد أقصى 20 في الطلب الواحد لتجنب التأخير
        result = checker.check_all(email.strip())
        results.append({
            "email": result.get("email", email),
            "valid": result.get("valid", False),
            "verdict": result.get("verdict", "unknown"),
            "quality_score": result.get("quality_score", 0),
            "is_disposable": result.get("is_disposable", False),
            "deliverability": result.get("deliverability", "unknown")
        })
    
    # إحصائيات
    stats = {
        "total": len(results),
        "valid": sum(1 for r in results if r["valid"]),
        "invalid": sum(1 for r in results if not r["valid"]),
        "disposable": sum(1 for r in results if r.get("is_disposable", False)),
        "safe": sum(1 for r in results if r.get("verdict") == "safe"),
        "average_score": sum(r.get("quality_score", 0) for r in results) / len(results) if results else 0
    }
    
    return jsonify({
        "stats": stats,
        "results": results
    })

# ================================================================
# File Scanner API
# ================================================================

@app.route('/api/scan-file', methods=['POST'])
@login_required
@check_permission('file_scan')
def api_scan_file():
    """API الموحد لفحص الملفات (VirusTotal + التحليل العميق)"""
    
    app.logger.info(f'[INFO] File scan requested by {current_user.username}')
    
    if 'file' not in request.files:
        app.logger.warning(f'[WARNING] No file provided by {current_user.username}')
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        app.logger.warning(f'[WARNING] Empty filename from {current_user.username}')
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_file(file.filename):
        app.logger.warning(f'[WARNING] Unallowed file type: {file.filename} by {current_user.username}')
        return jsonify({"error": f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400
    
    try:
        file_content = file.read()
        file_size = len(file_content)
        
        if file_size > MAX_FILE_SIZE:
            app.logger.warning(f'[WARNING] File too large: {file_size} bytes by {current_user.username}')
            return jsonify({"error": f"File too large. Max: {MAX_FILE_SIZE // 1024 // 1024} MB"}), 400
        
        filename = secure_filename(file.filename)
        app.logger.info(f'[INFO] Processing file: {filename} ({file_size} bytes) by {current_user.username}')
        
        # 1. التحليل العميق المحلي
        analyzer = FileDeepAnalyzer(use_exiftool=True)
        deep_result = analyzer.comprehensive_analysis(file_content, filename)
        
        # 2. تحليل VirusTotal
        vt_result = {"verdict": "unknown", "stats": {}, "threats": []}
        if API_KEY:
            try:
                headers = {"x-apikey": API_KEY}
                files = {'file': (filename, file_content)}
                upload_resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=30)
                
                if upload_resp.status_code in (200, 201):
                    analysis_id = upload_resp.json().get("data", {}).get("id", "")
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    
                    for _ in range(20):
                        time.sleep(2)
                        analysis_resp = requests.get(analysis_url, headers=headers, timeout=30)
                        if analysis_resp.status_code == 200:
                            analysis_data = analysis_resp.json()
                            if analysis_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                                attr = analysis_data["data"]["attributes"]
                                stats = attr.get("stats", {})
                                results = attr.get("results", {})
                                
                                malicious = stats.get("malicious", 0)
                                suspicious = stats.get("suspicious", 0)
                                total_engines = sum(stats.values())
                                
                                threats = []
                                for engine, data in results.items():
                                    if data.get("category") in ("malicious", "suspicious"):
                                        threats.append({"engine": engine, "result": data.get("result"), "category": data.get("category")})
                                
                                vt_result = {
                                    "verdict": "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean",
                                    "malicious": malicious,
                                    "suspicious": suspicious,
                                    "harmless": stats.get("harmless", 0),
                                    "undetected": stats.get("undetected", 0),
                                    "total_engines": total_engines,
                                    "detection_rate": round((malicious + suspicious) / total_engines * 100, 2) if total_engines > 0 else 0,
                                    "threats": threats[:20]
                                }
                                break
            except Exception as e:
                vt_result["error"] = str(e)
        
        # دمج النتائج
        deep_result["virustotal"] = vt_result
        
        # تحديث درجة الأمان بناءً على VT
        if vt_result.get("verdict") == "malicious":
            deep_result["security_score"] = max(0, deep_result["security_score"] - 50)
        elif vt_result.get("verdict") == "suspicious":
            deep_result["security_score"] = max(0, deep_result["security_score"] - 25)
            
        # تحديث الحكم النهائي بناءً على النتيجة الجديدة
        score = deep_result["security_score"]
        if score >= 80:
            deep_result["verdict"] = "safe"
        elif score >= 60:
            deep_result["verdict"] = "suspicious"
        elif score >= 30:
            deep_result["verdict"] = "high_risk"
        else:
            deep_result["verdict"] = "malicious"
        
        app.logger.info(f'[SUCCESS] File scan completed for {filename} | Score: {deep_result["security_score"]} | Verdict: {deep_result["verdict"]}')
        log_activity(current_user.username, 'file_scan', f'Scanned file: {filename} | Verdict: {deep_result.get("verdict")}')
        return jsonify(deep_result)
        
    except Exception as e:
        app.logger.error(f'[ERROR] File scan failed for {current_user.username}: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan error: {str(e)}"}), 500
        
# ================================================================
# File Deep Analysis API
# ================================================================

@app.route('/api/file-deep-analysis', methods=['POST'])
@login_required
def api_file_deep_analysis():
    """API للتحليل العميق للملفات مع exiftool"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        file_content = file.read()
        filename = file.filename
        
        # ✅ التعديل هنا: إضافة use_exiftool=True
        analyzer = FileDeepAnalyzer(use_exiftool=True)
        result = analyzer.comprehensive_analysis(file_content, filename)
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
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
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # حفظ الملف مؤقتاً
    task_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_FOLDER, f"{task_id}_{file.filename}")
    file.save(temp_path)
    
    # بدء المهمة في الخلفية
    task = scan_file_task.delay(temp_path, file.filename, current_user.id)
    
    return jsonify({
        "task_id": task.id,
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
        response = {
            'state': 'SUCCESS',
            'status': 'Task completed successfully',
            'result': task.result,
            'progress': 100
        }
    elif task.state == 'FAILURE':
        response = {
            'state': 'FAILURE',
            'status': 'Task failed',
            'error': str(task.info),
            'progress': 0
        }
    else:
        response = {
            'state': task.state,
            'status': 'Unknown state',
            'progress': 0
        }
    
    return jsonify(response)


# ================================================================
# API: بدء فحص موقع غير متزامن
# ================================================================

@app.route('/api/async-scan-site', methods=['POST'])
@login_required
def async_scan_site():
    app.logger.info(f'[INFO] Site scan requested by {current_user.username}')
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        app.logger.warning(f'⚠️ No domain provided by {current_user.username}')
        return jsonify({"error": "No domain provided"}), 400
    
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
    task = scan_site_task.delay(domain, current_user.id, new_scan.id)
    
    app.logger.info(f'[SUCCESS] Async scan started for {domain} | Task ID: {task.id}')
    
    return jsonify({
        "task_id": task.id,
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
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls or len(urls) > 20:
        return jsonify({"error": "Provide 1-20 URLs"}), 400
    
    task = batch_scan_task.delay(urls, current_user.id)
    
    return jsonify({
        "task_id": task.id,
        "total_urls": len(urls),
        "status": "started",
        "message": f"Batch scan of {len(urls)} URLs started"
    })
    
# Removed redundant and broken scan-file route

# ================================================================
# Admin
# ================================================================

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
    return render_template('email_check.html')


@app.route('/api/check-email', methods=['POST'])
@login_required
@check_permission('email_check')
def api_check_email():
    app.logger.info(f'[INFO] Email check requested by {current_user.username}')

    data = request.get_json()
    email = data.get('email', '').strip()

    if not email:
        app.logger.warning(f'[WARNING] No email provided by {current_user.username}')
        return jsonify({"error": "No email provided"}), 400

    app.logger.info(f'[INFO] Checking email: {email} | User: {current_user.username}')

    try:
        checker = AdvancedEmailChecker(redis_client)
        result = checker.check_all(email)

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
            "is_mx": result["dns"]["mx"]["exists"],
            "is_smtp": result["smtp"]["valid"],
            "deliverability": result["deliverability"],
            "quality_score": result["quality_score"] / 100,
            "address_risk": result["verdict"],
            "total_breaches": 0,
            "last_breached": None,
            "breached_domains": [],
            "domain_age": result["domain_info"].get("age_days", 0),
            "registrar": result["domain_info"].get("registrar", "Unknown"),
            "spf_record": result["dns"]["spf"]["record"],
            "spf_valid": result["dns"]["spf"]["exists"],
            "dkim_record": None,
            "dkim_valid": False,
            "dmarc_record": result["dns"]["dmarc"]["record"],
            "dmarc_valid": result["dns"]["dmarc"]["exists"],
            "blacklisted": result["blacklist"]["is_blacklisted"],
            "blacklist_count": len(result["blacklist"].get("blacklisted_on", [])),
            "blacklist_results": result["blacklist"].get("blacklisted_on", []),
            "smtp_details": result["smtp"],
            "quality_breakdown": {
                "score": result["quality_score"],
                "smtp_valid": result["smtp"]["valid"],
                "no_disposable": not result["is_disposable"],
                "not_blacklisted": not result["blacklist"]["is_blacklisted"],
                "spf_exists": result["dns"]["spf"]["exists"],
                "dmarc_exists": result["dns"]["dmarc"]["exists"]
            },
            "format_suggestions": result.get("format_suggestions", [])
        })

    except Exception as e:
        app.logger.error(f'[ERROR] Email check failed for {email}: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Check error: {str(e)}"}), 500


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
    app.logger.info(f'[INFO] IP check requested by {current_user.username}')
    
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        app.logger.warning(f'[WARNING] No IP provided by {current_user.username}')
        return jsonify({"error": "No IP provided"}), 400
    
    app.logger.info(f'[INFO] Analyzing IP: {ip} | User: {current_user.username}')
    
    try:
        analyzer = IPAnalyzer()
        result = analyzer.analyze_ip(ip, ABUSEIPDB_API_KEY)
        
        if "error" in result:
            app.logger.warning(f'[WARNING] IP analysis error for {ip}: {result["error"]}')
            return jsonify({"error": result["error"]}), 400
        
        app.logger.info(f'[SUCCESS] IP analysis completed for {ip} | Verdict: {result.get("verdict")}')
        log_activity(current_user.username, 'ip_check', f'Checked IP: {ip} | Verdict: {result.get("verdict")}')
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f'[ERROR] IP check failed for {ip}: {str(e)}')
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500


# ================================================================
# PDF Report
# ================================================================

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.enums import TA_CENTER, TA_LEFT

@app.route('/report/pdf/<int:scan_id>')
@login_required
def download_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash('Scan not found.', 'danger')
        return redirect(url_for('dashboard'))
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    raw = {}
    try:
        if scan.raw_report:
            raw = json.loads(scan.raw_report)
    except:
        pass

    stats = raw.get('data', {}).get('attributes', {}).get('stats', {})
    results = raw.get('data', {}).get('attributes', {}).get('results', {})
    h = stats.get('harmless', 0)
    m = stats.get('malicious', 0)
    sus = stats.get('suspicious', 0)
    u = stats.get('undetected', 0)
    total = h + m + sus + u
    risk = round(((m * 3 + sus * 2) / (total * 3)) * 100) if total > 0 else 0

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm, topMargin=2*cm, bottomMargin=1.5*cm, allowSplitting=1)
    elements = []

    accent = colors.HexColor('#00c8ff')
    dark_bg = colors.HexColor('#0a0a14')
    card_bg = colors.HexColor('#141425')
    green = colors.HexColor('#00e676')
    red = colors.HexColor('#ff4560')
    yellow = colors.HexColor('#ffd32a')
    white = colors.HexColor('#dde0f0')
    muted = colors.HexColor('#6a6a90')
    border = colors.HexColor('#2a2a45')

    title_style = ParagraphStyle('title', fontSize=26, fontName='Helvetica-Bold', textColor=accent, alignment=TA_CENTER, spaceAfter=4)
    sub_style = ParagraphStyle('sub', fontSize=10, fontName='Helvetica', textColor=muted, alignment=TA_CENTER, spaceAfter=16)
    section_style = ParagraphStyle('sec', fontSize=12, fontName='Helvetica-Bold', textColor=accent, spaceBefore=20, spaceAfter=10, alignment=TA_LEFT)
    text_style = ParagraphStyle('txt', fontSize=9, fontName='Helvetica', textColor=white, leading=14)
    small_style = ParagraphStyle('sm', fontSize=8, fontName='Courier', textColor=white)
    tiny_style = ParagraphStyle('ty', fontSize=7, fontName='Courier', textColor=muted)
    footer_style = ParagraphStyle('ft', fontSize=7, fontName='Helvetica', textColor=muted, alignment=TA_CENTER)
    verdict_style = ParagraphStyle('v', fontSize=16, fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=12)
    score_style = ParagraphStyle('score', fontSize=12, fontName='Helvetica', textColor=muted, alignment=TA_CENTER, spaceAfter=16)

    elements.append(Spacer(1, 10))
    elements.append(Paragraph('🛡️ MyScanner', title_style))
    elements.append(Paragraph('Security Scan Report', sub_style))
    elements.append(HRFlowable(width="90%", thickness=1, color=accent, spaceBefore=0, spaceAfter=12))

    v_map = {'harmless': ('✅ HARMLESS', green), 'malicious': ('🚨 MALICIOUS', red), 'suspicious': ('⚠️ SUSPICIOUS', yellow)}
    v_text, v_color = v_map.get(scan.verdict, ('❓ UNKNOWN', muted))
    verdict_style.textColor = v_color
    elements.append(Paragraph(v_text, verdict_style))
    elements.append(Paragraph(f'Risk Score: {risk}%', score_style))

    elements.append(Paragraph('📋 SCAN INFORMATION', section_style))
    info_data = [
        [Paragraph('Scan ID', small_style), Paragraph(f'#{scan.id}', text_style)],
        [Paragraph('URL', small_style), Paragraph(scan.url[:80], tiny_style)],
        [Paragraph('Status', small_style), Paragraph(scan.status.upper(), text_style)],
        [Paragraph('Date', small_style), Paragraph(scan.date_posted.strftime('%Y-%m-%d %H:%M UTC'), tiny_style)],
        [Paragraph('User', small_style), Paragraph(current_user.username, text_style)],
        [Paragraph('Risk Score', small_style), Paragraph(f'{risk}%', text_style)],
    ]
    info_table = Table(info_data, colWidths=[3.5*cm, 12.5*cm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), card_bg), ('TEXTCOLOR', (0,0), (0,-1), muted),
        ('TEXTCOLOR', (1,0), (1,-1), white), ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7), ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.5, border),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 14))

    elements.append(Paragraph('📊 SCAN STATISTICS', section_style))
    stats_data = [
        [Paragraph('HARMLESS', small_style), Paragraph('MALICIOUS', small_style), Paragraph('SUSPICIOUS', small_style), Paragraph('UNDETECTED', small_style)],
        [Paragraph(str(h), ParagraphStyle('b1', fontSize=22, fontName='Helvetica-Bold', textColor=green, alignment=TA_CENTER)),
         Paragraph(str(m), ParagraphStyle('b2', fontSize=22, fontName='Helvetica-Bold', textColor=red, alignment=TA_CENTER)),
         Paragraph(str(sus), ParagraphStyle('b3', fontSize=22, fontName='Helvetica-Bold', textColor=yellow, alignment=TA_CENTER)),
         Paragraph(str(u), ParagraphStyle('b4', fontSize=22, fontName='Helvetica-Bold', textColor=white, alignment=TA_CENTER))],
    ]
    stats_table = Table(stats_data, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), card_bg), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 10), ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, border),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 14))

    elements.append(Paragraph('🎯 THREAT DISTRIBUTION', section_style))
    drawing = Drawing(250, 160)
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 60, 15, 130, 130
    pie.data = [max(h,1), max(m,1), max(sus,1), max(u,1)]
    pie.labels = ['Harmless', 'Malicious', 'Suspicious', 'Undetected']
    pie.slices[0].fillColor = green; pie.slices[1].fillColor = red
    pie.slices[2].fillColor = yellow; pie.slices[3].fillColor = muted
    pie.slices.strokeWidth = 1; pie.slices.strokeColor = dark_bg
    pie.slices.popout = 3; pie.sideLabels = True; pie.simpleLabels = False
    drawing.add(pie)
    elements.append(drawing)
    elements.append(Spacer(1, 16))

    elements.append(Paragraph('🔍 ENGINE RESULTS', section_style))
    engine_rows = [[Paragraph('Engine', small_style), Paragraph('Category', small_style), Paragraph('Result', small_style)]]
    for name, info in list(results.items())[:10]:
        cat = info.get('category', 'undetected').upper()
        res = str(info.get('result', 'N/A'))[:40]
        engine_rows.append([Paragraph(name[:25], tiny_style), Paragraph(cat, tiny_style), Paragraph(res, tiny_style)])
    engine_table = Table(engine_rows, colWidths=[5.5*cm, 4*cm, 6.5*cm])
    engine_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), dark_bg), ('TEXTCOLOR', (0,0), (-1,0), accent),
        ('BACKGROUND', (0,1), (-1,-1), card_bg), ('TEXTCOLOR', (0,1), (-1,-1), white),
        ('TOPPADDING', (0,0), (-1,-1), 5), ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8), ('GRID', (0,0), (-1,-1), 0.5, border),
    ]))
    elements.append(engine_table)
    elements.append(Spacer(1, 20))

    elements.append(HRFlowable(width="90%", thickness=0.5, color=border))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f'Generated by MyScanner · {scan.date_posted.strftime("%Y-%m-%d %H:%M")} UTC · Ahmed Sairafi', footer_style))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f'myscanner-report-{scan.id}.pdf', mimetype='application/pdf')

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
    """API متطور لفحص المواقع الإلكترونية"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    app.logger.info(f'[INFO] Site scan requested by {current_user.username}')

    
    try:
        analyzer = SiteAnalyzer()
        result = analyzer.comprehensive_analysis(domain)
        
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        
        app.logger.info(f'[SUCCESS] Site scan completed for {domain} | Score: {result.get("security_score")}')

        log_activity(current_user.username, 'site_scan', f'Scanned domain: {domain}')

        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f'[ERROR] Site scan failed for {domain}: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500
# ================================================================
# Password Checker
# ================================================================

@app.route('/password-check')
@login_required
def password_check():
    return render_template('password_check.html')


@app.route('/api/check-password', methods=['POST'])
@login_required
@check_permission('password_check')
def api_check_password():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "No password provided"}), 400
    
    show_password = data.get('show_password', False)
    
    try:
        analyzer = PasswordAnalyzer()
        result = analyzer.comprehensive_analysis(password)
        
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        
        result.pop('password', None)
        log_activity(current_user.username, 'password_check', f'Checked password strength')
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500  # ← داخل الـ except

# ================================================================
# Subdomain Finder
# ================================================================

@app.route('/subdomain-finder')
@login_required
def subdomain_finder():
    return render_template('subdomain_finder.html')


@app.route('/api/subdomain-finder', methods=['POST'])
@login_required
@check_permission('subdomain_finder')
def api_subdomain_finder():
    """API لاكتشاف النطاقات الفرعية"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    try:
        finder = SubdomainFinder()
        result = finder.find_subdomains(domain)
        log_activity(current_user.username, 'subdomain_finder', f'Found subdomains for: {domain}')
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500


@app.route('/api/scan-subdomain', methods=['POST'])
@login_required
def api_scan_subdomain():
    """فحص نطاق فرعي عبر VirusTotal"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    try:
        headers = {"x-apikey": API_KEY}
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": f"https://{domain}"},
            timeout=30
        )
        
        if resp.status_code not in (200, 201):
            return jsonify({"verdict": "unknown", "error": f"Submit failed: {resp.status_code}"})
        
        url_id = resp.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        
        for _ in range(10):
            time.sleep(2)
            r = requests.get(analysis_url, headers=headers, timeout=30)
            if r.status_code == 200:
                result = r.json()
                status = result.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
        else:
            return jsonify({"verdict": "unknown", "error": "Timeout"})
        
        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        return jsonify({"verdict": verdict})
        
    except Exception as e:
        return jsonify({"verdict": "unknown", "error": str(e)})
    
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
            send_email(
                to_email="ahmetsayrafi538213@gmail.com",
                subject=f"[MyScanner Contact] {subject} from {name}",
                body=email_body
            )
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
    app.logger.info(f'[INFO] Domain lookup requested by {current_user.username}')

    data = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        app.logger.warning(f'[WARNING] No domain provided by {current_user.username}')
        return jsonify({"error": "No domain provided"}), 400

    app.logger.info(f'[INFO] Analyzing domain: {domain} | User: {current_user.username}')

    try:
        analyzer = DomainAnalyzer()
        result = analyzer.analyze_domain(domain)

        if "error" in result:
            app.logger.warning(f'[WARNING] Domain analysis error for {domain}: {result["error"]}')
            return jsonify({"error": result["error"]}), 400

        app.logger.info(f'[SUCCESS] Domain lookup completed for {domain} | IP: {result.get("ip")} | Registrar: {result.get("registrar")}')
        log_activity(
            current_user.username,
            'domain_lookup',
            f'Looked up domain: {domain} | IP: {result.get("ip")}'
        )

        return jsonify(result)

    except Exception as e:
        app.logger.error(f'[ERROR] Domain lookup failed for {domain}: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500

@app.route('/qr-scanner')
@login_required
def qr_scanner():
    return render_template('qr_scanner.html')
@app.route('/api/scan-qr-url', methods=['POST'])
@login_required
@check_permission('qr_scan')
def api_scan_qr_url():
    app.logger.info(f'[INFO] QR scan requested by {current_user.username}')

    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        app.logger.warning(f'[WARNING] No URL provided by {current_user.username}')
        return jsonify({"error": "No URL provided"}), 400

    app.logger.info(f'[INFO] Scanning QR URL: {url[:100]} | User: {current_user.username}')

    try:
        analyzer = QRAnalyzer()
        result = analyzer.scan_url(url, API_KEY)

        app.logger.info(f'[SUCCESS] QR scan completed for {url[:100]} | Verdict: {result.get("verdict")}')
        log_activity(
            current_user.username,
            'qr_scan',
            f'Scanned QR URL: {url[:100]} | Verdict: {result.get("verdict")}'
        )

        return jsonify(result)

    except Exception as e:
        app.logger.error(f'[ERROR] QR scan failed for {url[:100]}: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan error: {str(e)}"}), 500
    
@app.route('/ssl-checker')
@login_required
def ssl_checker():
    return render_template('ssl_checker.html')


@app.route('/api/ssl-checker', methods=['POST'])
@login_required
@check_permission('ssl_check')
def api_ssl_checker():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    analyzer = SSLAnalyzer()
    result = analyzer.analyze_certificate(domain)
    log_activity(current_user.username, 'ssl_check', f'Checked SSL for: {domain}')
    return jsonify(result)


@app.route('/dashboard-v2')
@login_required
def dashboard_v2():
    return render_template('dashboard-v2.html')

@app.route('/api/url-analysis/<int:scan_id>')
@login_required
def api_url_analysis(scan_id):
    app.logger.info(f'[INFO] URL analysis requested for scan #{scan_id} by {current_user.username}')
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404
    
    url = scan.url
    domain = urlparse(url).netloc
    app.logger.info(f'[INFO] Starting URL deep analysis for: {url}')
    
    # استخدام المحلل المدمج (يحل محل URLAnalyzer و URLDeepAnalyzer)
    analyzer = URLDeepAnalyzer()
    
    # تحليل سريع (بدون جلب محتوى الصفحة)
    local_analysis = analyzer.comprehensive_analysis(url)

    # تحليل عميق (مع جلب محتوى الصفحة)
    deep_analysis = analyzer.comprehensive_deep_analysis(url)
    app.logger.info(f'[SUCCESS] URL analysis completed for {url} | Score: {local_analysis.get("security_score")} | Verdict: {local_analysis.get("verdict")}')
    log_activity(current_user.username, 'url_analysis', f'Analyzed URL: {url}')
    # تحليلات إضافية
    analysis = {
        "redirect_chain": [],
        "final_url": url,
        "cookies": [],
        "security_headers": local_analysis.get("security_headers", {}).get("headers", {}),
        "tech_stack": [],
        "screenshot": f"https://image.thum.io/get/1024x768/crop/{url}",
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
        "verdict": local_analysis.get("verdict", "unknown"),
        "recommendations": local_analysis.get("recommendations", []),
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
    
    # جمع الـ cookies
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        for r in resp.history:
            analysis["redirect_chain"].append({"url": r.url, "status_code": r.status_code})
        analysis["final_url"] = resp.url
        
        for cookie in resp.cookies:
            analysis["cookies"].append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "domain": cookie.domain or 'N/A'
            })
    except:
        pass
    
    # WHOIS (إضافي)
    try:
        whois_resp = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&apiKey=at_free_demo_key&outputFormat=JSON", timeout=10)
        if whois_resp.status_code == 200:
            w = whois_resp.json().get("WhoisRecord", {})
            analysis["whois"] = {
                "registrar": w.get("registrarName", "N/A"),
                "created": (w.get("createdDate") or "N/A")[:10],
                "expires": (w.get("expiresDate") or "N/A")[:10],
            }
    except:
        pass
    
    # Geo
    try:
        geo_resp = requests.get(f"http://ip-api.com/json/{domain}", timeout=10)
        if geo_resp.status_code == 200:
            g = geo_resp.json()
            if g.get("status") != "fail":
                analysis["geo"] = {"lat": g.get("lat"), "lon": g.get("lon"), "city": g.get("city", ""), "country": g.get("country", "")}
    except:
        pass
    
    # History Scans
    try:
        history = Scan.query.filter(Scan.url.contains(domain)).order_by(Scan.date_posted.desc()).limit(10).all()
        analysis["history_scans"] = [{"id": s.id, "verdict": s.verdict, "date": s.date_posted.strftime("%Y-%m-%d")} for s in history]
    except:
        pass
    
    return jsonify(analysis)
# ================================================================
# URL Analyzer API (Direct URL Scan)
# ================================================================

@app.route('/api/url-analyze', methods=['POST'])
@login_required
@check_permission('url_analyzer')
def api_url_analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    app.logger.info(f'[INFO] URL analysis requested for: {url}')
    
    try:
        analyzer = URLDeepAnalyzer()
        result = analyzer.comprehensive_analysis(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
csrf.exempt(api_scan_file)
csrf.exempt(api_site_scan)
csrf.exempt(api_check_email)
csrf.exempt(api_check_ip)
csrf.exempt(api_domain_lookup)
csrf.exempt(api_ssl_checker)
csrf.exempt(api_scan_qr_url)
csrf.exempt(api_check_password)
csrf.exempt(api_subdomain_finder)
csrf.exempt(api_url_analyze)


# ================================================================
# Fix missing database columns for production (Render/PostgreSQL only)
# ================================================================
with app.app_context():
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if 'postgresql' in db_uri or 'postgres' in db_uri:
        from sqlalchemy import text
        cols = [
            ('last_login', 'TIMESTAMP'),
            ("role", "VARCHAR(20) DEFAULT 'user'"),
            ('remaining_scans', 'INTEGER DEFAULT 20'),
            ('scans_reset_date', 'TIMESTAMP'),
            ('site_scan_remaining', 'INTEGER DEFAULT 10'),
            ('file_scan_remaining', 'INTEGER DEFAULT 10'),
            ('url_analyzer_remaining', 'INTEGER DEFAULT 20'),
            ('email_check_remaining', 'INTEGER DEFAULT 15'),
            ('ip_check_remaining', 'INTEGER DEFAULT 15'),
            ('domain_lookup_remaining', 'INTEGER DEFAULT 15'),
            ('ssl_check_remaining', 'INTEGER DEFAULT 15'),
            ('qr_scan_remaining', 'INTEGER DEFAULT 15'),
            ('subdomain_finder_remaining', 'INTEGER DEFAULT 5'),
            ('password_check_remaining', 'INTEGER DEFAULT 20'),
            ('sandbox_remaining', 'INTEGER DEFAULT 5'),
            ('is_admin', 'BOOLEAN DEFAULT FALSE'),
        ]
        for col, typ in cols:
            try:
                db.session.execute(text(f'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS {col} {typ}'))
                print(f'[DB] OK: {col}')
            except Exception as e:
                print(f'[DB] SKIP {col}: {e}')
        db.session.commit()
        print('[DB] PostgreSQL columns check done!')

        
# ================================================================
# Run
# ================================================================
if __name__ == '__main__':
    app.run(debug=True)