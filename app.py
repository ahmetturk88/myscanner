from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
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
from services.file_analyzer import FileAnalyzer
from services.site_analyzer import SiteAnalyzer
from services.url_analyzer import URLAnalyzer
from services.subdomain_finder import SubdomainFinder
from services.password_analyzer import PasswordAnalyzer
from models import User, Scan
from extensions import db, login_manager
from services.ip_analyzer import IPAnalyzer
from services.domain_analyzer import DomainAnalyzer
from services.ssl_analyzer import SSLAnalyzer
from services.qr_analyzer import QRAnalyzer
load_dotenv()

# ================================================================
# Initialization
# ================================================================
app = Flask(__name__)

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

# ================================================================
# Extensions
# ================================================================

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")
# ================================================================
# Email Helper (Resend API)
# ================================================================

import base64

def send_email_via_resend(to_email, subject, body):
    """إرسال إيميل عبر Resend API"""
    if not RESEND_API_KEY:
        print("[RESEND] No API key configured")
        return False
    
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": "MyScanner <ahmetsayrafi538213@gmail.com>",
                "to": [to_email],
                "subject": subject,
                "text": body
            }
        )
        if resp.status_code in (200, 201):
            print(f"[RESEND SUCCESS] Email sent to {to_email}")
            return True
        else:
            print(f"[RESEND ERROR] {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[RESEND ERROR] {e}")
        return False

def send_verification_email(user):
    token = serializer.dumps(user.email, salt='email-verify')
    link  = url_for('verify_email', token=token, _external=True)
    subject = '✅ Verify your MyScanner account'
    body = f"""Hello {user.username},

Please click the link below to verify your email address:

{link}

This link expires in 1 hour.

— MyScanner Team
"""
    send_email_via_resend(user.email, subject, body)

def send_reset_email(user):
    token = serializer.dumps(user.email, salt='password-reset')
    link  = url_for('reset_password', token=token, _external=True)
    subject = '🔑 Reset your MyScanner password'
    body = f"""Hello {user.username},

Click the link below to reset your password:

{link}

This link expires in 30 minutes.

— MyScanner Team
"""
    send_email_via_resend(user.email, subject, body)


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

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        user.is_verified = True
        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
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

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Please verify your email before logging in.', 'warning')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
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
        confirm  = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(request.url)

        user.set_password(password)
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
        new_scan = Scan(url=url, verdict='pending', result='Pending...', user_id=current_user.id)
        db.session.add(new_scan)
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


# ================================================================
# Email Check
# ================================================================

@app.route('/email-check')
@login_required
def email_check():
    return render_template('email_check.html')


@app.route('/api/check-email', methods=['POST'])
@login_required
def api_check_email():
    """API متطور لفحص الإيميلات مع جميع الميزات الجديدة"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({"error": "No email provided"}), 400
    
    # استخدام الفاحص المتقدم
    checker = AdvancedEmailChecker(redis_client)
    result = checker.check_all(email)
    
    if not result.get("valid"):
        return jsonify({
            "error": result.get("error", "Invalid email format"),
            "suggestions": result.get("suggestions", [])
        }), 400
    
    # إعادة النتائج بصيغة متوافقة مع الواجهة الحالية مع ميزات إضافية
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
        "total_breaches": 0,  # API خارجي للـ breaches
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


# ================================================================
# IP Check
# ================================================================

@app.route('/ip-check')
@login_required
def ip_check():
    return render_template('ip_check.html')


@app.route('/api/check-ip', methods=['POST'])
@login_required
def api_check_ip():
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    analyzer = IPAnalyzer()
    result = analyzer.analyze_ip(ip, ABUSEIPDB_API_KEY)
    
    if "error" in result:
        return jsonify({"error": result["error"]}), 400
    
    return jsonify(result)


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
def api_site_scan():
    """API متطور لفحص المواقع الإلكترونية"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    try:
        analyzer = SiteAnalyzer()
        result = analyzer.comprehensive_analysis(domain)
        
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        
        return jsonify(result)
        
    except Exception as e:
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
def api_check_password():
    """API متطور لفحص قوة كلمات المرور"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "No password provided"}), 400
    
    # تحديد إذا كان يجب إظهار الكلمة (لن نعرضها أبداً)
    show_password = data.get('show_password', False)
    
    try:
        analyzer = PasswordAnalyzer()
        result = analyzer.comprehensive_analysis(password)
        
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        
        # لا نرسل كلمة المرور أبداً في الـ response
        result.pop('password', None)
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500

# ================================================================
# Subdomain Finder
# ================================================================

@app.route('/subdomain-finder')
@login_required
def subdomain_finder():
    return render_template('subdomain_finder.html')


@app.route('/api/subdomain-finder', methods=['POST'])
@login_required
def api_subdomain_finder():
    """API لاكتشاف النطاقات الفرعية"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    try:
        finder = SubdomainFinder()
        result = finder.find_subdomains(domain)
        
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

@app.route('/contact')
def contact():
    return render_template('contact.html')


    # قائمة subdomains شائعة + المجال
    common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'shop', 'api', 'dev', 'admin', 'portal', 'cdn', 'remote', 'vpn', 'support', 'status', 'web', 'app', 'cloud', 'mail2', 'owa', 'exchange', 'demo', 'staging', 'beta']
    
    for sub in common_subs:
        subdomains.add(f"{sub}.{domain}")

    subdomains = sorted(list(subdomains))[:30]
    results = [{"domain": sub, "verdict": "found"} for sub in subdomains]

    return jsonify({"total": len(results), "subdomains": results})


@app.route('/domain-lookup')
@login_required
def domain_lookup():
    return render_template('domain_lookup.html')


@app.route('/api/domain-lookup', methods=['POST'])
@login_required
def api_domain_lookup():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    analyzer = DomainAnalyzer()
    result = analyzer.analyze_domain(domain)
    
    return jsonify(result)

@app.route('/qr-scanner')
@login_required
def qr_scanner():
    return render_template('qr_scanner.html')
@app.route('/api/scan-qr-url', methods=['POST'])
@login_required
def api_scan_qr_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    analyzer = QRAnalyzer()
    result = analyzer.scan_url(url, API_KEY)
    
    return jsonify(result)
    
@app.route('/ssl-checker')
@login_required
def ssl_checker():
    return render_template('ssl_checker.html')


@app.route('/api/ssl-checker', methods=['POST'])
@login_required
def api_ssl_checker():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    analyzer = SSLAnalyzer()
    result = analyzer.analyze_certificate(domain)
    
    return jsonify(result)


@app.route('/dashboard-v2')
@login_required
def dashboard_v2():
    return render_template('dashboard-v2.html')

@app.route('/api/url-analysis/<int:scan_id>')
@login_required
def api_url_analysis(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or (scan.user_id != current_user.id and not current_user.is_admin):
        return jsonify({"error": "Not found"}), 404
    
    url = scan.url
    domain = urlparse(url).netloc
    
    # تحليل محلي متقدم
    analyzer = URLAnalyzer()
    local_analysis = analyzer.comprehensive_analysis(url)
    
    # تحليلات إضافية
    analysis = {
        "redirect_chain": [],
        "final_url": url,
        "cookies": [],
        "security_headers": local_analysis["security_headers"]["headers"],
        "tech_stack": [],
        "screenshot": f"https://image.thum.io/get/1024x768/crop/{url}",
        "whois": {},
        "geo": {},
        "similar_sites": [],
        "history_scans": [],
        # ميزات جديدة
        "url_structure": local_analysis["structure"],
        "phishing_indicators": local_analysis["phishing"],
        "ssl_info": local_analysis["ssl"],
        "dns_records": local_analysis["dns"],
        "is_shortened": local_analysis["is_shortened"],
        "security_score": local_analysis["security_score"],
        "verdict": local_analysis["verdict"],
        "recommendations": local_analysis["recommendations"]
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
    
    # WHOIS
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
# Run
# ================================================================
if __name__ == '__main__':
    app.run(debug=True)