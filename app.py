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

load_dotenv()

# ================================================================
# Initialization
# ================================================================
app = Flask(__name__)

# ================================================================
# Config
# ================================================================
app.config['SECRET_KEY']                  = os.getenv('SECRET_KEY', 'change-this-secret-key')
app.config['SQLALCHEMY_DATABASE_URI']     = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

API_KEY          = os.getenv('VIRUSTOTAL_API_KEY')
ABSTRACT_API_KEY = os.getenv('ABSTRACT_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
RESEND_API_KEY = os.getenv('RESEND_API_KEY')

# ================================================================
# Extensions
# ================================================================
db            = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view             = 'login'
login_manager.login_message          = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'
serializer    = URLSafeTimedSerializer(app.config['SECRET_KEY'])


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

class User(db.Model, UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_verified   = db.Column(db.Boolean, default=False)
    is_admin      = db.Column(db.Boolean, default=False)
    date_joined   = db.Column(db.DateTime, default=datetime.utcnow)
    scans         = db.relationship('Scan', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    url         = db.Column(db.String(500), nullable=False)
    result      = db.Column(db.String(1000))
    raw_report  = db.Column(db.Text)
    verdict     = db.Column(db.String(50))
    status      = db.Column(db.String(20), default='pending')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


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
        return redirect(url_for('dashboard'))
    return render_template('home.html')


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
    data  = request.get_json()
    email = data.get('email', '').strip()

    if not email:
        return jsonify({"error": "No email provided"}), 400

    domain = email.split('@')[-1] if '@' in email else email

    try:
        # 1. Email Reputation
        resp = requests.get(
            "https://emailreputation.abstractapi.com/v1/",
            params={"api_key": ABSTRACT_API_KEY, "email": email}
        )
        r = resp.json() if resp.status_code == 200 else {}

        deliverability = r.get("email_deliverability", {})
        quality        = r.get("email_quality", {})
        risk           = r.get("email_risk", {})
        breaches       = r.get("email_breaches", {})
        domain_info    = r.get("email_domain", {})

        is_valid       = deliverability.get("is_format_valid", False)
        is_mx          = deliverability.get("is_mx_valid", False)
        is_smtp        = deliverability.get("is_smtp_valid", False)
        is_disposable  = quality.get("is_disposable", False)
        is_free        = quality.get("is_free_email", False)
        quality_score  = quality.get("score", 0)
        status         = deliverability.get("status", "unknown")
        address_risk   = risk.get("address_risk_status", "unknown")
        total_breaches = breaches.get("total_breaches", 0)
        last_breached  = breaches.get("date_last_breached", None)
        
        breached_raw   = breaches.get("breached_domains", [])
        breached_list  = []
        for b in breached_raw:
            if isinstance(b, str):
                breached_list.append({"domain": b, "breach_date": "N/A"})
            elif isinstance(b, dict):
                breached_list.append({
                    "domain": b.get("domain", b.get("name", "Unknown")),
                    "breach_date": b.get("breach_date", b.get("date", "N/A"))
                })
        breached_list = breached_list[:10]

        # 2. SPF / DKIM / DMARC Check via Google DNS
        spf_record = None
        dkim_record = None
        dmarc_record = None

        try:
            # SPF
            resp_txt = requests.get(
                f"https://dns.google/resolve?name={domain}&type=TXT",
                timeout=10
            )
            if resp_txt.status_code == 200:
                for ans in resp_txt.json().get('Answer', []):
                    txt = ans.get('data', '').strip('"')
                    if 'v=spf1' in txt:
                        spf_record = txt
                        break
        except:
            pass

        try:
            # DKIM (google._domainkey)
            resp_dkim = requests.get(
                f"https://dns.google/resolve?name=google._domainkey.{domain}&type=TXT",
                timeout=10
            )
            if resp_dkim.status_code == 200:
                for ans in resp_dkim.json().get('Answer', []):
                    txt = ans.get('data', '').strip('"')
                    if 'v=DKIM1' in txt:
                        dkim_record = txt
                        break
        except:
            pass

        try:
            # DMARC
            resp_dmarc = requests.get(
                f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
                timeout=10
            )
            if resp_dmarc.status_code == 200:
                for ans in resp_dmarc.json().get('Answer', []):
                    txt = ans.get('data', '').strip('"')
                    if 'v=DMARC1' in txt:
                        dmarc_record = txt
                        break
        except:
            pass

        # 3. Blacklist Check (via domain)
        blacklisted = False
        blacklist_count = 0
        blacklist_results = []

        try:
            # Check a few blacklists
            bl_checks = [
                ("Spamhaus DBL", f"{domain}.dbl.spamhaus.org"),
                ("Surriel", f"{domain}.multi.surriel.com"),
                ("Barracuda", f"{domain}.bb.barracudacentral.org"),
            ]
            import socket
            for bl_name, bl_domain in bl_checks:
                try:
                    socket.gethostbyname(bl_domain)
                    blacklisted = True
                    blacklist_count += 1
                    blacklist_results.append({"name": bl_name, "listed": True})
                except:
                    blacklist_results.append({"name": bl_name, "listed": False})
        except:
            pass

        # Verdict
        if not is_valid:
            verdict = "invalid"
        elif is_disposable:
            verdict = "disposable"
        elif total_breaches > 0 and address_risk == "high":
            verdict = "breached"
        elif blacklisted:
            verdict = "blacklisted"
        elif not is_mx:
            verdict = "no_mx"
        elif not spf_record:
            verdict = "no_spf"
        elif status == "deliverable":
            verdict = "safe"
        else:
            verdict = "risky"

        return jsonify({
            "email":           email,
            "domain":          domain,
            "verdict":         verdict,
            "is_valid":        is_valid,
            "is_disposable":   is_disposable,
            "is_free":         is_free,
            "is_mx":           is_mx,
            "is_smtp":         is_smtp,
            "deliverability":  status.upper(),
            "quality_score":   quality_score,
            "address_risk":    address_risk,
            "total_breaches":  total_breaches,
            "last_breached":   last_breached,
            "breached_domains": breached_list,
            "domain_age":      domain_info.get("domain_age", 0),
            "registrar":       domain_info.get("registrar", "Unknown"),
            "spf_record":      spf_record,
            "spf_valid":       spf_record is not None,
            "dkim_record":     dkim_record,
            "dkim_valid":      dkim_record is not None,
            "dmarc_record":    dmarc_record,
            "dmarc_valid":     dmarc_record is not None,
            "blacklisted":     blacklisted,
            "blacklist_count": blacklist_count,
            "blacklist_results": blacklist_results,
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 500


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
    ip   = data.get('ip', '').strip()

    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query"}
        )
        r = resp.json()
        if r.get('status') == 'fail':
            return jsonify({"error": r.get('message', 'Invalid IP')}), 400

        verdict = "suspicious" if r.get('proxy') or r.get('hosting') else "safe"

        blacklist_count = 0
        blacklist_results = []
        
        if ABUSEIPDB_API_KEY:
            try:
                abuse_resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                )
                if abuse_resp.status_code == 200:
                    abuse_data = abuse_resp.json()
                    abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)
                    total_reports = abuse_data.get("data", {}).get("totalReports", 0)
                    
                    if abuse_score > 0:
                        blacklist_results.append({
                            "name": "AbuseIPDB",
                            "listed": True,
                            "detail": f"Score: {abuse_score}% ({total_reports} reports)"
                        })
                        blacklist_count += 1
                    else:
                        blacklist_results.append({
                            "name": "AbuseIPDB",
                            "listed": False,
                            "detail": "Clean"
                        })
                    
                    if abuse_score >= 50:
                        verdict = "blacklisted"
                else:
                    blacklist_results.append({
                        "name": "AbuseIPDB",
                        "listed": False,
                        "detail": "API unavailable"
                    })
            except:
                blacklist_results.append({
                    "name": "AbuseIPDB",
                    "listed": False,
                    "detail": "Check failed"
                })
        else:
            blacklist_results.append({
                "name": "AbuseIPDB",
                "listed": False,
                "detail": "Not configured"
            })

        return jsonify({
            "ip":           r.get('query'),
            "verdict":      verdict,
            "country":      r.get('country'),
            "country_code": r.get('countryCode'),
            "city":         r.get('city'),
            "region":       r.get('regionName'),
            "timezone":     r.get('timezone'),
            "isp":          r.get('isp'),
            "org":          r.get('org'),
            "lat":          r.get('lat'),
            "lon":          r.get('lon'),
            "is_proxy":     r.get('proxy', False),
            "is_hosting":   r.get('hosting', False),
            "is_mobile":    r.get('mobile', False),
            "blacklist_count": blacklist_count,
            "blacklist_results": blacklist_results,
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 500


# ================================================================
# PDF Report
# ================================================================

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
    except Exception:
        pass

    stats      = raw.get('data', {}).get('attributes', {}).get('stats', {})
    harmless   = stats.get('harmless', 0)
    malicious  = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)

    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    elements = []

    title_style = ParagraphStyle('title', fontSize=22, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#00c8ff'), spaceAfter=6)
    sub_style = ParagraphStyle('sub', fontSize=10, fontName='Helvetica',
        textColor=colors.HexColor('#888888'), spaceAfter=20)
    section_style = ParagraphStyle('section', fontSize=13, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#00c8ff'), spaceBefore=16, spaceAfter=10)

    elements.append(Paragraph('MyScanner', title_style))
    elements.append(Paragraph('Security Scan Report', sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e0e0e0')))
    elements.append(Spacer(1, 16))
    elements.append(Paragraph('SCAN INFORMATION', section_style))

    info_data = [
        ['Scan ID',    f'#{scan.id}'],
        ['URL',        scan.url],
        ['Status',     scan.status.upper()],
        ['Verdict',    scan.verdict.upper()],
        ['Date',       scan.date_posted.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Scanned By', current_user.username],
    ]

    info_table = Table(info_data, colWidths=[4*cm, 13*cm])
    info_table.setStyle(TableStyle([
        ('FONTNAME',  (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE',  (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#888888')),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#222222')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f7f8fa'), colors.white]),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e8e8e8')),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('SCAN STATISTICS', section_style))

    verdict_color = {'harmless':'#28a745','malicious':'#dc3545','suspicious':'#ffc107','unknown':'#6c757d','error':'#343434'}.get(scan.verdict, '#6c757d')

    stats_data = [
        ['Metric', 'Count', 'Status'],
        ['Harmless',   str(harmless),   'Safe'],
        ['Malicious',  str(malicious),  'Threat' if malicious > 0 else 'Clean'],
        ['Suspicious', str(suspicious), 'Warning' if suspicious > 0 else 'Clean'],
        ['Undetected', str(undetected), 'N/A'],
    ]

    stats_table = Table(stats_data, colWidths=[7*cm, 4*cm, 6*cm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',   (0,0), (-1,0), colors.HexColor('#00c8ff')),
        ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f7f8fa'), colors.white]),
        ('TOPPADDING',    (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,-1), 9),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e8e8e8')),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('OVERALL VERDICT', section_style))

    verdict_text = {
        'harmless':   'HARMLESS — No threats detected. This URL appears to be safe.',
        'malicious':  'MALICIOUS — This URL was flagged by multiple security engines.',
        'suspicious': 'SUSPICIOUS — Some engines flagged this URL. Proceed with caution.',
        'unknown':    'UNKNOWN — Not enough data to determine safety.',
        'error':      'ERROR — Scan could not be completed.',
    }.get(scan.verdict, 'UNKNOWN')

    verdict_style = ParagraphStyle('verdict', fontSize=12, fontName='Helvetica-Bold',
        textColor=colors.HexColor(verdict_color),
        backColor=colors.HexColor('#f7f8fa'),
        borderPad=12, spaceBefore=4, spaceAfter=20)

    elements.append(Paragraph(verdict_text, verdict_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e0e0e0')))
    elements.append(Spacer(1, 10))

    footer_style = ParagraphStyle('footer', fontSize=8, fontName='Helvetica',
        textColor=colors.HexColor('#aaaaaa'), alignment=1)
    elements.append(Paragraph(
        f'Generated by MyScanner · {scan.date_posted.strftime("%Y-%m-%d %H:%M")} UTC · Ahmed Sairafi',
        footer_style
    ))

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name=f'myscanner-report-{scan.id}.pdf',
                     mimetype='application/pdf')


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
    data   = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'https://' + domain
    domain = domain.strip('/')

    try:
        resp = requests.get(domain, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        base  = urlparse(domain).netloc
        # استخراج النطاق الأساسي (مثلاً: wikipedia.org)
        base_parts = base.split('.')
        base_domain = '.'.join(base_parts[-2:]) if len(base_parts) >= 2 else base
        
        links = set()

        for tag in soup.find_all('a', href=True):
            href   = urljoin(domain, tag['href'])
            parsed = urlparse(href)
            parsed_parts = parsed.netloc.split('.')
            parsed_domain = '.'.join(parsed_parts[-2:]) if len(parsed_parts) >= 2 else parsed.netloc
            
            # قبول أي رابط من نفس النطاق الأساسي أو نطاقات فرعية
            if parsed_domain == base_domain and href.startswith('http'):
                links.add(href)

        links = list(links)[:50]
        links.insert(0, domain)
        links = list(set(links))[:50]

    except Exception as e:
        return jsonify({"error": f"Could not reach domain: {str(e)}"}), 400

    headers = {"x-apikey": API_KEY}
    results = []
    lock = threading.Lock()

    def scan_url(url):
        try:
            r = requests.post("https://www.virustotal.com/api/v3/urls",
                              headers=headers, data={"url": url}, timeout=10)
            if r.status_code not in (200, 201):
                with lock:
                    results.append({"url": url, "verdict": "error", "malicious": 0, "harmless": 0, "suspicious": 0})
                return

            url_id     = r.json()["data"]["id"]
            report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            verdict    = "unknown"
            malicious  = harmless = suspicious = 0

            for _ in range(8):
                time.sleep(2)
                rr = requests.get(report_url, headers=headers, timeout=10)
                report = rr.json()
                if report["data"]["attributes"].get("status") == "completed":
                    s = report["data"]["attributes"].get("stats", {})
                    malicious  = s.get("malicious", 0)
                    suspicious = s.get("suspicious", 0)
                    harmless   = s.get("harmless", 0)
                    if malicious > 0:   verdict = "malicious"
                    elif suspicious > 0: verdict = "suspicious"
                    elif harmless > 0:  verdict = "harmless"
                    break

            with lock:
                results.append({"url": url, "verdict": verdict,
                                "malicious": malicious, "suspicious": suspicious, "harmless": harmless})

        except Exception:
            with lock:
                results.append({"url": url, "verdict": "error", "malicious": 0, "harmless": 0, "suspicious": 0})

    # فحص 10 روابط في نفس الوقت
    threads_list = []
    for i in range(0, len(links), 10):
        batch = links[i:i+10]
        batch_threads = []
        for url in batch:
            t = threading.Thread(target=scan_url, args=(url,))
            t.start()
            batch_threads.append(t)
        for t in batch_threads:
            t.join()

    total             = len(results)
    malicious_count   = sum(1 for r in results if r['verdict'] == 'malicious')
    suspicious_count  = sum(1 for r in results if r['verdict'] == 'suspicious')
    harmless_count    = sum(1 for r in results if r['verdict'] == 'harmless')
    overall           = "malicious" if malicious_count > 0 else ("suspicious" if suspicious_count > 0 else "harmless")

    return jsonify({"domain": domain, "total": total, "overall": overall,
                    "malicious": malicious_count, "suspicious": suspicious_count,
                    "harmless": harmless_count, "results": results})

@app.route('/file-scanner')
@login_required
def file_scanner():
    return render_template('file_scanner.html')


@app.route('/api/scan-file', methods=['POST'])
@login_required
def api_scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        file_content = file.read()
        file_size = len(file_content)
        file_name = file.filename
        
        headers = {"x-apikey": API_KEY}
        files = {'file': (file_name, file_content)}
        upload_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files
        )
        
        if upload_resp.status_code not in (200, 201):
            return jsonify({"error": f"Upload failed: {upload_resp.status_code}"}), 500
        
        upload_data = upload_resp.json()
        analysis_id = upload_data.get("data", {}).get("id", "")
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        for _ in range(30):
            time.sleep(2)
            analysis_resp = requests.get(analysis_url, headers=headers)
            if analysis_resp.status_code == 200:
                analysis_data = analysis_resp.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
        else:
            return jsonify({"error": "Analysis timeout"}), 500
        
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        results = analysis_data.get("data", {}).get("attributes", {}).get("results", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "harmless"
        
        engine_results = []
        for engine_name, engine_data in results.items():
            category = engine_data.get("category", "undetected")
            if category in ("malicious", "suspicious"):
                engine_results.append({
                    "name": engine_name,
                    "result": engine_data.get("result", category),
                    "category": category
                })
        
        return jsonify({
            "file_name": file_name,
            "file_size": file_size,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "engine_results": engine_results
        })
        
    except Exception as e:
        return jsonify({"error": f"Scan error: {str(e)}"}), 500


# ================================================================
# Password Check
# ================================================================

@app.route('/password-check')
@login_required
def password_check():
    return render_template('password_check.html')


@app.route('/api/check-password', methods=['POST'])
@login_required
def api_check_password():
    data     = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "No password provided"}), 400

    sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                            headers={"Add-Padding": "true"})
        if resp.status_code != 200:
            return jsonify({"error": "API error"}), 500

        count = 0
        for line in resp.text.splitlines():
            parts = line.split(':')
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                break

        return jsonify({"verdict": "pwned" if count > 0 else "safe", "count": count, "safe": count == 0})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 500


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
@app.route('/subdomain-finder')
@login_required
def subdomain_finder():
    return render_template('subdomain_finder.html')


@app.route('/api/subdomain-finder', methods=['POST'])
@login_required
def api_subdomain_finder():
    data   = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    domain = domain.replace('https://', '').replace('http://', '').strip('/')

    subdomains = set()

    # قائمة subdomains شائعة + المجال
    common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'shop', 'api', 'dev', 'admin', 'portal', 'cdn', 'remote', 'vpn', 'support', 'status', 'web', 'app', 'cloud', 'mail2', 'owa', 'exchange', 'demo', 'staging', 'beta']
    
    for sub in common_subs:
        subdomains.add(f"{sub}.{domain}")

    subdomains = sorted(list(subdomains))[:30]
    results = [{"domain": sub, "verdict": "found"} for sub in subdomains]

    return jsonify({"total": len(results), "subdomains": results})

@app.route('/api/scan-subdomain', methods=['POST'])
@login_required
def api_scan_subdomain():
    import traceback
    data   = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": API_KEY},
            data={"url": f"https://{domain}"}
        )
        if resp.status_code not in (200, 201):
            return jsonify({"verdict": "unknown", "error": f"Submit failed: {resp.status_code}"})

        url_id = resp.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"

        for _ in range(10):
            time.sleep(2)
            r = requests.get(analysis_url, headers={"x-apikey": API_KEY})
            if r.status_code == 200:
                result = r.json()
                status = result.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
        else:
            return jsonify({"verdict": "unknown", "error": "Timeout"})

        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return jsonify({"verdict": verdict})

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"verdict": "unknown", "error": str(e)})


@app.route('/domain-lookup')
@login_required
def domain_lookup():
    return render_template('domain_lookup.html')


@app.route('/api/domain-lookup', methods=['POST'])
@login_required
def api_domain_lookup():
    data   = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    domain = domain.replace('https://', '').replace('http://', '').strip('/')

    result = {
        "domain": domain,
        "registrar": "N/A",
        "created": "N/A",
        "expires": "N/A",
        "ip": "N/A",
        "country": "N/A",
        "isp": "N/A",
        "nameservers": [],
        "dns": [],
        "whois_updated": "N/A",
        "status": "N/A",
    }

    # 1. WHOIS via whoisxmlapi (free)
    try:
        whois_resp = requests.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={
                "domainName": domain,
                "apiKey": "at_free_demo_key",  # demo key - limited
                "outputFormat": "JSON"
            },
            timeout=15
        )
        if whois_resp.status_code == 200:
            whois_data = whois_resp.json()
            reg_record = whois_data.get("WhoisRecord", {})
            result["registrar"] = reg_record.get("registrarName", "N/A")
            result["created"] = reg_record.get("createdDate", "N/A")[:10] if reg_record.get("createdDate") else "N/A"
            result["expires"] = reg_record.get("expiresDate", "N/A")[:10] if reg_record.get("expiresDate") else "N/A"
            result["whois_updated"] = reg_record.get("updatedDate", "N/A")[:10] if reg_record.get("updatedDate") else "N/A"
            result["status"] = reg_record.get("status", "N/A")
            
            nameservers = reg_record.get("nameServers", {}).get("hostNames", [])
            result["nameservers"] = nameservers[:5] if nameservers else []
    except:
        pass

    # 2. IP info via ip-api
    try:
        resp = requests.get(f"http://ip-api.com/json/{domain}", timeout=10)
        if resp.status_code == 200:
            r = resp.json()
            if r.get('status') != 'fail':
                result["ip"] = r.get('query', 'N/A')
                result["country"] = r.get('country', 'N/A')
                result["isp"] = r.get('isp', 'N/A')
                if result["registrar"] == "N/A":
                    result["registrar"] = r.get('org', 'N/A')
    except:
        pass

    # 3. DNS Records
    try:
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
            resp = requests.get(
                f"https://dns.google/resolve?name={domain}&type={rtype}",
                timeout=10
            )
            if resp.status_code == 200:
                answers = resp.json().get('Answer', [])
                for ans in answers[:3]:
                    val = ans.get('data', '')
                    if val:
                        result["dns"].append({"type": rtype, "value": val})
    except:
        pass

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

    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": API_KEY},
            data={"url": url}
        )
        if resp.status_code not in (200, 201):
            return jsonify({"verdict": "unknown", "stats": {}})

        url_id = resp.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"

        for _ in range(10):
            time.sleep(2)
            r = requests.get(analysis_url, headers={"x-apikey": API_KEY})
            if r.status_code == 200:
                result = r.json()
                if result.get("data", {}).get("attributes", {}).get("status") == "completed":
                    break
        else:
            return jsonify({"verdict": "unknown", "stats": {}})

        stats = result["data"]["attributes"].get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0: verdict = "malicious"
        elif suspicious > 0: verdict = "suspicious"
        else: verdict = "clean"

        return jsonify({"verdict": verdict, "stats": stats})

    except:
      
      return jsonify({"verdict": "unknown", "stats": {}})
    
@app.route('/ssl-checker')
@login_required
def ssl_checker():
    return render_template('ssl_checker.html')


@app.route('/api/ssl-checker', methods=['POST'])
@login_required
def api_ssl_checker():
    data   = request.get_json()
    domain = data.get('domain', '').strip().replace('https://', '').replace('http://', '').split('/')[0]

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    try:
        import ssl
        import socket
        from datetime import datetime

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        if not cert:
            return jsonify({"valid": False, "error_msg": "No certificate found"})

        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        days_remaining = (not_after - now).days

        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        # Grade calculation
        if days_remaining > 180: grade = 'A+'
        elif days_remaining > 90: grade = 'A'
        elif days_remaining > 60: grade = 'B'
        elif days_remaining > 30: grade = 'C'
        elif days_remaining > 0: grade = 'D'
        else: grade = 'F'

        return jsonify({
            "domain": domain,
            "valid": days_remaining > 0,
            "days_remaining": days_remaining,
            "issuer": issuer.get('organizationName', issuer.get('commonName', 'N/A')),
            "subject": subject.get('commonName', domain),
            "valid_from": not_before.strftime('%Y-%m-%d'),
            "valid_until": not_after.strftime('%Y-%m-%d'),
            "expiry_date": not_after.strftime('%B %d, %Y'),
            "tls_version": tls_version,
            "grade": grade,
            "serial_number": cert.get('serialNumber', 'N/A'),
        })

    except Exception as e:
        return jsonify({"valid": False, "error_msg": str(e)})


# ================================================================
# Run
# ================================================================
if __name__ == '__main__':
    app.run(debug=True)