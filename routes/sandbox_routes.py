# routes/sandbox_routes.py
# ================================================================
# Sandbox Analysis Routes — Hybrid Analysis + VirusTotal + Static
# ================================================================

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os, hashlib, json
from datetime import datetime

from services.hybrid_analysis import HybridAnalysisService
from services.permissions import check_permission
from logging_config import log_activity

sandbox_bp = Blueprint('sandbox', __name__)

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'zip', 'rar', '7z', 'js', 'py', 'ps1', 'sh', 'bat',
    'vbs', 'scr', 'msi', 'jar', 'apk', 'bin', 'iso', 'lnk'
}
MAX_SIZE = 32 * 1024 * 1024  # 32 MB


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ──────────────────────────────────────────────
#  PAGE ROUTE
# ──────────────────────────────────────────────
@sandbox_bp.route('/sandbox')
@login_required
def sandbox_page():
    return render_template('sandbox.html')


# ──────────────────────────────────────────────
#  API: تحليل ملف كامل
# ──────────────────────────────────────────────
@sandbox_bp.route('/api/sandbox/analyze-file', methods=['POST'])
@login_required
@check_permission('file_scan')
def api_sandbox_analyze_file():
    current_app.logger.info(f'[SANDBOX] File analysis requested by {current_user.username}')

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed'}), 400

    file_content = file.read()
    if len(file_content) > MAX_SIZE:
        return jsonify({'error': f'File too large (max 32MB)'}), 400

    filename = secure_filename(file.filename)
    environment_id = request.form.get('environment_id', '300')

    try:
        # ── Static Analysis (MyScanner) ──
        from services.file_deep_analyzer import FileDeepAnalyzer
        static_analyzer = FileDeepAnalyzer(use_exiftool=True)
        static_result = static_analyzer.comprehensive_analysis(file_content, filename)

        # ── Hybrid Analysis + VirusTotal ──
        sandbox = HybridAnalysisService()
        sandbox_result = sandbox.comprehensive_analysis(file_content, filename, environment_id)

        # ── دمج النتائج ──
        final = {
            **sandbox_result,
            'static_analysis': {
                'security_score': static_result.get('security_score', 0),
                'static_verdict': static_result.get('verdict', 'unknown'),
                'file_type': static_result.get('file_type', {}),
                'metadata': static_result.get('metadata', {}),
                'strings': static_result.get('strings', [])[:50],
                'pe_info': static_result.get('pe_info', {}),
                'entropy': static_result.get('entropy', 0),
                'indicators': static_result.get('indicators', []),
            },
            'analysis_type': 'comprehensive',
        }

        # حساب الدرجة الكلية
        static_score = static_result.get('security_score', 100)
        sandbox_score = sandbox_result.get('threat_score', 0)
        final['combined_risk_score'] = min(100, max(sandbox_score, 100 - static_score))

        log_activity(
            current_user.username,
            'file_scan',
            f'[SANDBOX] Analyzed: {filename} | Verdict: {final.get("verdict")}'
        )

        return jsonify(final)

    except Exception as e:
        current_app.logger.error(f'[SANDBOX] Error: {e}')
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────
#  API: Hash Lookup (بحث سريع)
# ──────────────────────────────────────────────
@sandbox_bp.route('/api/sandbox/hash-lookup', methods=['POST'])
@login_required
def api_sandbox_hash_lookup():
    data = request.get_json()
    file_hash = (data.get('hash', '') or '').strip()

    if not file_hash or len(file_hash) not in (32, 40, 64):
        return jsonify({'error': 'Provide a valid MD5/SHA1/SHA256 hash'}), 400

    try:
        sandbox = HybridAnalysisService()
        result = sandbox.lookup_hash(file_hash)

        log_activity(current_user.username, 'file_scan', f'[SANDBOX] Hash lookup: {file_hash[:16]}...')
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────
#  API: تحليل URL في Sandbox
# ──────────────────────────────────────────────
@sandbox_bp.route('/api/sandbox/analyze-url', methods=['POST'])
@login_required
@check_permission('url_analyzer')
def api_sandbox_analyze_url():
    data = request.get_json()
    url = (data.get('url', '') or '').strip()
    environment_id = data.get('environment_id', '300')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        sandbox = HybridAnalysisService()

        # تحليل URL محلي أولاً
        from services.url_analyzer import URLDeepAnalyzer
        url_analyzer = URLDeepAnalyzer()
        local_result = url_analyzer.comprehensive_analysis(url)

        # إرسال URL للـ Sandbox
        submit_result = sandbox.submit_url(url, environment_id)

        final = {
            'url': url,
            'local_analysis': local_result,
            'sandbox_submission': submit_result,
            'verdict': local_result.get('verdict', 'unknown'),
            'security_score': local_result.get('security_score', 0),
        }

        log_activity(current_user.username, 'url_analyzer', f'[SANDBOX] URL: {url[:80]}')
        return jsonify(final)

    except Exception as e:
        return jsonify({'error': str(e)}), 500