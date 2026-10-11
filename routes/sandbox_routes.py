# routes/sandbox_routes.py
# ================================================================
# Sandbox Analysis Routes — Hybrid Analysis + Static
# ================================================================

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os, hashlib, json
from datetime import datetime

from services.hybrid_analysis import HybridAnalysisService, ENVIRONMENTS
from services.permissions import check_permission, reserve_request_quota
from services.safe_http import UnsafeTargetError
from services.upload_validation import read_validated_upload
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
def sandbox_file_report(file_content, filename, environment_id):
    """Static analysis plus Hybrid Analysis/MalwareBazaar evidence (runs in a worker)."""
    from services.file_deep_analyzer import FileDeepAnalyzer
    static_result = FileDeepAnalyzer(use_exiftool=True).comprehensive_analysis(file_content, filename)
    sandbox_result = HybridAnalysisService().comprehensive_analysis(file_content, filename, environment_id)
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
    static_score = static_result.get('security_score', 100)
    sandbox_score = sandbox_result.get('threat_score', 0)
    final['combined_risk_score'] = min(100, max(sandbox_score, 100 - static_score))
    return final


@sandbox_bp.route('/api/sandbox/analyze-file', methods=['POST'])
@login_required
def api_sandbox_analyze_file():
    """Queue Sandbox file analysis; read the result from /api/task-status/<task_id>."""
    filename, file_content = read_validated_upload(
        request.files.get('file'), ALLOWED_EXTENSIONS, MAX_SIZE
    )
    environment_id = request.form.get('environment_id', '300')
    if environment_id not in ENVIRONMENTS:
        return jsonify(error='Unsupported analysis environment'), 400
    failure = reserve_request_quota('file_scan')
    if failure is not None:
        return failure
    from services.task_dispatch import enqueue_owned_task
    from services.upload_validation import save_temporary_upload, remove_temporary_upload
    from tasks import sandbox_file_task
    temp_path = save_temporary_upload(file_content, filename, 'temp_uploads')
    try:
        task_id = enqueue_owned_task(sandbox_file_task, (temp_path, filename, current_user.id, environment_id), current_user.id)
    except Exception:
        remove_temporary_upload(temp_path)
        current_app.logger.exception('[SANDBOX] File analysis could not be queued')
        return jsonify(error='Sandbox analysis is temporarily unavailable. Please try again later.'), 503
    log_activity(current_user.username, 'file_scan', '[SANDBOX] File analysis queued')
    return jsonify(task_id=task_id, status='started'), 202


# ──────────────────────────────────────────────
#  API: Hash Lookup (بحث سريع)
# ──────────────────────────────────────────────
@sandbox_bp.route('/api/sandbox/hash-lookup', methods=['POST'])
@login_required
def api_sandbox_hash_lookup():
    data = request.get_json(silent=True)
    value = data.get('hash') if isinstance(data, dict) else None
    if not isinstance(value, str):
        return jsonify(error='Provide a valid MD5/SHA1/SHA256 hash'), 400
    file_hash = value.strip()
    if len(file_hash) not in (32, 40, 64) or any(c not in '0123456789abcdefABCDEF' for c in file_hash):
        return jsonify(error='Provide a valid MD5/SHA1/SHA256 hash'), 400
    failure = reserve_request_quota('file_scan')
    if failure is not None:
        return failure

    try:
        sandbox = HybridAnalysisService()
        result = sandbox.lookup_hash(file_hash)

        log_activity(current_user.username, 'file_scan', f'[SANDBOX] Hash lookup: {file_hash[:16]}...')
        return jsonify(result)

    except Exception:
        current_app.logger.exception('[SANDBOX] Request failed')
        return jsonify({'error': 'Sandbox service is temporarily unavailable. Please retry.'}), 500


# ──────────────────────────────────────────────
#  API: تحليل URL في Sandbox
# ──────────────────────────────────────────────
@sandbox_bp.route('/api/sandbox/analyze-url', methods=['POST'])
@login_required
def api_sandbox_analyze_url():
    """URL Sandbox uses the queued URL scan pipeline; open result_url when done."""
    data = request.get_json(silent=True)
    from services.url_scan_request import queue_url_scan
    return queue_url_scan(data.get('url') if isinstance(data, dict) else None)

