"""Authenticated PDF export of the website and email reports from their signed receipts."""
from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from itsdangerous import BadData

from services.report_receipts import load_receipt

report_pdf_bp = Blueprint('report_pdf', __name__)
EXPIRED = {'site': 'This PDF export is unavailable or expired. Start a new inspection.',
           'email': 'This PDF export is unavailable or expired. Check the address again.'}
NAMES = {'site': 'myscanner-website-report.pdf', 'email': 'myscanner-email-report.pdf'}


def _export(kind):
    from services.report_pdf import generate_email_report, generate_site_report
    from services.site_i18n import current_language
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('report-pdf', str(current_user.get_id()), 30, 600)  # building a PDF is heavy work
    except AuthRateLimited as error:
        return jsonify(error='Too many PDFs in a short time. Please try again in a few minutes.'), 429, {'Retry-After': str(error.retry_after)}
    data = request.get_json(silent=True)
    try:
        report = load_receipt(kind, data.get('receipt') if isinstance(data, dict) else None,
                              current_user.get_id(), current_app.config['SECRET_KEY'])
    except BadData:
        return jsonify(error=EXPIRED[kind]), 400
    try:
        build = generate_site_report if kind == 'site' else generate_email_report
        pdf = build(report, current_user.username, lang=current_language())
    except Exception:
        current_app.logger.exception('%s PDF generation failed', kind)
        return jsonify(error='PDF generation is temporarily unavailable.'), 503
    response = send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name=NAMES[kind], max_age=0)
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@report_pdf_bp.route('/api/site-report/pdf', methods=['POST'])
@login_required
def download_site_pdf():
    return _export('site')


@report_pdf_bp.route('/api/email-report/pdf', methods=['POST'])
@login_required
def download_email_pdf():
    return _export('email')
