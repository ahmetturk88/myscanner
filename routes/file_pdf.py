"""Authenticated PDF export from an unmodified, server-issued report receipt."""
from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user, login_required
from itsdangerous import BadData
from services.file_pdf_receipts import load_file_pdf_receipt
from services.file_pdf_report import generate_file_report

file_pdf_bp=Blueprint('file_pdf',__name__)


@file_pdf_bp.route('/api/file-report/pdf',methods=['POST'])
@login_required
def download_file_pdf():
    data=request.get_json(silent=True)
    try:
        report=load_file_pdf_receipt(data.get('receipt') if isinstance(data,dict) else None,
                                     current_user.get_id(), current_app.config['SECRET_KEY'])
    except BadData:
        return jsonify(error='This PDF export is unavailable or expired. Start a new file scan.'),400
    try:
        pdf=generate_file_report(report)
    except Exception:
        current_app.logger.error('File PDF generation unavailable')
        return jsonify(error='PDF generation is temporarily unavailable.'),503
    response=send_file(pdf,mimetype='application/pdf',as_attachment=True,download_name='myscanner-file-report.pdf',max_age=0)
    response.headers['Cache-Control']='private, no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response
