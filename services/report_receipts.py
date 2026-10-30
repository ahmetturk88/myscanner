"""Short-lived, owner-bound PDF receipts for the website and email reports.

Same idea as file_pdf_receipts: the server signs the result it just produced, the
page hands the receipt back, and the PDF is built from that signed copy. The PDF
therefore says exactly what the page said, and nobody can print a report they
edited in the browser or one that belongs to someone else.
"""
from itsdangerous import BadData, URLSafeTimedSerializer

from services.file_pdf_receipts import compact

MAX_TOKEN = 300000
EXPORT_AGE = 3600
FIELDS = {
    'site': ('url', 'domain', 'verdict', 'plain', 'analyzed_at', 'structure', 'dns', 'http', 'tls', 'content', 'provider',
             'trust', 'crawl', 'posture', 'header_observations', 'findings', 'checks', 'assessment', 'discovery',
             'missing_checks', 'evidence_policy'),
    'email': ('email', 'domain', 'verdict', 'plain', 'assessment', 'dns', 'blacklist', 'domain_info', 'smtp', 'is_disposable',
              'is_free', 'web_risk', 'name_signals', 'local_signals', 'address_features', 'checked_at'),
}
BUDGET = {'site': 90000, 'email': 50000}


def _signer(kind, secret):
    return URLSafeTimedSerializer(secret, salt=f'myscanner-{kind}-pdf-v1')


def issue_receipt(kind, report, owner, secret):
    selected = {key: report[key] for key in FIELDS[kind] if key in report}
    if kind == 'site' and isinstance(selected.get('crawl'), dict):
        selected['crawl'] = {k: v for k, v in selected['crawl'].items() if k != 'text'}
    token = _signer(kind, secret).dumps({'owner': str(owner), 'report': compact(selected, [BUDGET[kind]])})
    if len(token) > MAX_TOKEN:
        raise ValueError('Export receipt exceeds limit')
    return token


def load_receipt(kind, token, owner, secret):
    if kind not in FIELDS or not isinstance(token, str) or not token or len(token) > MAX_TOKEN:
        raise BadData('Invalid export receipt')
    data = _signer(kind, secret).loads(token, max_age=EXPORT_AGE)
    if not isinstance(data, dict) or data.get('owner') != str(owner) or not isinstance(data.get('report'), dict):
        raise BadData('Invalid export receipt owner')
    return data['report']
