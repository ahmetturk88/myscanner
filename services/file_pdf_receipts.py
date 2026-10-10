"""Short-lived, owner-bound export receipts for server-generated file evidence."""
from itsdangerous import URLSafeTimedSerializer, BadData

MAX_TOKEN = 200000
EXPORT_AGE = 3600
FIELDS = ('filename','file_size','file_size_bytes','file_type','hashes','metadata','iocs','yara','malwarebazaar','hash_reputation','warnings','recommendations','missing_checks','coverage_status','security_score','verdict','scanned_at','analyzed_at','scope')


def compact(value, budget, depth=0):
    if budget[0] <= 0 or depth > 5:
        return '[Additional evidence omitted from PDF; see JSON]'
    if isinstance(value, dict):
        return {str(k)[:100]: compact(v,budget,depth+1) for k,v in list(value.items())[:40]}
    if isinstance(value, list):
        return [compact(v,budget,depth+1) for v in value[:40]]
    if value is None or isinstance(value,(bool,int,float)):
        return value
    text = str(value)[:min(1200,budget[0])]
    budget[0] -= len(text)
    return text


def signer(secret):
    return URLSafeTimedSerializer(secret, salt='myscanner-file-pdf-v1')


def issue_file_pdf_receipt(report, owner, secret):
    budget=[40000]
    selected=compact({key:report[key] for key in FIELDS if key in report},budget)
    token=signer(secret).dumps({'owner':str(owner),'report':selected})
    if len(token)>MAX_TOKEN:
        raise ValueError('Export receipt exceeds limit')
    return token


def load_file_pdf_receipt(token, owner, secret):
    if not isinstance(token,str) or not token or len(token)>MAX_TOKEN:
        raise BadData('Invalid export receipt')
    data=signer(secret).loads(token,max_age=EXPORT_AGE)
    if not isinstance(data,dict) or data.get('owner')!=str(owner) or not isinstance(data.get('report'),dict):
        raise BadData('Invalid export receipt owner')
    return data['report']
