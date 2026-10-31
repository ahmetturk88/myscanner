"""Signed AI receipts: the report evidence the assistant may read, issued by the server.

Only the URL scanner saves its reports, so the other tools' results reach the AI assistant
through these receipts instead: when a tool finishes, the server signs the (already sanitized)
evidence together with the user and the tool. The assistant accepts a context only from a saved
report or from an unmodified receipt of the same user and tool, so nobody can hand it evidence
the server didn't produce. Receipts last six hours (a report stays open about that long).
"""
import functools
import json

from itsdangerous import BadData, URLSafeTimedSerializer

AGE_SECONDS = 6 * 3600
MAX_TOKEN = 120_000
FIELD = 'ai_receipt'


def _signer(secret):
    return URLSafeTimedSerializer(secret, salt='myscanner-ai-evidence-v1')


def issue(tool, result, owner, secret):
    """The receipt for one finished tool result, or None when it can't be made."""
    from services.ai_assistant import TOOLS, sanitize_evidence
    if tool not in TOOLS or not isinstance(result, (dict, list)):
        return None
    evidence = {k: v for k, v in result.items() if k not in (FIELD, '_pdf_receipt', 'pdf_receipt')} if isinstance(result, dict) else result
    token = _signer(secret).dumps({'o': str(owner), 't': tool, 'e': sanitize_evidence(evidence)})
    return token if len(token) <= MAX_TOKEN else None


def load(token, tool, owner, secret):
    """The sanitized evidence JSON from a receipt of this user and tool; raises BadData otherwise."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN:
        raise BadData('Invalid AI receipt')
    data = _signer(secret).loads(token, max_age=AGE_SECONDS)
    if not isinstance(data, dict) or data.get('o') != str(owner) or data.get('t') != tool or not isinstance(data.get('e'), str):
        raise BadData('AI receipt does not match')
    json.loads(data['e'])  # sanitized JSON, as stored for every context
    return data['e']


def with_ai_receipt(tool):
    """Adds `ai_receipt` to a tool endpoint's successful JSON answer (website and app alike)."""
    def decorate(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            from flask import current_app, make_response
            from flask_login import current_user
            response = make_response(view(*args, **kwargs))
            if response.status_code != 200 or response.mimetype != 'application/json' or response.direct_passthrough:
                return response
            try:
                data = json.loads(response.get_data(as_text=True))
                if isinstance(data, dict) and 'error' not in data:
                    receipt = issue(tool, data, current_user.get_id(), current_app.config['SECRET_KEY'])
                    if receipt:
                        data[FIELD] = receipt
                        response.set_data(json.dumps(data))
            except (ValueError, TypeError):
                current_app.logger.warning('AI receipt not added for %s', tool)
            return response
        return wrapper
    return decorate
