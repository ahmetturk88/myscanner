"""Reject malformed scan payloads before the existing service quota decorator."""
from functools import wraps
from flask import jsonify, request
from services.safe_http import UnsafeTargetError, normalize_url


def validate_web_scan_request(field, option, domain=False):
    def decorate(view):
        @wraps(view)
        def checked(*args, **kwargs):
            data = request.get_json(silent=True)
            default = option == 'include_ct'
            if not isinstance(data, dict) or not isinstance(data.get(field), str) or not isinstance(data.get(option, default), bool):
                return jsonify(error='Provide a valid '+field+' and a boolean '+option+' option'), 400
            value = data[field]
            if not value or len(value) > (253 if domain else 2048):
                return jsonify(error='The '+field+' is empty or exceeds the allowed length'), 400
            try:
                if domain:
                    from services.subdomain_finder import normalize_domain
                    normalize_domain(value.strip())
                else:
                    normalize_url(value)
            except (ValueError, UnsafeTargetError) as error:
                return jsonify(error=str(error)), 400
            return view(*args, **kwargs)
        return checked
    return decorate
