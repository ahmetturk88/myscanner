"""Shared atomic daily permissions. Counters are stored in the application DB."""
from functools import wraps
from flask import current_app, jsonify, request
from flask_login import current_user
from sqlalchemy import inspect
from extensions import db
from services.quota_policy import DAILY_LIMITS, SERVICE_COST
from services.daily_quota import (SERVICES, DailyQuotaExceeded, DailyQuotaUnavailable,
    QuotaUserMissing, consume_quota, remaining_quota, reset_expired_quotas)


def _refresh_cached_user():
    # A request may already hold this User in its ORM identity map. Expire only
    # quota fields so a subsequent unrelated commit cannot restore old balances.
    user = current_user._get_current_object()
    if inspect(user, raiseerr=False) is not None and inspect(user).persistent:
        db.session.expire(user, [name + '_remaining' for name in SERVICES] + ['remaining_scans', 'scans_reset_date'])


def reserve_request_quota(service, cost=1):
    if not current_user.is_authenticated:
        return jsonify(error='Authentication required'), 401
    try:
        consume_quota(current_user.id, service, cost)
        _refresh_cached_user()
    except QuotaUserMissing:
        return jsonify(error='User not found'), 401
    except DailyQuotaExceeded as error:
        return jsonify(error=f'Daily limit reached for {service}.', remaining=error.remaining), 429
    except DailyQuotaUnavailable:
        current_app.logger.error('Daily quota storage unavailable')
        return jsonify(error='Scan allowance temporarily unavailable. Please try again later.'), 503
    return None


def check_permission(service_name, cost=1):
    if service_name not in SERVICES:
        raise ValueError('Service does not have a persistent daily quota.')
    def decorator(view):
        @wraps(view)
        def checked(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify(error='Authentication required'), 401
            # Reject malformed JSON before charging. Service-specific format
            # checks and upload validation remain in their endpoint handlers.
            if service_name != 'file_scan':
                data = request.get_json(silent=True)
                field = {'site_scan':'domain','email_check':'email','ip_check':'ip',
                         'domain_lookup':'domain','ssl_check':'domain','qr_scan':'url',
                         'subdomain_finder':'domain','password_check':'password','url_analyzer':'url'}.get(service_name)
                if not isinstance(data, dict) or field and (not isinstance(data.get(field), str) or not data[field].strip() or len(data[field]) > (1024 if field == 'password' else 2048)):
                    return jsonify(error='Provide a valid scan request.'), 400
            failure = reserve_request_quota(service_name, cost)
            return failure if failure is not None else view(*args, **kwargs)
        return checked
    return decorator


def reset_daily_scans():
    return reset_expired_quotas()


def check_permission_manual(service_name):
    if not current_user.is_authenticated:
        return False, 'Authentication required', 0
    remaining = remaining_quota(current_user.id, service_name)
    return remaining > 0, 'OK' if remaining > 0 else 'Daily scan limit reached.', remaining


def deduct_scan(service_name):
    return reserve_request_quota(service_name) is None


def get_remaining_scans(service_name):
    if not current_user.is_authenticated:
        return 0
    return remaining_quota(current_user.id, service_name)


def get_user_limits():
    if not current_user.is_authenticated:
        return {}
    role = 'admin' if current_user.is_admin else current_user.role if current_user.role in DAILY_LIMITS else 'user'
    limits = {name: DAILY_LIMITS[role][name] for name in SERVICES}
    limits.update({name + '_remaining': get_remaining_scans(name) for name in SERVICES})
    return {'role':role, 'limits':limits, 'is_premium':role == 'premium', 'is_admin':role == 'admin'}
