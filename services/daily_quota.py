"""Atomic UTC daily reservations using the existing User columns (SQLite/Postgres)."""
from datetime import datetime, timezone
from sqlalchemy import case, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from models import User
from services.quota_policy import DAILY_LIMITS

SERVICES = tuple(name for name in DAILY_LIMITS['user'] if hasattr(User, name + '_remaining'))

class DailyQuotaExceeded(Exception):
    def __init__(self, service, remaining):
        self.service, self.remaining = service, max(0, int(remaining))

class DailyQuotaUnavailable(Exception):
    pass

class QuotaUserMissing(Exception):
    pass

def _clock(now=None):
    now = datetime.now(timezone.utc) if now is None else now
    if now.tzinfo is None:
        raise ValueError('Quota clock must be timezone-aware.')
    now = now.astimezone(timezone.utc).replace(tzinfo=None)
    return now, now.replace(hour=0, minute=0, second=0, microsecond=0)

def _limit(service):
    return case((User.is_admin.is_(True), DAILY_LIMITS['admin'][service]),
                (User.role == 'admin', DAILY_LIMITS['admin'][service]),
                (User.role == 'premium', DAILY_LIMITS['premium'][service]),
                else_=DAILY_LIMITS['user'][service])

def _available(service, midnight):
    field = getattr(User, service + '_remaining')
    limit = _limit(service)
    expired = or_(User.scans_reset_date.is_(None), User.scans_reset_date < midnight)
    balance = case((field.is_(None), limit), (field > limit, limit), (field < 0, 0), else_=field)
    return case((expired, limit), else_=balance), expired

def _validate(service, cost=1):
    if service not in SERVICES:
        raise ValueError('Service does not have a persistent daily quota.')
    if not isinstance(cost, int) or isinstance(cost, bool) or cost < 1:
        raise ValueError('Quota cost must be a positive integer.')

def _reset_values(expired, now):
    values = {name + '_remaining': case((expired, _limit(name)), else_=getattr(User, name + '_remaining')) for name in SERVICES}
    # Keep the legacy aggregate display synchronized on rollover; URL dispatch
    # no longer uses it as an alternative allowance.
    values['remaining_scans'] = case((expired, case((or_(User.is_admin.is_(True), User.role.in_(['admin','premium'])), 999999), else_=20)), else_=User.remaining_scans)
    values['scans_reset_date'] = case((expired, now), else_=User.scans_reset_date)
    return values

def consume_quota(user_id, service, cost=1, now=None):
    """Reserve the complete cost or nothing, committed before provider/queue work.

    One conditional UPDATE resets all balances and debits this service. Its row
    predicate is evaluated under database write locking, even across workers.
    """
    _validate(service, cost)
    instant, midnight = _clock(now)
    available, expired = _available(service, midnight)
    values = _reset_values(expired, instant)
    values[service + '_remaining'] = available - cost
    try:
        with db.engine.begin() as connection:
            accepted = connection.execute(update(User).where(User.id == user_id, available >= cost).values(**values)).rowcount == 1
            remaining = connection.execute(select(available).where(User.id == user_id)).scalar_one_or_none()
    except SQLAlchemyError as error:
        raise DailyQuotaUnavailable('Daily quota storage unavailable.') from error
    if remaining is None:
        raise QuotaUserMissing()
    if not accepted:
        raise DailyQuotaExceeded(service, remaining)
    return int(remaining)

def remaining_quota(user_id, service, now=None):
    _validate(service)
    instant, midnight = _clock(now)
    available, expired = _available(service, midnight)
    try:
        with db.engine.begin() as connection:
            connection.execute(update(User).where(User.id == user_id, expired).values(**_reset_values(expired, instant)))
            value = connection.execute(select(available).where(User.id == user_id)).scalar_one_or_none()
    except SQLAlchemyError as error:
        raise DailyQuotaUnavailable('Daily quota storage unavailable.') from error
    return int(value) if value is not None else 0

def reset_expired_quotas(now=None):
    """Idempotent compatibility hook; never replenish today's reservations."""
    instant, midnight = _clock(now)
    _, expired = _available('url_analyzer', midnight)
    try:
        with db.engine.begin() as connection:
            return connection.execute(update(User).where(expired).values(**_reset_values(expired, instant))).rowcount
    except SQLAlchemyError as error:
        raise DailyQuotaUnavailable('Daily quota storage unavailable.') from error
