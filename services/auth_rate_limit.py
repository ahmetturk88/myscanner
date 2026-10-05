"""Atomic, shared authentication limits backed by the application database."""
import hashlib
import hmac
import math
import time
from flask import current_app
from sqlalchemy import case, delete, or_, select
from extensions import db
from models import AuthRateLimit


class AuthRateLimited(Exception):
    def __init__(self, retry_after):
        self.retry_after = max(1, int(math.ceil(retry_after)))


def consume_limit(namespace, identity, limit, window, now=None):
    now = time.time() if now is None else now
    key = hmac.new(current_app.config['SECRET_KEY'].encode(),
                   (namespace + ':' + identity).encode(), hashlib.sha256).hexdigest()
    table = AuthRateLimit.__table__
    dialect = db.engine.dialect.name
    if dialect == 'sqlite':
        from sqlalchemy.dialects.sqlite import insert
    elif dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    else:
        raise RuntimeError('Authentication limits require SQLite or PostgreSQL.')
    expired = table.c.expires_at <= now
    statement = insert(table).values(key=key, hits=1, expires_at=now + window)
    statement = statement.on_conflict_do_update(
        index_elements=[table.c.key],
        set_={'hits': case((expired, 1), else_=table.c.hits + 1),
              'expires_at': case((expired, now + window), else_=table.c.expires_at)},
        where=or_(expired, table.c.hits < limit))
    # Independent committed transaction: a later login failure/rollback cannot
    # undo the attempt, and workers share the same atomic counter.
    with db.engine.begin() as connection:
        connection.execute(delete(table).where(table.c.expires_at < now - 86400))
        accepted = connection.execute(statement).rowcount != 0
        expires = connection.execute(select(table.c.expires_at).where(table.c.key == key)).scalar_one()
    if not accepted:
        raise AuthRateLimited(expires - now)


def check_auth_request(endpoint, ip, email):
    if endpoint == 'login':
        consume_limit('login-ip', ip, 60, 900)
        consume_limit('login-account', email, 20, 900)
    elif endpoint == 'register':
        consume_limit('register-ip', ip, 5, 3600)


def check_verification_send(user_id):
    consume_limit('verification-hour', str(user_id), 3, 3600)
    consume_limit('verification-minute', str(user_id), 1, 60)
