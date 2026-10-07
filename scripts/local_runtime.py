"""Guarded local initialization and non-sensitive dependency health checks."""
import argparse
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def require_local_stack(environ=None):
    env = os.environ if environ is None else environ
    url = urlsplit(env.get('DATABASE_URL', ''))
    if (env.get('LOCAL_STACK') != '1' or env.get('APP_ENV') != 'development'
            or url.scheme != 'postgresql+psycopg2' or url.hostname != 'postgres'
            or url.username != 'myscanner_local' or url.path != '/myscanner_local'):
        raise RuntimeError('This command is limited to the isolated local Docker database.')


def dependencies_ready():
    from redis import Redis
    from sqlalchemy import create_engine, text
    engine = create_engine(os.environ['DATABASE_URL'], connect_args={'connect_timeout': 3})
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        for setting in ['CELERY_BROKER_URL', 'CELERY_RESULT_BACKEND']:
            client = Redis.from_url(os.environ[setting], socket_connect_timeout=2, socket_timeout=2)
            try:
                if not client.ping():
                    raise RuntimeError('Queue is unavailable')
            finally:
                client.close()
    finally:
        engine.dispose()


def create_local_user():
    import getpass
    password = getpass.getpass('Local administrator password (at least 12 characters): ')
    confirmation = getpass.getpass('Confirm password: ')
    if len(password) < 12 or password != confirmation:
        raise ValueError('Password must match and contain at least 12 characters')
    from app import app
    from extensions import db, bcrypt
    from models import User
    with app.app_context():
        email = 'local-admin@example.invalid'
        user = User.query.filter_by(email=email).first()
        if user is not None:
            raise RuntimeError('Local administrator already exists; it was not changed')
        user = User(username='local-admin', email=email, is_verified=True,
                    is_admin=True, role='admin',
                    password_hash=bcrypt.generate_password_hash(password).decode('utf-8'))
        db.session.add(user)
        db.session.commit()
    print('Local administrator created: local-admin@example.invalid')


def smoke_queue():
    """Real broker -> Linux worker -> PostgreSQL transition, without scanning a target."""
    import json
    import uuid
    from datetime import datetime, timezone, timedelta
    from app import app
    from extensions import db
    from models import User, Scan
    from tasks import expire_url_scan_jobs
    from services.url_scan_storage import JOB_MARKER, JOB_LIFETIME
    identity = 'local-smoke-' + uuid.uuid4().hex
    scan_id = user_id = None
    result = None
    try:
        with app.app_context():
            user = User(username=identity, email=identity+'@example.invalid', password_hash='disabled-local-smoke-login')
            db.session.add(user); db.session.flush(); user_id = user.id
            scan = Scan(url='https://example.invalid', user_id=user_id, status='queued',
                        result=JOB_MARKER, date_posted=datetime.now(timezone.utc).replace(tzinfo=None)-JOB_LIFETIME-timedelta(seconds=1))
            db.session.add(scan); db.session.commit(); scan_id = scan.id
        result = expire_url_scan_jobs.apply_async(expires=30)
        outcome = result.get(timeout=25)
        if not isinstance(outcome, dict) or outcome.get('expired', 0) < 1:
            raise RuntimeError('Worker did not confirm expiration')
        with app.app_context():
            db.session.expire_all()
            saved = db.session.get(Scan, scan_id)
            if saved is None or saved.status != 'error' or json.loads(saved.raw_report or '{}').get('status') != 'failed':
                raise RuntimeError('Worker database transition was not observed')
        print('PASS: real queue -> worker -> PostgreSQL; test record expired correctly.')
    finally:
        with app.app_context():
            db.session.rollback()
            if scan_id is not None:
                Scan.query.filter_by(id=scan_id, user_id=user_id).delete()
            if user_id is not None:
                User.query.filter_by(id=user_id, username=identity).delete()
            db.session.commit()
        if result is not None and result.ready():
            result.forget()


def run(command):
    require_local_stack()
    if command == 'init-db':
        dependencies_ready()
        from app import app
        from extensions import db
        with app.app_context():
            # Only the disposable local database: production migrations remain a separate task.
            db.create_all()
        print('Isolated local database initialized.')
    elif command == 'create-user':
        dependencies_ready()
        create_local_user()
    elif command == 'smoke-queue':
        dependencies_ready()
        smoke_queue()
    elif command == 'web-health':
        import urllib.request
        with urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3) as response:
            if response.status != 200:
                raise RuntimeError('Web is unavailable')
        dependencies_ready()
    elif command == 'worker-health':
        from celery_worker import celery
        name = 'local-worker@' + socket.gethostname()
        replies = celery.control.inspect(destination=[name], timeout=3).ping() or {}
        if replies.get(name, {}).get('ok') != 'pong':
            raise RuntimeError('Local worker is unavailable')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init-db', 'web-health', 'worker-health', 'create-user', 'smoke-queue'])
    args = parser.parse_args()
    try:
        run(args.command)
    except Exception:
        print('Local ' + args.command + ' failed; inspect the service logs.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
