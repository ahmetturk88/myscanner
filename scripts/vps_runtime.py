"""Fixed Compose production entry point; secrets are mounted, not command arguments."""
import os
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def secret(name):
    value=(Path('/run/secrets')/name).read_text(encoding='utf-8').strip()
    if not re.fullmatch('[0-9a-f]{64,96}',value):raise RuntimeError('Invalid deployment secret.')
    return value


def configure(command):
    if os.getenv('APP_ENV')!='production' or os.getenv('VPS_STACK')!='1':raise RuntimeError('Explicit VPS deployment profile is required.')
    # Fixed private service/DB names; never use hosted connection URLs here.
    user='myscanner_bootstrap' if command=='bootstrap' else 'myscanner_migrator' if command=='migrate' else 'myscanner_app'
    password=secret('db_admin_password' if command=='bootstrap' else 'db_migration_password' if command=='migrate' else 'db_app_password')
    os.environ['DATABASE_URL']='postgresql+psycopg2://'+user+':'+password+'@postgres:5432/myscanner_vps'
    if command in {'web','worker','beat','health-web','health-worker','seed','smoke-queue'}:
        os.environ['SECRET_KEY']=secret('session_key')
        redis_password=secret('redis_password')
        os.environ['CELERY_BROKER_URL']='redis://:'+redis_password+'@redis:6379/0'
        os.environ['CELERY_RESULT_BACKEND']='redis://:'+redis_password+'@redis:6379/1'


def smoke_queue():
    """Real broker -> Linux worker -> PostgreSQL transition, without scanning a target."""
    if os.getenv("VPS_REHEARSAL") != "1":raise RuntimeError("Explicit rehearsal required.")
    import json
    import uuid
    from datetime import datetime, timezone, timedelta
    from app import app
    from extensions import db
    from models import User, Scan
    from tasks import expire_url_scan_jobs
    from services.url_scan_storage import JOB_MARKER, JOB_LIFETIME
    identity = 'vps-smoke-' + uuid.uuid4().hex
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
    configure(command)
    if command=='bootstrap':
        import sqlalchemy as sa
        from services.database_roles import provision_roles
        engine=sa.create_engine(os.environ['DATABASE_URL'],hide_parameters=True)
        try:provision_roles(engine,secret('db_app_password'),secret('db_migration_password'),database='myscanner_vps',administrator='myscanner_bootstrap')
        finally:engine.dispose()
        print('PASS: VPS roles initialized.')
    elif command=='migrate':
        import sqlalchemy as sa
        from services.schema_migrations import upgrade_database
        engine=sa.create_engine(os.environ['DATABASE_URL'],hide_parameters=True)
        try:upgrade_database(engine,schema_role='myscanner_schema_owner')
        finally:engine.dispose()
        print('PASS: VPS schema migrated.')
    elif command=='smoke-queue':
        smoke_queue()
    elif command=='seed':
        from services.schema_migrations import initialize_sources
        initialize_sources();print('PASS: VPS sources initialized with runtime permissions.')
    elif command=='health-web':
        import urllib.request
        with urllib.request.urlopen('http://127.0.0.1:8000/health/live',timeout=3) as response:
            if response.status!=200:raise RuntimeError('Web unavailable.')
    elif command=='health-worker':
        import socket
        from celery_worker import celery
        replies=celery.control.inspect(destination=['vps-worker@'+socket.gethostname()],timeout=2).ping() or {}
        if not replies:raise RuntimeError('Worker unavailable.')
    else:
        commands={
          'web':['gunicorn','app:app','--bind','0.0.0.0:8000','--workers','2','--threads','2','--no-control-socket','--timeout','120','--worker-tmp-dir','/tmp','--access-logfile','-'],
          'worker':['celery','-A','celery_worker:celery','worker','--loglevel=info','--pool=prefork','--concurrency=1','-Q','scans,tip,celery','--hostname','vps-worker@%h'],
          'beat':['celery','-A','celery_worker:celery','beat','--loglevel=info','--schedule','/state/celerybeat-schedule','--pidfile','/tmp/celerybeat.pid']}
        if command not in commands:raise RuntimeError('Unknown runtime command.')
        os.execvp(commands[command][0],commands[command])

if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise RuntimeError('One command required.')
        run(sys.argv[1])
    except Exception:
        print('VPS runtime operation failed; no credentials printed.',file=sys.stderr)
        raise SystemExit(1)
