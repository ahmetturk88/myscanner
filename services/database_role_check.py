"""Rollback-only PostgreSQL permission checks for the isolated Docker stack."""
import uuid
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from services.database_roles import APPLICATION, DATABASE


def expect_denied(connection, statement):
    savepoint = connection.begin_nested()
    try:
        connection.exec_driver_sql(statement)
    except DBAPIError as error:
        if getattr(error.orig, 'pgcode', None) != '42501':
            raise RuntimeError('Permission check returned an unexpected database error.') from None
    else:
        raise RuntimeError('Runtime account unexpectedly has administrative permissions.')
    finally:
        savepoint.rollback()


def check_runtime_permissions():
    import os
    from scripts.local_runtime import require_local_stack
    from services.schema_migrations import application_metadata
    require_local_stack()
    engine = sa.create_engine(os.environ['DATABASE_URL'], hide_parameters=True)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("SET LOCAL lock_timeout = '2s'")
                identity = connection.exec_driver_sql('SELECT current_user, current_database()').one()
                if identity != (APPLICATION, DATABASE):
                    raise RuntimeError('Unexpected runtime identity.')
                elevated = connection.exec_driver_sql("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user").scalar()
                membership = connection.exec_driver_sql('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)').scalar()
                if elevated or membership:
                    raise RuntimeError('Runtime role has elevated privileges or memberships.')
                metadata = application_metadata()
                user, scan = metadata.tables['user'], metadata.tables['scan']
                tag = 'permission-check-' + uuid.uuid4().hex
                user_id = connection.execute(user.insert().values(username=tag, email=tag+'@example.invalid', password_hash='disabled').returning(user.c.id)).scalar_one()
                scan_id = connection.execute(scan.insert().values(user_id=user_id, url='https://example.invalid', result='بيانات' * 30000).returning(scan.c.id)).scalar_one()
                connection.execute(scan.update().where(scan.c.id == scan_id).values(status='completed'))
                if connection.execute(sa.select(scan.c.status).where(scan.c.id == scan_id)).scalar_one() != 'completed':
                    raise RuntimeError('Runtime data access failed.')
                connection.execute(scan.delete().where(scan.c.id == scan_id))
                connection.execute(user.delete().where(user.c.id == user_id))
                for statement in [
                    'CREATE TABLE public.permission_check_probe (id integer)',
                    'CREATE TEMP TABLE permission_check_probe (id integer)',
                    'CREATE SCHEMA permission_check_probe',
                    'ALTER TABLE public."user" ADD COLUMN permission_check_probe boolean',
                    'DROP TABLE public.auth_rate_limit',
                    'TRUNCATE public.auth_rate_limit',
                    'UPDATE public.alembic_version SET version_num=version_num',
                    'SET ROLE myscanner_schema_owner',
                    'SET ROLE myscanner_migrator',
                ]:
                    expect_denied(connection, statement)
            finally:
                transaction.rollback()
        print('PASS: runtime data access works; schema changes, truncation and role escalation are denied. Test rows rolled back.')
    finally:
        engine.dispose()
