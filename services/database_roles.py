"""Fixed PostgreSQL roles for the isolated local cluster only."""
import re
import sqlalchemy as sa

OWNER = 'myscanner_schema_owner'
MIGRATOR = 'myscanner_migrator'
APPLICATION = 'myscanner_app'
DATABASE = 'myscanner_local'

def validate_passwords(application, migration):
    if (not isinstance(application, str) or not isinstance(migration, str)
            or not re.fullmatch('[0-9a-f]{64}', application)
            or not re.fullmatch('[0-9a-f]{64}', migration) or application == migration):
        raise RuntimeError('Independent local database credentials are required.')

def apply_runtime_grants(connection):
    # Executed as schema owner, after migrations as well as during provisioning.
    statements = [
        'REVOKE ALL ON SCHEMA public FROM PUBLIC, myscanner_app',
        'GRANT USAGE ON SCHEMA public TO myscanner_app',
        'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, myscanner_app',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO myscanner_app',
        'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, myscanner_app',
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO myscanner_app',
        'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, myscanner_app',
        'ALTER DEFAULT PRIVILEGES FOR ROLE myscanner_schema_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO myscanner_app',
        'ALTER DEFAULT PRIVILEGES FOR ROLE myscanner_schema_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO myscanner_app',
        'ALTER DEFAULT PRIVILEGES FOR ROLE myscanner_schema_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
    ]
    for statement in statements:
        connection.exec_driver_sql(statement)
    if sa.inspect(connection).has_table('alembic_version'):
        connection.exec_driver_sql('REVOKE ALL ON public.alembic_version FROM myscanner_app')
        connection.exec_driver_sql('GRANT SELECT ON public.alembic_version TO myscanner_app')

def provision_roles(engine, application_password, migration_password):
    validate_passwords(application_password, migration_password)
    if (engine.url.drivername != 'postgresql+psycopg2' or engine.url.host != 'postgres'
            or engine.url.database != DATABASE or engine.url.username != DATABASE):
        raise RuntimeError('Role provisioning requires the isolated local administrator.')
    with engine.begin() as connection:
        # Serialize cooperating initializers and suppress credential-bearing DDL logs.
        connection.exec_driver_sql('SELECT pg_advisory_xact_lock(67384021)')
        connection.exec_driver_sql("SET LOCAL log_statement = 'none'")
        connection.exec_driver_sql("SET LOCAL log_min_error_statement = 'panic'")
        identity = connection.exec_driver_sql('SELECT current_user, current_database()').one()
        if identity != (DATABASE, DATABASE):
            raise RuntimeError('Unexpected local database identity.')
        for name, login in [(OWNER, False), (MIGRATOR, True), (APPLICATION, True)]:
            role = connection.execute(sa.text('SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname=:name'), {'name': name}).first()
            if role is None:
                connection.exec_driver_sql('CREATE ROLE ' + name + (' LOGIN' if login else ' NOLOGIN') + ' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            elif any(role[:5]) or role[5] != login:
                raise RuntimeError('An existing role has unexpected elevated privileges.')
        members = connection.exec_driver_sql("SELECT parent.rolname, child.rolname, m.admin_option FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON child.oid=m.member WHERE child.rolname IN ('myscanner_app','myscanner_migrator','myscanner_schema_owner')").all()
        if any(tuple(pair) != (OWNER, MIGRATOR, False) for pair in members):
            raise RuntimeError('Unexpected role membership; no credentials were changed.')
        # Driver-bound values, no user-controlled identifiers. Caller never logs exceptions.
        connection.exec_driver_sql('ALTER ROLE myscanner_app PASSWORD %s', (application_password,))
        connection.exec_driver_sql('ALTER ROLE myscanner_migrator PASSWORD %s', (migration_password,))
        connection.exec_driver_sql('GRANT myscanner_schema_owner TO myscanner_migrator')
        connection.exec_driver_sql('ALTER SCHEMA public OWNER TO myscanner_schema_owner')
        objects = connection.exec_driver_sql("SELECT c.relname, c.relkind, r.rolname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f')").all()
        for name, kind, owner in objects:
            if owner not in (DATABASE, OWNER):
                raise RuntimeError('Public object ownership requires review.')
            if kind not in ('r', 'p', 'S'):
                raise RuntimeError('Unexpected public object; no automatic ownership transfer.')
            quoted = connection.dialect.identifier_preparer.quote(name)
            connection.exec_driver_sql(('ALTER SEQUENCE ' if kind == 'S' else 'ALTER TABLE ') + 'public.' + quoted + ' OWNER TO myscanner_schema_owner')
        connection.exec_driver_sql('REVOKE ALL ON DATABASE myscanner_local FROM PUBLIC, myscanner_app, myscanner_migrator')
        connection.exec_driver_sql('GRANT CONNECT ON DATABASE myscanner_local TO myscanner_app, myscanner_migrator')
        connection.exec_driver_sql('SET LOCAL ROLE myscanner_schema_owner')
        apply_runtime_grants(connection)
