"""Explicit schema deployment, independent of web application startup."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]

def migration_config():
    config = Config(str(ROOT / 'migrations' / 'alembic.ini'))
    config.set_main_option('script_location', str(ROOT / 'migrations'))
    return config

def application_metadata():
    from extensions import db
    import models
    return db.metadata

def upgrade_database(engine, schema_role=None):
    """Upgrade a fresh or compatible legacy schema; never blindly stamp it."""
    if schema_role is not None and (schema_role != 'myscanner_schema_owner' or engine.dialect.name != 'postgresql'):
        raise RuntimeError('Unexpected schema deployment role.')
    metadata = application_metadata()
    config = migration_config()
    with engine.begin() as connection:
        if schema_role is not None:
            connection.exec_driver_sql('SELECT pg_advisory_xact_lock(67384021)')
            connection.exec_driver_sql('SET LOCAL ROLE myscanner_schema_owner')
        inspector = sa.inspect(connection)
        existing = set(inspector.get_table_names())
        for name, table in metadata.tables.items():
            if name in existing:
                actual = {c['name']: c for c in inspector.get_columns(name)}
                if not set(table.columns.keys()).issubset(actual):
                    raise RuntimeError('Existing schema is incomplete; repair a restored copy first.')
                for column in table.columns:
                    found = actual[column.name]
                    widening_report = name == 'scan' and column.name == 'result' and isinstance(found['type'], sa.String)
                    if not widening_report and found['type']._type_affinity is not column.type._type_affinity:
                        raise RuntimeError('Existing schema has incompatible column types.')
                    if column.nullable != found['nullable']:
                        raise RuntimeError('Existing schema has incompatible nullability.')
                expected_pk = {c.name for c in table.primary_key}
                if expected_pk != set(inspector.get_pk_constraint(name)['constrained_columns']):
                    raise RuntimeError('Existing schema has an incompatible primary key.')
        if 'alembic_version' in existing:
            revisions = connection.execute(sa.text('SELECT version_num FROM alembic_version')).scalars().all()
            scripts = ScriptDirectory.from_config(config)
            for revision in revisions:
                scripts.get_revision(revision)
            if revisions == [scripts.get_current_head()] and not set(metadata.tables).issubset(existing):
                raise RuntimeError('Schema does not match its migration revision.')
        config.attributes['connection'] = connection
        config.attributes['target_metadata'] = metadata
        command.upgrade(config, 'head')
        inspector = sa.inspect(connection)
        if not set(metadata.tables).issubset(inspector.get_table_names()):
            raise RuntimeError('Migration did not establish all application tables.')
        if schema_role is not None:
            from services.database_roles import apply_runtime_grants
            apply_runtime_grants(connection)

def initialize_sources():
    from app import app
    from services.tip_collector import TIPCollector
    with app.app_context():
        TIPCollector().initialize_default_sources()
