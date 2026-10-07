import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from services.schema_migrations import application_metadata, upgrade_database

ROOT = Path(__file__).resolve().parents[1]

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = sa.create_engine('sqlite:///' + str(Path(self.directory.name) / 'fixture.db'))
        self.metadata = application_metadata()
    def tearDown(self):
        self.engine.dispose()
        self.directory.cleanup()
    def test_empty_database_builds_all_tables_and_matches_models(self):
        upgrade_database(self.engine)
        with self.engine.connect() as connection:
            self.assertEqual(compare_metadata(MigrationContext.configure(connection), self.metadata), [])
            self.assertEqual(connection.execute(sa.text('select version_num from alembic_version')).scalar(), 'd4e52098ab61')
    def test_unversioned_legacy_preserves_large_unicode_report_and_user(self):
        self.metadata.create_all(self.engine)
        report = '{"report":"' + 'تقرير <literal>' * 10000 + '"}'
        with self.engine.begin() as connection:
            connection.execute(sa.text('INSERT INTO user (id, username, email, password_hash) VALUES (1, :name, :email, :password)'), dict(name='owner', email='owner@example.invalid', password='test-hash'))
            connection.execute(self.metadata.tables['scan'].insert().values(id=1, user_id=1, url='https://example.com', result=report))
        upgrade_database(self.engine)
        upgrade_database(self.engine)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(sa.text('select result from scan where id=1')).scalar(), report)
            self.assertEqual(connection.execute(sa.text('select count(*) from user')).scalar(), 1)
    def test_original_stamped_revision_upgrades_without_replaying_baseline(self):
        self.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)')
            connection.exec_driver_sql("INSERT INTO alembic_version VALUES ('5594693f7fdb')")
        upgrade_database(self.engine)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(sa.text('select version_num from alembic_version')).scalar(), 'd4e52098ab61')
    def test_old_string_report_storage_is_widened_without_data_loss(self):
        legacy = sa.MetaData()
        for table in self.metadata.sorted_tables:
            table.to_metadata(legacy)
        legacy.tables['scan'].c.result.type = sa.String(1000)
        legacy.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(legacy.tables['user'].insert().values(id=1, username='owner', email='owner@example.invalid', password_hash='hash'))
            connection.execute(legacy.tables['scan'].insert().values(id=1, user_id=1, url='https://example.com', result='old report'))
        upgrade_database(self.engine)
        column = next(c for c in sa.inspect(self.engine).get_columns('scan') if c['name'] == 'result')
        self.assertIsInstance(column['type'], sa.Text)
        with self.engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql('select result from scan').scalar(), 'old report')
    def test_missing_legacy_column_fails_before_creating_other_tables(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE user (id INTEGER PRIMARY KEY, username VARCHAR(80))')
            connection.exec_driver_sql("INSERT INTO user VALUES (1, 'owner')")
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            upgrade_database(self.engine)
        self.assertEqual(sa.inspect(self.engine).get_table_names(), ['user'])
        with self.engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql('select username from user').scalar(), 'owner')
    def test_unknown_revision_does_not_stamp_or_change_schema(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE alembic_version (version_num VARCHAR(32))')
            connection.exec_driver_sql("INSERT INTO alembic_version VALUES ('unknown_history')")
        with self.assertRaises(Exception):
            upgrade_database(self.engine)
        self.assertEqual(sa.inspect(self.engine).get_table_names(), ['alembic_version'])
    def test_head_with_missing_tables_is_rejected(self):
        with self.engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE alembic_version (version_num VARCHAR(32))')
            connection.exec_driver_sql("INSERT INTO alembic_version VALUES ('d4e52098ab61')")
        with self.assertRaisesRegex(RuntimeError, 'revision'):
            upgrade_database(self.engine)
    def test_web_import_does_not_access_database(self):
        code = """
from extensions import db
from sqlalchemy.engine import Engine
from unittest.mock import patch
with patch.object(db, 'create_all', side_effect=AssertionError('create_all at startup')), patch.object(Engine, 'connect', side_effect=AssertionError('database access at startup')):
    import app
"""
        env = dict(os.environ, APP_ENV='testing', DATABASE_URL='sqlite://', SECRET_KEY='testing-key', PYTHONUTF8='1', PYTHONIOENCODING='utf-8', CELERY_BROKER_URL='memory://', CELERY_RESULT_BACKEND='cache+memory://')
        result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True, encoding='utf-8', errors='replace')
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
