"""Threat intelligence lookups against a disposable in-memory database.

The previous version of these checks used the application's configured
database and only printed results; these tests isolate state and assert.
"""
import os
import unittest
from unittest.mock import patch

from flask import Flask

from extensions import db
from models import IoCEntry, IoCSource


class TIPTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY='test-only', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_missing_indicator_is_not_reported_as_safe(self):
        from services.ioc_lookup import IoCLookup
        result = IoCLookup().lookup('192.0.2.1', 'ip')
        self.assertFalse(result['found'])
        self.assertEqual(result['count'], 0)
        self.assertNotIn('clean', result['summary'].lower())
        self.assertIn('does not establish safety', result['summary'])

    def test_stored_indicator_is_found_with_its_severity(self):
        from services.ioc_lookup import IoCLookup
        db.session.add(IoCEntry(value='198.51.100.7', ioc_type='ip', severity='high', confidence=90))
        db.session.commit()
        result = IoCLookup().lookup('198.51.100.7', 'ip')
        self.assertTrue(result['found'])
        self.assertEqual(result['highest_severity'], 'high')

    def test_inactive_indicator_is_ignored(self):
        from services.ioc_lookup import IoCLookup
        db.session.add(IoCEntry(value='198.51.100.8', ioc_type='ip', severity='high', is_active=False))
        db.session.commit()
        self.assertFalse(IoCLookup().lookup('198.51.100.8', 'ip')['found'])

    def test_default_sources_are_initialized_once(self):
        from services.tip_collector import TIPCollector
        collector = TIPCollector()
        added = collector.initialize_default_sources()
        self.assertGreater(added, 0)
        self.assertEqual(IoCSource.query.count(), added)
        self.assertEqual(collector.initialize_default_sources(), 0)

    def test_misp_is_not_configured_without_credentials(self):
        from services.misp_client import MISPClient
        with patch.dict(os.environ, {'MISP_URL': '', 'MISP_API_KEY': ''}):
            self.assertFalse(MISPClient().is_configured)


if __name__ == '__main__':
    unittest.main()
