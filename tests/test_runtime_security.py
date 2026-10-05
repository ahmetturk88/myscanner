import unittest
from services.runtime_security import security_settings


class RuntimeSecurityTests(unittest.TestCase):
    def test_production_refuses_missing_short_and_placeholder_keys(self):
        for key in ['', 'short', 'change-this-secret-key', 'your-secret-key-here-change-it']:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                security_settings({'APP_ENV': 'production', 'SECRET_KEY': key})

    def test_production_cookie_flags_and_debug(self):
        config = security_settings({'APP_ENV': 'production', 'SECRET_KEY': 'a' * 48, 'FLASK_DEBUG': '1'})
        self.assertFalse(config['DEBUG'])
        for prefix in ['SESSION', 'REMEMBER']:
            self.assertTrue(config[prefix + '_COOKIE_SECURE'])
            self.assertTrue(config[prefix + '_COOKIE_HTTPONLY'])
            self.assertEqual(config[prefix + '_COOKIE_SAMESITE'], 'Lax')

    def test_render_defaults_to_production(self):
        with self.assertRaises(RuntimeError):
            security_settings({'RENDER': 'true'})

    def test_local_missing_key_is_random_and_http_remains_usable(self):
        first, second = security_settings({}), security_settings({})
        self.assertNotEqual(first['SECRET_KEY'], second['SECRET_KEY'])
        self.assertFalse(first['SESSION_COOKIE_SECURE'])
        self.assertFalse(first['DEBUG'])

    def test_local_existing_key_is_preserved_and_debug_is_opt_in(self):
        self.assertEqual(security_settings({'SECRET_KEY': 'existing-local'})['SECRET_KEY'], 'existing-local')
        self.assertTrue(security_settings({'FLASK_DEBUG': '1'})['DEBUG'])

    def test_misspelled_environment_is_rejected(self):
        with self.assertRaises(RuntimeError):
            security_settings({'APP_ENV': 'prodution'})


if __name__ == '__main__':
    unittest.main()
