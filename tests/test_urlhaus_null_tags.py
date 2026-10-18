"""URLhaus sends "tags": null for entries without tags; a listed URL must still be reported."""
import unittest
from unittest import mock

from services.url_analyzer import URLDeepAnalyzer


class NullTagsTests(unittest.TestCase):
    def test_listed_url_without_tags_is_reported_as_malicious(self):
        analyzer = URLDeepAnalyzer()
        response = mock.Mock(status_code=200)
        response.json.return_value = {'query_status': 'ok', 'id': '1', 'threat': 'malware_download', 'tags': None,
                                      'firstseen': '2026-10-17', 'lastseen': None, 'reporter': 'x'}
        with mock.patch.dict('os.environ', {'URLHAUS_AUTH_KEY': 'key', 'URLHAUS_AUTH_KEY_FILE': ''}), \
                mock.patch.object(analyzer.session, 'post', return_value=response), \
                mock.patch.object(analyzer, '_save_phishing_cache'):
            result = analyzer.check_osint_sources('http://115.51.81.89:49341/i')
        self.assertTrue(result['urlhaus'])
        self.assertEqual(result['urlhaus_status'], 'matched')
        self.assertEqual(result['urlhaus_details']['tags'], [])


if __name__ == '__main__':
    unittest.main()
