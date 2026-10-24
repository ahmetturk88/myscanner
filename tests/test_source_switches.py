"""Operator switches for external sources, and the local DB-IP Lite IP location."""
import datetime
import gzip
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from services import ip_location
from services.source_switches import SOURCES, source_enabled

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import update_dbip  # noqa: E402


def off(*names):
    return patch.dict(os.environ, {'MYSCANNER_DISABLED_SOURCES': ', '.join(names)})


class SwitchTests(unittest.TestCase):
    def test_all_on_by_default_and_list_is_case_insensitive(self):
        with patch.dict(os.environ, {'MYSCANNER_DISABLED_SOURCES': ''}):
            self.assertTrue(all(source_enabled(name) for name in SOURCES))
        with off('URLhaus ', 'abuseipdb'):
            self.assertFalse(source_enabled('urlhaus'))
            self.assertFalse(source_enabled('abuseipdb'))
            self.assertTrue(source_enabled('web_risk'))

    def test_unknown_source_name_in_code_is_an_error(self):
        with self.assertRaises(ValueError):
            source_enabled('urlhause')

    def test_disabled_sources_are_never_contacted(self):
        session = Mock()
        with off(*SOURCES), patch.dict(os.environ, {'URLHAUS_AUTH_KEY': 'k' * 32, 'ABUSEIPDB_API_KEY': 'k' * 32}):
            from services.web_risk import check_web_risk
            self.assertEqual(check_web_risk('https://example.com/', session, key='k' * 32)['status'], 'not_configured')
            from services.provider_credentials import abuseipdb_key
            self.assertIsNone(abuseipdb_key())
            from services.url_analyzer import URLDeepAnalyzer
            analyzer = URLDeepAnalyzer()
            analyzer.session = session
            self.assertEqual(analyzer.check_urlhaus('https://example.com/')['coverage_reason'], 'disabled_by_operator')
            from services.malwarebazaar_client import MalwareBazaarClient
            client = MalwareBazaarClient(auth_key='k' * 32)
            client.session = session
            self.assertEqual(client.check_hash('a' * 64)['reason'], 'disabled_by_operator')
            from services.subdomain_finder import SubdomainFinder
            names, source = SubdomainFinder().certificate_names('example.com', None)
            self.assertEqual((names, source['status']), (set(), 'unavailable'))
            from services.password_analyzer import PasswordAnalyzer
            analyzer = PasswordAnalyzer()
            analyzer.session = session
            self.assertEqual(analyzer.check_pwned('example')['status'], 'unavailable')
        session.get.assert_not_called()
        session.post.assert_not_called()

    def test_feeds_follow_their_switch(self):
        from services.tip_collector import feed_enabled
        with off('abuse_ch_feeds', 'phishtank'):
            self.assertFalse(feed_enabled('https://urlhaus.abuse.ch/downloads/text/'))
            self.assertFalse(feed_enabled('https://feodotracker.abuse.ch/downloads/ipblocklist.txt'))
            self.assertFalse(feed_enabled('https://data.phishtank.com/data/online-valid.json'))
            self.assertTrue(feed_enabled('https://openphish.com/feed.txt'))
            self.assertTrue(feed_enabled('https://notabuse.ch.example/feed'))


CITY = {'city': {'names': {'en': 'Istanbul'}}, 'continent': {'names': {'en': 'Asia'}},
        'country': {'iso_code': 'TR', 'names': {'en': 'Türkiye'}},
        'location': {'latitude': 41.01, 'longitude': 28.97},
        'subdivisions': [{'names': {'en': 'Istanbul'}}]}
ASN = {'autonomous_system_number': 9121, 'autonomous_system_organization': 'Turk Telekom'}


class LocationTests(unittest.TestCase):
    def readers(self, city, asn):
        return patch.object(ip_location, '_reader', side_effect=lambda name: {ip_location.CITY_FILE: city, ip_location.ASN_FILE: asn}[name])

    def test_lookup_maps_dbip_records(self):
        with self.readers(Mock(get=Mock(return_value=CITY)), Mock(get=Mock(return_value=ASN))):
            result = ip_location.lookup('85.105.0.1')
        self.assertEqual((result['country'], result['country_code'], result['city'], result['region']), ('Türkiye', 'TR', 'Istanbul', 'Istanbul'))
        self.assertEqual((result['asn'], result['org'], result['isp'], result['lat']), (9121, 'Turk Telekom', 'Turk Telekom', 41.01))

    def test_missing_databases_and_unknown_addresses(self):
        with self.readers(None, None):
            self.assertIsNone(ip_location.lookup('85.105.0.1'))
        with self.readers(Mock(get=Mock(return_value=None)), None):
            self.assertIsNone(ip_location.lookup('85.105.0.1')['country'])
        with self.assertRaises(ValueError):
            ip_location.lookup('not-an-ip')

    def test_reader_reopens_a_replaced_file(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'DBIP_DIRECTORY': folder}), \
                patch.object(ip_location.maxminddb, 'open_database', side_effect=lambda path: Mock(path=path)) as opener:
            self.assertIsNone(ip_location._reader(ip_location.CITY_FILE))
            path = Path(folder, ip_location.CITY_FILE)
            path.write_bytes(b'one')
            first = ip_location._reader(ip_location.CITY_FILE)
            self.assertIs(ip_location._reader(ip_location.CITY_FILE), first)
            os.utime(path, (1, 1))
            self.assertIsNot(ip_location._reader(ip_location.CITY_FILE), first)
            first.close.assert_called_once()
            self.assertEqual(opener.call_count, 2)
        ip_location._readers.clear()

    def test_ip_check_uses_local_location_and_credits_it(self):
        from services.ip_analyzer import IPAnalyzer
        from services.ip_report_view import plain_ip_report
        analyzer = IPAnalyzer()
        analyzer.session = Mock()
        with off(), patch.object(ip_location, 'lookup', return_value={**dict.fromkeys(('country', 'city', 'region', 'continent', 'timezone', 'org', 'isp', 'network_domain', 'country_code', 'asn', 'lat', 'lon')), 'country': 'Türkiye'}):
            result = analyzer._get_ip_info('85.105.0.1')
        self.assertEqual((result['coverage']['metadata'], result['metadata_source']), ('assessed', 'DB-IP Lite'))
        self.assertIn('DB-IP', result['metadata_attribution'])
        analyzer.session.get.assert_not_called()
        checks = plain_ip_report({**result, 'ip': '85.105.0.1'})['checks']
        self.assertIn('Türkiye (DB-IP)', [check['result'] for check in checks])
        with off(), patch.object(ip_location, 'lookup', return_value=None):
            self.assertEqual(analyzer._get_ip_info('85.105.0.1')['metadata_reason'], 'database_not_installed')
        with off('dbip'), patch.object(ip_location, 'lookup') as lookup:
            self.assertEqual(analyzer._get_ip_info('85.105.0.1')['metadata_reason'], 'disabled_by_operator')
            lookup.assert_not_called()


class UpdateScriptTests(unittest.TestCase):
    def test_months_fall_back_to_last_month(self):
        self.assertEqual(update_dbip.months(datetime.date(2026, 1, 1)), ['2026-01', '2025-12'])

    def test_installs_a_valid_file_and_rejects_others(self):
        good = b'data' + update_dbip.MARKER + b'metadata'
        def opener(month_ok, payload):
            def urlopen(url, timeout):
                if month_ok not in url:
                    raise update_dbip.urllib.error.HTTPError(url, 404, 'missing', {}, None)
                return io.BytesIO(gzip.compress(payload))
            return urlopen
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(update_dbip.urllib.request, 'urlopen', side_effect=opener('2026-09', good)):
                self.assertEqual(update_dbip.download('city', folder, datetime.date(2026, 10, 1))[0], '2026-09')
            self.assertEqual(Path(folder, 'dbip-city-lite.mmdb').read_bytes(), good)
            with patch.object(update_dbip.urllib.request, 'urlopen', side_effect=opener('2026-10', b'<html>error</html>')):
                with self.assertRaises(ValueError):
                    update_dbip.download('city', folder, datetime.date(2026, 10, 1))
            self.assertEqual(Path(folder, 'dbip-city-lite.mmdb').read_bytes(), good)
            self.assertEqual(sorted(os.listdir(folder)), ['dbip-city-lite.mmdb'])


if __name__ == '__main__':
    unittest.main()
