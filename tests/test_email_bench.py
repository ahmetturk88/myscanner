"""The email benchmark turns a phishing-link list into one scam sender address per host."""
import io
import unittest
from unittest.mock import patch

from scripts import email_bench


class EmailBenchTests(unittest.TestCase):
    def test_one_address_per_host_and_no_ip_addresses(self):
        links = 'https://mydpd.kslud.top/track\n# note\nhttp://1.2.3.4/x\nhttps://MYDPD.kslud.top/other\nexample.com/x\n'
        with patch('sys.stdin', io.StringIO(links)):
            self.assertEqual(email_bench.scam_addresses('-'), ['info@mydpd.kslud.top', 'info@example.com'])

    def test_real_addresses_must_not_be_dangerous(self):
        self.assertNotIn('dangerous', email_bench.LEGIT_OK)
        self.assertIn('dangerous', email_bench.SCAM_OK)
        with patch.object(email_bench, 'check', side_effect=lambda e: (e, 'dangerous', '-')), patch('builtins.print'):
            self.assertFalse(email_bench.bench('x', ['a@b.com'], email_bench.LEGIT_OK))


if __name__ == '__main__':
    unittest.main()
