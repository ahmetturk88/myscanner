"""Windows programs: digital signature and brand-named installers; byte patterns that ordinary programs don't trip (file-evidence-v6)."""
import datetime
import glob
import os
import struct
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from services.file_deep_analyzer import FileDeepAnalyzer
from services.file_report_view import plain_file_report
from services.format_inspectors import authenticode_signer, inspect_program, program_brand
from services.report_i18n import translate_plain



def launchers():
    """pip's own Windows launcher: a real, unsigned Windows program every Python install has."""
    try:
        import pip._vendor.distlib as distlib
        folder = os.path.dirname(distlib.__file__)
    except ImportError:
        folder = ''
    found = [os.path.join(folder, n) for n in ('t64.exe', 'w64.exe') if folder and os.path.exists(os.path.join(folder, n))]
    return found or sorted(glob.glob(os.path.expanduser('~/.cache/uv/archive-v0/*/distlib/t64.exe')))  # Debian's pip leaves them out


LAUNCHERS = launchers()


def table(organization):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization), x509.NameAttribute(NameOID.COMMON_NAME, organization)])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    der = pkcs7.PKCS7SignatureBuilder().set_data(b'x').add_signer(cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, [])
    return struct.pack('<IHH', 8 + len(der), 0x200, 2) + der


def analyze(content, name):
    with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value={'status': 'not_found', 'is_malicious': False, 'sources': []}), \
            patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}):
        return FileDeepAnalyzer().comprehensive_analysis(content, name)


class SignatureTests(unittest.TestCase):
    def test_signer_name_is_read(self):
        self.assertEqual(authenticode_signer(table('OpenAI, L.L.C.')), 'OpenAI, L.L.C.')
        self.assertIsNone(authenticode_signer(b'\0' * 8))

    def test_brand_named_program_must_be_signed(self):
        self.assertEqual(program_brand('ChatGPT_Installer.exe'), 'ChatGPT')
        self.assertIsNone(program_brand('python-3.12.exe'))
        fake = inspect_program('ChatGPT_Installer.exe', {'has_digital_signature': False})
        self.assertTrue(fake['raises_review'])
        self.assertEqual(fake['findings'][0]['title'], 'A fake ChatGPT installer?')
        real = inspect_program('ChromeSetup.exe', {'has_digital_signature': True, 'signer': 'Google LLC'})
        self.assertFalse(real['raises_review'])
        self.assertEqual(real['row'], {'name': 'Digital signature', 'state': 'ok', 'result': 'Google LLC'})
        plain = inspect_program('tool.exe', {'has_digital_signature': False})
        self.assertFalse(plain['raises_review'])
        self.assertEqual(plain['findings'][0]['level'], 'info')


@unittest.skipUnless(LAUNCHERS, 'needs a real Windows program (pip launcher)')
class RealProgramTests(unittest.TestCase):
    def test_an_ordinary_program_trips_no_byte_pattern(self):
        report = analyze(open(LAUNCHERS[0], 'rb').read(), 'launcher.exe')
        self.assertEqual(report['yara']['matched_rules'], [])
        self.assertEqual(report['verdict'], 'not_found')
        self.assertIn(('Digital signature', 'info', 'Not signed'), [(c['name'], c['state'], c['result']) for c in plain_file_report(report)['checks']])

    def test_unsigned_chatgpt_installer_needs_care(self):
        report = analyze(open(LAUNCHERS[0], 'rb').read(), 'ChatGPT_Installer.exe')
        self.assertEqual(report['verdict'], 'suspicious')
        plain = plain_file_report(report)
        self.assertEqual(plain['reasons'][0]['title'], 'A fake ChatGPT installer?')
        self.assertEqual(translate_plain(plain, 'tr')['reasons'][0]['title'], 'Sahte bir ChatGPT yükleyicisi mi?')


if __name__ == '__main__':
    unittest.main()
