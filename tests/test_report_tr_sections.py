"""Technical report sections in Turkish, and page titles decoded as UTF-8."""
import unittest

from services.site_i18n import _catalogs, _lookup
from services.url_analyzer import decode_page


def tr(text):
    return _lookup(text, _catalogs()['tr'], 'tr')


class ReportSectionTests(unittest.TestCase):
    def test_leading_symbols_are_kept_and_words_translated(self):
        self.assertEqual(tr('✓ Valid'), '✓ Geçerli')
        self.assertEqual(tr('📄 Page Content Analysis'), '📄 Sayfa İçeriği Analizi')
        self.assertEqual(tr('🚩 Red Flags (3)'), '🚩 Uyarı işaretleri (3)')
        self.assertEqual(tr('−20 pts'), '−20 puan')
        self.assertIsNone(tr('—'))

    def test_url_vet_observations_and_counts(self):
        self.assertEqual(tr('Very low traffic volume.'), 'Çok düşük trafik hacmi.')
        self.assertEqual(tr('Young domain (9 months old). Use caution.'), 'Yeni alan adı (9 aylık). Dikkatli ol.')
        self.assertEqual(tr('3 red flag(s) reported'), '3 uyarı işareti bildirildi')
        self.assertEqual(tr('282 days'), '282 gün')
        self.assertEqual(tr('5 of 5 evidence categories assessed'), '5 kanıt kategorisinden 5 tanesi değerlendirildi')

    def test_ai_panel_text_is_translated(self):
        import re
        source = open('static/ai_assistant.js', encoding='utf-8').read()
        for name in ('Understand this report', 'Sign in to chat'):
            self.assertIsNotNone(tr(name), name)
        for text in re.findall(r"'ai-(?:sub|note)', '((?:[^'\\]|\\.)+)'", source):
            self.assertIsNotNone(tr(text.replace("\\'", "'")), text)
        self.assertEqual(tr('Hi Ahmed, how can I help you stay safe today?'), 'Merhaba Ahmed, bugün güvende kalman için nasıl yardımcı olabilirim?')

    def test_every_verdict_reason_is_translated(self):
        import re
        source = open('services/url_assessment.py', encoding='utf-8').read()
        for message in re.findall(r"signal\('[a-z]+','[a-z_]+',[\d.]+,'([^']+)'\)", source):
            self.assertIsNotNone(tr(message), message)


class DecodeTests(unittest.TestCase):
    class Response:
        def __init__(self, body, content_type):
            self.content, self.headers = body, {'Content-Type': content_type}
            self.text = body.decode('latin-1')

    def test_utf8_page_without_charset_keeps_emoji(self):
        page = '<title>🎉 Qaado $50</title>'.encode()
        self.assertEqual(decode_page(self.Response(page, 'text/html')), '<title>🎉 Qaado $50</title>')

    def test_declared_charset_is_respected(self):
        page = '<title>café</title>'.encode('latin-1')
        self.assertEqual(decode_page(self.Response(page, 'text/html; charset=ISO-8859-1')), '<title>café</title>')


if __name__ == '__main__':
    unittest.main()
