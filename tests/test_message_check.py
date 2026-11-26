"""Message check: masking, links, scam signs, link lookups, AI opinion and the web/app API. No network, no real AI."""
import json
import unittest
from unittest.mock import patch

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import User
from services import message_check as mc
from services.report_i18n import translate_plain

PARCEL = 'PTT: Kargonuz adres eksikligi nedeniyle bekliyor. 24 saat icinde ek ücret ödeyin: ptt-kargo.info/takip?no=1 Bilgi: 0532 123 45 67'


class FakeAnalyzer:
    """Stands in for URLAnalyzer: never touches the network. `listed` hosts are on a threat list."""
    def __init__(self, listed=(), tricks=()):
        self.listed, self.tricks, self.asked = set(listed), set(tricks), []

    def check_phishing_indicators(self, url):
        return {'issues': ['Possible typosquatting of paypal.com'] if any(t in url for t in self.tricks) else []}

    def check_osint_sources(self, url):
        self.asked.append(url)
        bad = any(h in url for h in self.listed)
        return {'urlhaus': bad, 'urlhaus_status': 'matched' if bad else 'not_found',
                'web_risk': {'status': 'matched' if bad else 'not_found'}, 'osint_risk_score': 60 if bad else 0}


class EngineTests(unittest.TestCase):
    def test_personal_data_is_masked_before_anything_else(self):
        masked, counts = mc.redact('IBAN TR12 0006 2000 1234 0006 2954 32, ara 0532 123 45 67 / +90 532 1234567, '
                                   'mail ali@ornek.com, TC 12345678901, kart 4111 1111 1111 1111')
        for secret in ('2954', '45 67', '1234567', 'ali@', '12345678901', '4111'):
            self.assertNotIn(secret, masked)
        self.assertEqual(counts, {'iban': 1, 'card': 1, 'email': 1, 'phone': 2, 'national_id': 1})

    def test_links_include_the_bare_forms_scam_texts_use_but_not_emails(self):
        self.assertEqual(mc.find_links('ptt-kargo.info/takip?no=1, https://bit.ly/x). www.firma.com.tr info@firma.com https://bit.ly/x'),
                         ['ptt-kargo.info/takip?no=1', 'https://bit.ly/x', 'www.firma.com.tr'])
        self.assertEqual(mc.defang('https://ptt-kargo.info/takip'), 'hxxps://ptt-kargo[.]info/takip')

    def test_signals_find_scam_tricks_and_leave_ordinary_words_alone(self):
        self.assertEqual(mc.find_signals(PARCEL), ['payment', 'parcel', 'urgent'])
        self.assertEqual(mc.find_signals('Akşam arasında buluşalım mı? Annem selam söyledi.'), [])

    def test_a_listed_link_is_a_scam_whatever_the_ai_says(self):
        analyzer = FakeAnalyzer(listed={'ptt-kargo.info'})
        result = mc.assess(PARCEL, analyzer=analyzer, ai=lambda system, turns: '{"verdict": "safe", "reasons": [], "actions": []}')
        self.assertEqual(result['plain']['tone'], 'danger')
        self.assertEqual(result['links'][0]['state'], 'bad')
        self.assertEqual(analyzer.asked, ['http://ptt-kargo.info/takip?no=1'])  # looked up, never fetched

    def test_the_ai_reads_only_masked_text_and_can_only_make_it_stricter(self):
        seen = []

        def ai(system, turns):
            seen.append(turns[0]['text'])
            return 'Sure: {"verdict": "scam", "reasons": ["Gerçek PTT mesajı ücret istemez."], "actions": ["Linke tıklama."]}'
        result = mc.assess('Merhaba, yarın 0532 123 45 67 numaradan arar mısın?', language='tr', analyzer=FakeAnalyzer(), ai=ai)
        self.assertNotIn('123 45 67', seen[0])
        self.assertIn('[phone]', seen[0])
        self.assertEqual(result['plain']['tone'], 'danger')  # rules said safe, the AI raised it
        self.assertEqual(result['plain']['ai_reasons'], ['Gerçek PTT mesajı ücret istemez.'])
        self.assertEqual(result['plain']['actions'], ['Linke tıklama.'])
        mild = mc.assess(PARCEL, analyzer=FakeAnalyzer(), ai=lambda s, t: '{"verdict": "safe", "reasons": [], "actions": []}')
        self.assertEqual(mild['plain']['tone'], 'danger')  # parcel + fee + pressure + link: the AI can't lower it

    def test_without_ai_the_rules_decide_and_nonsense_from_the_ai_is_ignored(self):
        self.assertEqual(mc.assess(PARCEL, analyzer=FakeAnalyzer(), ai=False)['plain']['tone'], 'danger')
        self.assertEqual(mc.assess('Toplantı saat 3te, unutma.', analyzer=FakeAnalyzer(), ai=lambda s, t: 'not json')['plain']['tone'], 'safe')
        self.assertFalse(mc.assess('Toplantı saat 3te.', analyzer=FakeAnalyzer(), ai=lambda s, t: '{"verdict": "maybe"}')['ai'])
        caution = mc.assess('Tebrikler, çekilişi kazandınız!', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual(caution['plain']['tone'], 'caution')

    def test_report_reads_in_turkish(self):
        plain = mc.assess(PARCEL, analyzer=FakeAnalyzer(listed={'ptt-kargo.info'}), ai=False)['plain']
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(turkish['headline'], 'Bu mesaj dolandırıcılığa benziyor')
        self.assertIn('ptt-kargo[.]info/takip?no=1 tehlikeli olarak listelenmiş.', [r['detail'] for r in turkish['reasons']])


def png(color=(255, 255, 255), size=(400, 120)):
    import io
    from PIL import Image
    buffer = io.BytesIO()
    Image.new('RGB', size, color).save(buffer, 'PNG')
    return buffer.getvalue()


class OcrTests(unittest.TestCase):
    def test_only_real_images_of_a_sane_size_are_read(self):
        from services import message_ocr as ocr
        for data, reason in ((b'%PDF-1.7 not an image', 'bad_image'), (b'x' * (ocr.MAX_BYTES + 1), 'too_large')):
            with self.assertRaises(ocr.OCRError) as caught:
                ocr.read_text(data, run=lambda path: 'never')
            self.assertEqual(str(caught.exception), reason)
        with self.assertRaises(ocr.OCRError) as caught:
            ocr.read_text(png(), run=lambda path: '  ')
        self.assertEqual(str(caught.exception), 'no_text')

    def test_dark_screenshots_are_inverted_and_the_file_is_gone_after(self):
        from PIL import Image, ImageStat
        from services import message_ocr as ocr
        seen = {}

        def run(path):
            seen['path'] = path
            with Image.open(path) as image:
                seen['mean'] = ImageStat.Stat(image).mean[0]
            return 'Kargonuz   bekliyor\n\n ptt-kargo.info/takip '
        self.assertEqual(ocr.read_text(png((17, 24, 39)), run=run), 'Kargonuz bekliyor\nptt-kargo.info/takip')
        self.assertGreater(seen['mean'], 128)  # inverted: dark text on light, as Tesseract reads best
        self.assertFalse(seen['path'].exists())


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        User.query.filter(User.email.like('%@msg.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='msguser', email='u@msg.invalid', password_hash='unused', is_verified=True)
        db.session.add(self.user)
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def post(self, body):
        from flask import g
        g.pop('csrf_token', None)
        page = self.client.get('/message-check?lang=tr').get_data(as_text=True)
        token = page.split('name="csrf-token" content="')[1].split('"')[0]
        return self.client.post('/api/check-message', data=json.dumps(body), content_type='application/json',
                                headers={'X-CSRFToken': token})

    def test_page_and_api(self):
        page = self.client.get('/message-check?lang=tr').get_data(as_text=True)
        self.assertIn('Garip bir mesaj mı aldınız?', page)
        fake = FakeAnalyzer()
        fake.session = type('S', (), {'close': lambda self: None})()
        with patch('services.url_analyzer.URLDeepAnalyzer', lambda: fake), \
                patch('services.ai_assistant.enabled', return_value=False):
            response = self.post({'text': PARCEL, 'lang': 'tr'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['plain']['tone'], 'danger')
        self.assertEqual(data['plain']['headline'], 'Bu mesaj dolandırıcılığa benziyor')
        self.assertNotIn('45 67', json.dumps(data))  # the reply never repeats masked personal data
        self.assertEqual(self.post({'text': '   '}).status_code, 400)
        self.assertEqual(self.post({'text': 'x' * 6001}).status_code, 400)

    def test_a_screenshot_is_read_and_checked(self):
        from flask import g
        g.pop('csrf_token', None)
        page = self.client.get('/message-check?lang=tr').get_data(as_text=True)
        token = page.split('name="csrf-token" content="')[1].split('"')[0]
        import io
        fake = FakeAnalyzer()
        fake.session = type('S', (), {'close': lambda self: None})()
        with patch('services.message_ocr.read_text', return_value=PARCEL), \
                patch('services.url_analyzer.URLDeepAnalyzer', lambda: fake), \
                patch('services.ai_assistant.enabled', return_value=False):
            response = self.client.post('/api/check-message', data={'image': (io.BytesIO(png()), 'shot.png'), 'lang': 'tr'},
                                        content_type='multipart/form-data', headers={'X-CSRFToken': token})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['plain']['tone'], 'danger')
        self.assertIn('[phone]', data['text'])  # what was read is shown back with personal data hidden
        self.assertNotIn('45 67', data['text'])
        from services.message_ocr import OCRError
        with patch('services.message_ocr.read_text', side_effect=OCRError('no_text')):
            refused = self.client.post('/api/check-message', data={'image': (io.BytesIO(png()), 'shot.png')},
                                       content_type='multipart/form-data', headers={'X-CSRFToken': token})
        self.assertEqual((refused.status_code, refused.get_json()['code']), (400, 'ocr_no_text'))

    def test_the_app_reaches_it_as_a_tool(self):
        from routes.mobile_api import TOOLS
        self.assertEqual(TOOLS['message'], 'api_check_message')


if __name__ == '__main__':
    unittest.main()
