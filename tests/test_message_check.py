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
            return 'Sure: {"verdict": "scam", "reasons": ["Gerçek PTT mesajı ücret istemez."], "actions": ["Linke tıkla."]}'
        result = mc.assess('Merhaba, yarın 0532 123 45 67 numaradan arar mısın?', language='tr', analyzer=FakeAnalyzer(), ai=ai)
        self.assertNotIn('123 45 67', seen[0])
        self.assertIn('[phone]', seen[0])
        self.assertEqual(result['plain']['tone'], 'caution')  # rules said safe; without evidence the AI raises one step only
        self.assertEqual(result['plain']['ai_reasons'], ['Gerçek PTT mesajı ücret istemez.'])
        self.assertEqual(result['plain']['actions'], mc.ACTIONS['caution'])  # advice is always ours, never the AI's
        strong = mc.assess('Hesabınız askıya alındı, lütfen bizi arayın.', analyzer=FakeAnalyzer(), ai=ai)
        self.assertEqual(strong['plain']['tone'], 'danger')  # a strong sign found by the rules lets the AI go all the way
        mild = mc.assess(PARCEL, analyzer=FakeAnalyzer(), ai=lambda s, t: '{"verdict": "safe", "reasons": [], "actions": []}')
        self.assertEqual(mild['plain']['tone'], 'danger')  # parcel + fee + pressure + link: the AI can't lower it

    def test_without_ai_the_rules_decide_and_nonsense_from_the_ai_is_ignored(self):
        self.assertEqual(mc.assess(PARCEL, analyzer=FakeAnalyzer(), ai=False)['plain']['tone'], 'danger')
        self.assertEqual(mc.assess('Toplantı saat 3te, unutma.', analyzer=FakeAnalyzer(), ai=lambda s, t: 'not json')['plain']['tone'], 'safe')
        self.assertFalse(mc.assess('Toplantı saat 3te.', analyzer=FakeAnalyzer(), ai=lambda s, t: '{"verdict": "maybe"}')['ai'])
        caution = mc.assess('Tebrikler, çekilişi kazandınız!', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual(caution['plain']['tone'], 'caution')

    def test_one_time_codes_are_masked(self):
        for text in ('Doğrulama kodunuz 482913. Kimseyle paylaşmayın.', '482913 is your WhatsApp code', 'رمز التحقق 556677'):
            masked, counts = mc.redact(text)
            self.assertNotIn('482913', masked)
            self.assertNotIn('556677', masked)
            self.assertEqual(counts, {'code': 1})
        self.assertEqual(mc.redact('Toplantı 2026 yılında, saat 1530')[1], {})

    def test_a_real_code_message_is_not_a_scam_but_asking_for_the_code_is(self):
        real = mc.assess('Garanti BBVA: Doğrulama kodunuz 482913. Kimseyle paylaşmayın.', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual(real['plain']['tone'], 'safe')
        self.assertEqual(real['plain']['actions'], mc.CODE_NOTICE_ACTIONS)
        for text in ('Merhaba, yanlışlıkla sana bir kod gönderdim, gelen 6 haneli kodu bana atar mısın?',
                     'Please send me the code I sent you by mistake', 'ابعتلي الكود اللي وصلك'):
            self.assertEqual(mc.assess(text, analyzer=FakeAnalyzer(), ai=False)['plain']['tone'], 'danger', text)
        self.assertEqual(mc.find_signals('Telefonunuza gelen kodu uygulamaya girin.'), [])

    def test_debts_fines_and_official_addresses(self):
        hgs = 'HGS geçiş ihlali nedeniyle 245 TL borcunuz bulunmaktadır. Ceza almamak için hemen ödeyin: hgs-odeme.com/tr'
        self.assertEqual(mc.assess(hgs, analyzer=FakeAnalyzer(), ai=False)['plain']['tone'], 'danger')
        real = mc.assess('PTT: Gönderiniz dağıtıma çıkmıştır. Takip: https://gonderitakip.ptt.gov.tr/Track?q=1', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual((real['links'][0]['state'], real['plain']['tone']), ('official', 'safe'))
        for host in ('ptt.gov.tr.kargo-takip.com', 'ptt-gov.tr', 'xptt.gov.tr.evil.com'):
            self.assertFalse(mc.is_official(host), host)
        listed = mc.assess('Takip: https://ptt.gov.tr/x', analyzer=FakeAnalyzer(listed={'ptt.gov.tr'}), ai=False)
        self.assertEqual(listed['links'][0]['state'], 'bad')  # a threat list still wins over the name

    def test_no_signs_only_when_every_link_was_looked_up(self):
        many = mc.assess('a.com/1 b.com/2 c.com/3 d.com/4 e.com/5', analyzer=FakeAnalyzer(), ai=False)['plain']
        self.assertEqual(many['tone'], 'unknown')
        self.assertIn('We checked 3 of the 5 links.', [r['detail'] for r in many['reasons']])
        self.assertEqual(many['checks'][0]['result'], '3 of 5 checked')

        class Down(FakeAnalyzer):
            def check_osint_sources(self, url):
                raise TimeoutError
        down = mc.assess('Bak: site.com/x', analyzer=Down(), ai=False)
        self.assertEqual((down['links'][0]['state'], down['plain']['tone']), ('na', 'unknown'))

    def test_ai_is_off_unless_switched_on(self):
        asked = []
        with patch.dict('os.environ', {'MESSAGE_CHECK_AI': ''}), patch('services.ai_assistant.enabled', return_value=True), \
                patch('services.ai_assistant.stream', side_effect=lambda *a: asked.append(a) or iter(())):
            result = mc.assess('Toplantı saat 3te.', analyzer=FakeAnalyzer())
        self.assertEqual((asked, result['ai']), ([], False))
        self.assertEqual(result['plain']['checks'][2]['result'], 'Off')
        with patch.dict('os.environ', {'MESSAGE_CHECK_AI': '1'}):
            self.assertTrue(mc.ai_switched_on())

    def test_the_warning_to_share_never_carries_the_message(self):
        plain = mc.assess(PARCEL, analyzer=FakeAnalyzer(listed={'ptt-kargo.info'}), ai=False)['plain']
        self.assertEqual(plain['share_text'], mc.SHARE['danger'])
        for part in ('ptt-kargo', '0532', 'Kargonuz'):
            self.assertNotIn(part, plain['share_text'])
        self.assertTrue(translate_plain(plain, 'tr')['share_text'].startswith('Dikkat:'))
        self.assertEqual(mc.assess('Toplantı saat 3te.', analyzer=FakeAnalyzer(), ai=False)['plain']['share_text'], '')

    def test_where_to_check_comes_from_our_own_official_list(self):
        hgs = mc.assess('HGS geçiş ihlali nedeniyle borcunuz var, hemen ödeyin: hgs-odeme.com/tr', language='tr',
                        analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual([(v['key'], v['url']) for v in hgs['verify']], [('hgs', 'https://www.turkiye.gov.tr')])
        self.assertIn('İhlalli Geçiş', hgs['verify'][0]['how'])
        self.assertTrue(hgs['verify'][0]['how'].startswith('Gerçek'))  # in the reader's language
        bank = mc.assess('Ziraat: hesabınızda şüpheli işlem var, hemen arayın', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual([v['key'] for v in bank['verify']], ['ziraat'])  # the named bank, not "your bank" too
        parcel = mc.assess(PARCEL, analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual([v['key'] for v in parcel['verify']], ['ptt'])
        for key, _, _, url, _ in mc.VERIFY:
            self.assertTrue(url is None or (url.startswith('https://') and mc.is_official(mc.urlparse(url).hostname)), key)
        self.assertEqual(mc.assess('Toplantı saat 3te.', analyzer=FakeAnalyzer(), ai=False)['verify'], [])

    def test_a_message_without_a_link_still_says_what_it_wants(self):
        result = mc.assess('Hesabınızda şüpheli işlem tespit edildi. Hemen 0850 222 00 00 numarayı arayın.',
                           analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual(result['plain']['tone'], 'danger')
        self.assertEqual(result['asks'], ['Call a number'])
        self.assertEqual(result['plain']['reasons'][0]['title'], 'No link, but it asks you to act')
        iban = mc.assess('Annen hastanede, acil IBAN TR12 0006 2000 1234 0006 2954 32 hesabına para gönder', analyzer=FakeAnalyzer(), ai=False)
        self.assertIn('Send money or pay a fee', iban['asks'])

    def test_a_full_link_scan_can_only_make_a_link_worse_or_confirm_it(self):
        base = lambda state: {'link': 'x.com/a', 'shown': 'x[.]com/a', 'host': 'x.com', 'state': state, 'notes': []}  # noqa: E731
        self.assertEqual(mc.merge_scan(base('ok'), 'running', 'pending')['state'], 'scanning')
        self.assertEqual(mc.merge_scan(base('bad'), 'running', 'pending')['state'], 'bad')
        self.assertEqual(mc.merge_scan(base('ok'), 'completed', 'malicious')['state'], 'bad')
        self.assertEqual(mc.merge_scan(base('ok'), 'partial', 'suspicious')['state'], 'warn')
        self.assertEqual(mc.merge_scan(base('bad'), 'completed', 'harmless')['state'], 'bad')  # a threat list still wins
        self.assertEqual(mc.merge_scan(base('na'), 'completed', 'harmless')['state'], 'ok')
        self.assertEqual(mc.merge_scan(base('na'), 'error', 'unknown')['state'], 'na')
        state = mc.prepare('Bak: site.com/x', analyzer=FakeAnalyzer(), ai=False)
        mc.merge_scan(state['links'][0], 'completed', 'malicious')
        result = mc.build(state)
        self.assertEqual(result['plain']['tone'], 'danger')
        self.assertEqual(result['plain']['reasons'][0]['title'], 'Our link scan found a dangerous link')

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


    def test_animated_images_and_too_many_at_once_are_refused(self):
        import io
        from PIL import Image
        from services import message_ocr as ocr
        buffer = io.BytesIO()
        Image.new('RGB', (60, 60), 'red').save(buffer, 'WEBP', save_all=True, append_images=[Image.new('RGB', (60, 60), 'blue')])
        with self.assertRaises(ocr.OCRError) as caught:
            ocr.read_text(buffer.getvalue(), run=lambda path: 'never')
        self.assertEqual(str(caught.exception), 'bad_image')
        with patch.object(ocr, '_SLOTS') as slots:
            slots.acquire.return_value = False
            with self.assertRaises(ocr.OCRError) as caught:
                ocr.read_text(png(), run=lambda path: 'never')
        self.assertEqual(str(caught.exception), 'busy')
        command = ocr._command('/tmp/x.png')
        if command[0].endswith('prlimit'):
            self.assertIn(f'--as={ocr.MEMORY}', command)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        from models import AuthRateLimit
        AuthRateLimit.query.delete()  # the per-minute limit starts fresh for every test
        User.query.filter(User.email.like('%@msg.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='msguser', email='u@msg.invalid', password_hash='unused', is_verified=True)
        db.session.add(self.user)
        db.session.commit()
        self.client = self.app.test_client()
        quiet = patch('services.url_scan_request.start_quietly', return_value=None)  # no job queue in tests
        quiet.start()
        self.addCleanup(quiet.stop)
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
        self.assertIn('Ekran görüntüsünü buraya bırakın', page)
        self.assertNotIn('id="mc-text"', page)  # no box to paste the message into: a screenshot only
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

    def test_five_checks_a_minute_at_most(self):
        quiet = {'plain': {'tone': 'safe'}, 'links': []}
        with patch('services.message_check.assess', return_value=quiet):
            codes = [self.post({'text': 'Toplantı saat 3te.'}).status_code for _ in range(6)]
        self.assertEqual(codes[:5], [200] * 5)
        self.assertEqual(codes[5], 429)

    def test_was_this_right_keeps_no_text_and_no_account(self):
        from flask import g
        from models import MessageFeedback
        MessageFeedback.query.delete()
        db.session.commit()

        def send(body):
            g.pop('csrf_token', None)
            page = self.client.get('/message-check').get_data(as_text=True)
            token = page.split('name="csrf-token" content="')[1].split('"')[0]
            return self.client.post('/api/message-feedback', data=json.dumps(body), content_type='application/json',
                                    headers={'X-CSRFToken': token})
        self.assertEqual(send({'tone': 'safe', 'answer': 'scam', 'signals': ['bank', 'code_notice']}).status_code, 200)
        row = MessageFeedback.query.one()
        self.assertEqual((row.tone, row.answer, row.signals), ('safe', 'scam', 'bank,code_notice'))
        self.assertFalse(hasattr(row, 'user_id'))
        for bad in ({'tone': 'safe', 'answer': 'maybe', 'signals': []}, {'tone': 'x', 'answer': 'real', 'signals': []},
                    {'tone': 'safe', 'answer': 'real', 'signals': ['Kargonuz 0532 123 45 67']}):
            self.assertEqual(send(bad).status_code, 400)
        self.assertEqual(MessageFeedback.query.count(), 1)

    def test_links_get_a_full_scan_and_the_verdict_waits_for_it(self):
        from flask import g
        from models import Scan

        def send(url, body):
            g.pop('csrf_token', None)
            g.pop('_login_user', None)
            page = self.client.get('/message-check').get_data(as_text=True)
            token = page.split('name="csrf-token" content="')[1].split('"')[0]
            return self.client.post(url, data=json.dumps(body), content_type='application/json', headers={'X-CSRFToken': token})
        scan = Scan(url='http://ptt-kargo.info/takip?no=1', user_id=self.user.id, status='running', verdict='pending', result='x')
        db.session.add(scan)
        db.session.commit()
        fake = FakeAnalyzer()
        fake.session = type('S', (), {'close': lambda self: None})()
        with patch('services.url_analyzer.URLDeepAnalyzer', lambda: fake), patch('services.ai_assistant.enabled', return_value=False), \
                patch('services.url_scan_request.start_quietly', return_value=scan.id) as started:
            first = send('/api/check-message', {'text': PARCEL, 'lang': 'tr'})
        self.assertEqual(first.status_code, 202)
        self.assertEqual(started.call_args[0][0], 'http://ptt-kargo.info/takip?no=1')
        token = first.get_json()['token']
        self.assertNotIn('45 67', token)
        self.assertEqual(send('/api/check-message/finish', {'token': token}).status_code, 202)  # still scanning
        scan.status, scan.verdict = 'completed', 'malicious'
        db.session.commit()
        done = send('/api/check-message/finish', {'token': token})
        self.assertEqual(done.status_code, 200)
        data = done.get_json()
        self.assertEqual((data['plain']['tone'], data['links'][0]['state'], data['links'][0]['scan_id']), ('danger', 'bad', scan.id))
        self.assertEqual(send('/api/check-message/finish', {'token': token + 'x'}).status_code, 400)  # tampered
        other = User(username='msgother', email='o@msg.invalid', password_hash='unused', is_verified=True)
        db.session.add(other)
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(other.id)
        self.assertEqual(send('/api/check-message/finish', {'token': token}).status_code, 400)  # someone else's check

    def test_the_app_reaches_it_as_a_tool(self):
        from routes.mobile_api import TOOLS
        self.assertEqual(TOOLS['message'], 'api_check_message')
        self.assertEqual(TOOLS['message-feedback'], 'api_message_feedback')
        self.assertEqual(TOOLS['message-finish'], 'api_message_finish')


if __name__ == '__main__':
    unittest.main()
