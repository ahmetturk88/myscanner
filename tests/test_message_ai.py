"""The message check's reviewer: what it is shown, how its answer is read, and the evidence it can't overrule."""
import io
import json
import unittest
from unittest.mock import patch

from services import message_ai
from services import message_check as mc
from test_message_check import PARCEL, FakeAnalyzer, png


def answer(**fields):
    base = {'is_message': True, 'kind': 'sms', 'claimed_sender': None, 'asks_for': [], 'lures': [], 'visible_links': [],
            'ignored_links': [], 'hidden_link': False, 'spam_folder': False, 'verdict': 'safe', 'summary': 'A message.',
            'reasons': []}
    return json.dumps(base | fields)


class ReviewerTests(unittest.TestCase):
    def test_only_a_valid_answer_is_used_and_lists_are_kept_to_known_values(self):
        self.assertIsNone(message_ai.parse('not json'))
        self.assertIsNone(message_ai.parse('{"verdict": "maybe"}'))
        parsed = message_ai.parse('Here: ' + answer(asks_for=['money', 'launch missiles'], lures=['parcel', 'x'], kind='fax',
                                                    claimed_sender='null', visible_links=['ptt-kargo.info/a', 'not a link']))
        self.assertEqual((parsed['asks_for'], parsed['lures'], parsed['kind'], parsed['claimed_sender']), (['money'], ['parcel'], 'other', None))
        self.assertEqual(parsed['visible_links'], ['ptt-kargo.info/a'])

    def test_the_image_sent_out_has_no_metadata_and_is_not_too_big(self):
        from PIL import Image
        source = io.BytesIO()
        exif = Image.Exif()
        exif[0x010F] = 'PhoneMaker'  # camera make
        Image.new('RGB', (4000, 3000), 'white').save(source, 'JPEG', exif=exif)
        prepared = message_ai.prepare_image(source.getvalue())
        with Image.open(io.BytesIO(prepared)) as image:
            self.assertLessEqual(max(image.size), message_ai.MAX_SIDE)
            self.assertFalse(image.getexif())
        self.assertIsNone(message_ai.prepare_image(b'not an image'))

    def test_nothing_is_sent_unless_switched_on_and_the_image_only_with_vision(self):
        sent = []

        def post(url, **kwargs):
            sent.append(kwargs['json'])
            return type('R', (), {'status_code': 200, 'json': lambda self: {'candidates': [{'content': {'parts': [{'text': answer()}]}}]}})()
        with patch.object(message_ai, 'gemini_key', return_value='k'), patch.object(message_ai, 'groq_key', return_value=''), \
                patch.object(message_ai.requests, 'post', side_effect=post):
            with patch.dict('os.environ', {'MESSAGE_CHECK_AI': '0', 'MESSAGE_CHECK_VISION': '1'}):
                self.assertIsNone(message_ai.review('text', {}, image=png()))
            with patch.dict('os.environ', {'MESSAGE_CHECK_AI': '1', 'MESSAGE_CHECK_VISION': '0'}):
                self.assertTrue(message_ai.review('text', {}, image=png()))
            with patch.dict('os.environ', {'MESSAGE_CHECK_AI': '1', 'MESSAGE_CHECK_VISION': '1'}):
                self.assertTrue(message_ai.review('text', {}, language='tr', image=png()))
        self.assertEqual(len(sent), 2)
        self.assertNotIn('inline_data', json.dumps(sent[0]))  # vision off: text only
        self.assertIn('inline_data', json.dumps(sent[1]))
        self.assertIn('Turkish', sent[1]['systemInstruction']['parts'][0]['text'])
        self.assertEqual(sent[1]['generationConfig']['temperature'], 0)  # the same image gives the same answer


    def test_admins_mode_shows_screenshots_to_the_reviewer_only_for_admins(self):
        admin, person = type('U', (), {'is_admin': True})(), type('U', (), {'is_admin': False})()
        with patch.dict('os.environ', {'MESSAGE_CHECK_VISION': 'admins'}):
            self.assertEqual((message_ai.vision_for(admin), message_ai.vision_for(person)), (True, False))
        with patch.dict('os.environ', {'MESSAGE_CHECK_VISION': '0'}):
            self.assertFalse(message_ai.vision_for(admin))


class GuardrailTests(unittest.TestCase):
    def ask(self, **fields):
        return lambda system, turns: answer(**fields)

    def test_a_page_that_explains_scams_is_not_a_scam_and_its_address_bar_is_not_scanned(self):
        page = ('myscanners.com/message-check\nKurallarımız kargo ücretleri, bloke hesaplar, borçlar, ödüller ve kod '
                'isteklerini arar. Hemen tıklayın.')
        result = mc.assess(page, analyzer=FakeAnalyzer(), ai=self.ask(is_message=False, kind='web_page', verdict='unsure'))
        self.assertTrue(result['not_message'])
        self.assertEqual((result['plain']['tone'], result['links'], result['signals']), ('unknown', [], []))
        self.assertEqual(result['plain']['headline'], 'We couldn’t find a message in this image')

    def test_a_listed_link_stays_dangerous_whatever_the_reviewer_says(self):
        result = mc.assess(PARCEL, analyzer=FakeAnalyzer(listed={'ptt-kargo.info'}),
                           ai=self.ask(is_message=False, verdict='safe', ignored_links=['ptt-kargo.info/takip?no=1']))
        self.assertEqual(result['plain']['tone'], 'danger')
        self.assertEqual(result['links'][0]['state'], 'bad')

    def test_the_reviewer_drops_only_the_addresses_it_names_and_adds_the_ones_it_reads(self):
        analyzer = FakeAnalyzer()
        text = 'chrome myscanners.com/messag\nKargonuz bekliyor: ptt-kargo.info/takip'
        result = mc.assess(text, analyzer=analyzer, ai=self.ask(verdict='scam', ignored_links=['myscanners.com/messag'],
                                                                 visible_links=['ptt-kargo.info/takip', 'bit.ly/x9']))
        self.assertEqual([l['link'] for l in result['links']], ['ptt-kargo.info/takip', 'bit.ly/x9'])
        kept = mc.assess(text, analyzer=FakeAnalyzer(), ai=self.ask(verdict='scam'))  # leaving a link out drops nothing
        self.assertEqual(len(kept['links']), 2)

    def test_a_hidden_link_is_never_safe_and_points_to_the_original_email(self):
        result = mc.assess('WhatsApp: Whit sent you a voice note. Listen to the full message', analyzer=FakeAnalyzer(),
                           ai=self.ask(verdict='safe', hidden_link=True))
        self.assertEqual(result['plain']['tone'], 'unknown')
        self.assertTrue(result['hidden_link'])
        self.assertEqual(result['plain']['reasons'][0]['title'], 'The link is hidden behind a button')

    def test_without_the_reviewer_the_rules_see_the_new_lures(self):
        voice = mc.assess('WhatsApp\nWhit online\nVoice message 0:23\n"Hey... I couldn\'t stop thinking about you last night"\n'
                          'Listen to the full message\nSpam değil', analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual(set(voice['signals']) >= {'romance', 'voice', 'hidden_cta', 'spam_mark'}, True)
        self.assertNotEqual(voice['plain']['tone'], 'safe')
        self.assertTrue(voice['hidden_link'])

    def test_the_summary_is_written_again_when_a_link_scan_finds_danger(self):
        state = mc.prepare('Bak: site.com/x', analyzer=FakeAnalyzer(), ai=self.ask(verdict='safe', summary='Harmless.'))
        mc.merge_scan(state['links'][0], 'completed', 'malicious')
        mc.refresh_review(state, ai=self.ask(verdict='scam', summary='The link is dangerous.'))
        result = mc.build(state)
        self.assertEqual((result['plain']['tone'], result['plain']['ai_summary']), ('danger', 'The link is dangerous.'))


EML = (b'Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=whatsapp-notify.top; dkim=none; dmarc=fail\r\n'
       b'From: "WhatsApp" <alerts@whatsapp-notify.top>\r\nSubject: Whit sent you a voice note\r\n'
       b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
       b'<html><head><script>alert(1)</script></head><body><p>Hey... I couldn\'t stop thinking about you</p>'
       b'<a href="https://voice-msg.example.top/play?id=1">Listen to the full message</a>'
       b'<a href="javascript:alert(1)">x</a></body></html>\r\n'
       b'--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename="v.zip"\r\n\r\nUEsDBA==\r\n--b--\r\n')


class EmailTests(unittest.TestCase):
    def test_the_real_address_behind_a_button_is_read_and_nothing_runs(self):
        from services import message_email
        text, info = message_email.read_email(EML)
        self.assertIn('https://voice-msg.example.top/play?id=1', text)
        self.assertNotIn('javascript:', text)
        self.assertNotIn('alert(1)', text)  # the script was dropped, never run
        self.assertEqual({k: info[k] for k in ('sender_domain', 'sender_name', 'auth', 'attachments')},
                         {'sender_domain': 'whatsapp-notify.top', 'sender_name': 'WhatsApp',
                          'auth': {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}, 'attachments': 1})
        self.assertNotIn('voice-msg', info['shown'])  # what the reader sees has no list of long addresses
        result = mc.assess(text, analyzer=FakeAnalyzer(), ai=False, email=info)
        self.assertEqual(result['links'][0]['link'], 'https://voice-msg.example.top/play?id=1')
        self.assertIn('auth_fail', result['signals'])
        self.assertEqual(result['plain']['tone'], 'danger')
        for bad in (b'not an email at all', b'x' * (message_email.MAX_BYTES + 1)):
            with self.assertRaises(message_email.EmailError):
                message_email.read_email(bad)

    def test_the_app_around_a_screenshot_is_left_out(self):
        screen = 'isem x # (c) + 5# (c)\nKalıcı olarak sil  Spam değil\nAHMET TÜRK merhaba, teklifimiz bugün bitiyor\n) © Yanıtla () Yönlendir |'
        self.assertEqual(mc.tidy(screen), 'AHMET TÜRK merhaba, teklifimiz bugün bitiyor')


class EmailFollowUpTests(unittest.TestCase):
    def test_a_known_name_from_an_unrelated_address_is_a_fake_sender(self):
        self.assertEqual(mc.sender_check('🟢 Whats App', 'piluflua.biz'), 'sender_fake')
        self.assertEqual(mc.sender_check('WhatsApp', 'whatsapp-notify.top'), 'sender_lookalike')
        self.assertIsNone(mc.sender_check('WhatsApp', 'facebookmail.com'))
        self.assertIsNone(mc.sender_check('Yurtiçi Kargo', 'bildirim.yurticikargo.com'))
        self.assertIsNone(mc.sender_check('Ali Yılmaz', 'gmail.com'))
        self.assertIsNone(mc.sender_check('Captain Cook', 'example.com'))  # "ptt" only as a word

    def test_many_random_addresses_on_one_site_are_checked_once_and_are_a_sign(self):
        links = ' '.join(f'https://{name}.piluflua.biz/x{i}?t=1' for i, name in enumerate(('v0z14a4acn', 'lyghwihhba', '9zlitcoi0a', 'ia6woqtrlz')))
        result = mc.assess('WhatsApp: You have been sent a request for correspondence. Open ' + links + ' https://ptt.gov.tr/a',
                           analyzer=FakeAnalyzer(), ai=False)
        self.assertEqual([mc.site_of(l['link']) for l in result['links']], ['piluflua.biz', 'ptt.gov.tr'])
        self.assertEqual(result['links'][0]['same_site'], 3)
        self.assertIn('random_subdomains', result['signals'])
        long = mc.assess('Bak: https://site.example/' + 'a' * 200, analyzer=FakeAnalyzer(listed={'site.example'}), ai=False)
        self.assertLessEqual(max(len(r['detail']) for r in long['plain']['reasons']), 140)  # long addresses are shortened

    def test_the_original_email_builds_on_the_screenshot_check(self):
        from services import message_email
        shot = mc.assess('WhatsApp\nWhit sent you a voice note\nListen to the full message', analyzer=FakeAnalyzer(),
                         ai=lambda s, t: answer(verdict='scam', hidden_link=True, summary='Fake WhatsApp voice note.'))
        self.assertEqual((shot['plain']['tone'], shot['hidden_link']), ('danger', True))
        text, info = message_email.read_email(EML)
        mild = lambda s, t: answer(verdict='suspicious', hidden_link=True)  # noqa: E731
        result = mc.assess(text, analyzer=FakeAnalyzer(), ai=mild, email=info, previous=mc.summary_of(shot))
        self.assertEqual(result['plain']['tone'], 'danger')  # the email never lowers the screenshot's verdict
        self.assertFalse(result['hidden_link'])  # its real links are known now
        titles = [r['title'] for r in result['plain']['reasons']]
        self.assertNotIn('The link is hidden behind a button', titles)
        self.assertIn('The sender’s address only looks like the company’s', titles)
        self.assertEqual(result['source'], 'email')


if __name__ == '__main__':
    unittest.main()
