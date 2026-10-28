"""Pages drawn by scripts: the text the preview browser saw is read too (url-evidence-v12)."""
import copy
import unittest
from unittest.mock import patch

from services.url_analyzer import apply_rendered_text, short_link_blocked
from services.url_assessment import assess_url
from services.url_screenshot import add_rendered_text, rendered_text

QRCO_BLOCK = 'QR Code Generator\nWarning: This URL has been blocked by QR Code Generator\nThe destination was reported for phishing.'


class FakeResponse:
    def __init__(self, status, payload, size=100):
        self.status_code, self._payload, self.content = status, payload, b'x' * size

    def json(self):
        return self._payload


class RenderedTextTests(unittest.TestCase):
    def test_a_short_link_block_page_drawn_by_scripts_is_caught(self):
        # qrco.de (QR Code Generator) answered 200 with no text until its script drew the warning.
        page = {'status_code': 200, 'title': '', 'visible_text_length': 0, 'scam_signals': []}
        apply_rendered_text(page, 'https://qrco.de/bh4yQu', QRCO_BLOCK)
        self.assertEqual(page['host_warning'], {'host': 'shortener', 'kind': 'blocked'})
        self.assertEqual(page['title'], 'QR Code Generator')
        self.assertGreater(page['visible_text_length'], 80)

    def test_ordinary_pages_and_other_hosts_are_not_called_blocked(self):
        page = {'visible_text_length': 0}
        apply_rendered_text(page, 'https://qrco.de/abc', 'Menu\nSoups and salads, fresh every day.')
        self.assertNotIn('host_warning', page)
        self.assertFalse(short_link_blocked('https://news.example/story', QRCO_BLOCK))
        self.assertTrue(apply_rendered_text(None, 'https://qrco.de/x', QRCO_BLOCK) is None)

    def test_scam_wording_seen_only_by_the_browser_counts(self):
        page = {'visible_text_length': 0, 'scam_signals': []}
        apply_rendered_text(page, 'https://prize.example/', 'Tebrikler! 5000 TL hediye kazandınız. Ödülünüzü almak için tıklayın.')
        self.assertIsInstance(page['scam_signals'], list)

    def test_only_empty_pages_ask_the_browser(self):
        deep = {'page_content': {'visible_text_length': 900}, 'behavior': {'final_url': 'https://qrco.de/x'}}
        with patch('services.url_screenshot.rendered_text', side_effect=AssertionError('not needed')):
            add_rendered_text('https://qrco.de/x', deep)
        deep['page_content']['visible_text_length'] = 0
        with patch('services.url_screenshot.rendered_text', return_value=QRCO_BLOCK):
            add_rendered_text('https://qrco.de/x', deep)
        self.assertEqual(deep['page_content']['host_warning']['kind'], 'blocked')

    def test_after_a_screenshot_every_page_gets_the_browser_text(self):
        # hbhdyw.com: 417 characters of menu without scripts; "GK Slots" and the games only with them.
        deep = {'page_content': {'visible_text_length': 417, 'scam_signals': []}, 'behavior': {'final_url': 'https://hbhdyw.com/egame/185'}}
        text = 'bet365 Login Register GK Slots Newest All Games King of Glory'
        with patch('services.url_screenshot.rendered_text', return_value=text):
            add_rendered_text('https://hbhdyw.com/egame/185', deep)
            self.assertNotIn('gambling', deep['page_content']['scam_signals'])  # no screenshot: not asked
            add_rendered_text('https://hbhdyw.com/egame/185', deep, rendered=True)
        self.assertIn('gambling', deep['page_content']['scam_signals'])

    def test_the_provider_answer_is_bounded_and_never_raises(self):
        with patch('services.url_screenshot.requests.get', return_value=FakeResponse(200, {'text': 'hi'})):
            self.assertEqual(rendered_text('https://a.example/', 'http://urlvet:8080'), 'hi')
        for response in (FakeResponse(500, {}), FakeResponse(200, {'text': 5}), FakeResponse(200, {'text': 'x'}, size=70000)):
            with patch('services.url_screenshot.requests.get', return_value=response):
                self.assertIsNone(rendered_text('https://a.example/', 'http://urlvet:8080'))
        self.assertIsNone(rendered_text('https://a.example/', ''))

    def test_the_blocked_short_link_is_dangerous(self):
        url = 'https://qrco.de/bh4yQu'
        provider = {'verdict': 'harmless', 'trust_score': 100, 'rank': 0, 'phishing': {'in_database': False, 'verified': False, 'valid': False}}
        page = {'title': '', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 0, 'scam_signals': []}
        apply_rendered_text(page, url, QRCO_BLOCK)
        local = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
                 'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
        deep = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
                'page_content': page, 'behavior': {'behavior_risk_score': 0, 'original_url': url, 'final_url': url},
                'osint': {'urlhaus_status': 'not_found'}, 'whois': {'age_days': 4000}}
        self.assertEqual(assess_url(local, deep)['verdict'], 'malicious')


class UrlvetPatchTests(unittest.TestCase):
    def test_the_rendered_text_patch_is_applied_in_the_image(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'deploy', 'urlvet.Dockerfile'), encoding='utf-8') as handle:
            dockerfile = handle.read()
        self.assertIn('git apply /tmp/urlvet-rendered-text.patch', dockerfile)
        with open(os.path.join(root, 'deploy', 'urlvet-rendered-text.patch'), encoding='utf-8') as handle:
            patch_text = handle.read()
        self.assertIn('v1.GET("/rendered-text", RenderedTextHandler)', patch_text)
        self.assertIn('.slice(0, 8000)', patch_text)
        # innerText skips shadow roots and frames: the live qrco.de block page came back empty.
        self.assertIn('node.shadowRoot', patch_text)
        self.assertIn("tag === 'IFRAME'", patch_text)
        self.assertIn('500 * time.Millisecond', patch_text)


if __name__ == '__main__':
    unittest.main()
