from io import BytesIO

import pytest
from itsdangerous import BadData
from pypdf import PdfReader

from services.email_report_view import plain_email_report
from services.report_pdf import area_scores, generate_email_report, generate_site_report, passed_percent
from services.report_receipts import issue_receipt, load_receipt
from services.simple_report_view import plain_web_report

SECRET = 'test-secret'


def site_result():
    result = {
        'url': 'https://shop.example.com/', 'domain': 'shop.example.com', 'verdict': 'suspicious', 'analyzed_at': '2026-10-30T09:15:00+00:00',
        'http': {'status': 'completed', 'status_code': 200, 'final_url': 'https://shop.example.com/',
                 'chain': [{'url': 'http://shop.example.com/', 'status_code': 301}, {'url': 'https://shop.example.com/', 'status_code': 200}]},
        'tls': {'status': 'completed', 'verified': True, 'issuer': 'Let’s Encrypt', 'expires_at': '2027-01-01T00:00:00+00:00',
                'days_remaining': 63, 'tls_version': 'TLSv1.3', 'subject_names': ['shop.example.com']},
        'content': {'status': 'completed'},
        'trust': {'policy': 'site-trust-v1', 'web_risk': {'status': 'not_found'}, 'brand': None,
                  'domain_age': {'status': 'completed', 'domain': 'example.com', 'created': '2019-04-01', 'age_days': 2770}},
        'dns': {'NS': {'values': ['ns1.example.net.']}, 'MX': {'values': ['10 mx.example.com.']}},
        'header_observations': [{'name': 'Strict-Transport-Security', 'status': 'present', 'value': 'max-age=31536000'},
                                {'name': 'Content-Security-Policy', 'status': 'missing', 'value': ''}],
        'crawl': {'policy': 'site-crawl-v1', 'pages_read': 2, 'external_sites': 4, 'privacy_notice': True,
                  'pages': [{'url': 'https://shop.example.com/', 'status': 'read', 'title': 'Ana sayfa'},
                            {'url': 'https://shop.example.com/iletisim?x=1', 'status': 'read', 'title': 'İletişim'}],
                  'lookalike_links': [{'host': 'paypal-secure.example.org', 'brand': 'PayPal'}],
                  'downloads': [{'url': 'https://shop.example.com/app.apk', 'extension': 'apk', 'antivirus': {'status': 'clean'}}],
                  'downloads_found': 1,
                  'shop': {'phone': True, 'address': True, 'company_id': False, 'returns': True, 'etbis': False, 'card_payment': True, 'missing': ['company_id', 'etbis']}},
        'posture': {'policy': 'site-posture-v1', 'hosting': {'status': 'completed', 'ip': '192.0.2.10', 'country': 'Türkiye', 'network': 'Example Hosting', 'asn': 64500},
                    'mail': {'status': 'completed', 'protected': False, 'dmarc_policy': 'none', 'spf': 'v=spf1 -all'},
                    'technology': [{'name': 'WordPress', 'version': '5.2', 'source': 'generator'}], 'old_software': ['WordPress 5.2'],
                    'outside_scripts': [{'host': 'cdn.example.net', 'url': 'https://cdn.example.net/a.js'}], 'copied_scripts': [],
                    'mixed_content': {'scripts': 0, 'frames': 0, 'other': 2}, 'cookies': [{'name': 'PHPSESSID', 'secure': False, 'httponly': True}]},
        'findings': [{'code': 'crawl_lookalike_links', 'severity': 'warning', 'title': 'It links to copies of well-known sites',
                      'detail': 'paypal-secure.example.org uses the name PayPal but isn’t its site.'},
                     {'code': 'old_software', 'severity': 'info', 'title': 'It runs old software',
                      'detail': 'WordPress 5.2 no longer gets security fixes. Hacked sites often run old versions; this isn’t proof of a problem.'}],
        'missing_checks': ['url.vet'], 'evidence_policy': 'site-passive-v3',
    }
    result['plain'] = plain_web_report(result, source='site')
    return result


def email_result():
    result = {'email': 'info@example.com', 'domain': 'example.com', 'checked_at': '2026-10-30T09:20:00+00:00',
              'dns': {'mx': {'exists': True, 'status': 'found', 'records': [{'exchange': 'mx.example.com', 'priority': 10}]},
                      'spf': {'status': 'found', 'record': 'v=spf1 -all', 'audit': {'configuration_valid': True}},
                      'dmarc': {'status': 'found', 'record': 'v=DMARC1; p=reject', 'policy': 'reject', 'audit': {'configuration_valid': True}}},
              'blacklist': {'is_blacklisted': False, 'coverage_status': 'completed', 'blacklisted_on': [], 'clean_on': ['A', 'B']},
              'domain_info': {'age_days': 9000, 'registrar': 'Example Registrar'}, 'smtp': {'valid': None, 'coverage_status': 'skipped'},
              'web_risk': {'status': 'not_found', 'threat_types': []}, 'is_disposable': False, 'is_free': False,
              'assessment': {'verdict': 'no_indicators', 'score': 96, 'policy_version': 'email-evidence-v6',
                             'categories': [{'key': 'routing', 'label': 'Mail routing', 'weight': 20, 'risk_deduction': 0, 'coverage_deduction': 0},
                                            {'key': 'reputation', 'label': 'Reputation', 'weight': 30, 'risk_deduction': 0, 'coverage_deduction': 4}],
                             'findings': [{'category': 'reputation', 'deduction': 4, 'message': 'Mailbox acceptance was not probed.'}],
                             'missing_checks': [], 'not_checked': ['Breach exposure and mailbox ownership were not checked.']}}
    result['plain'] = plain_email_report(result)
    return result


def text_of(buffer):
    return '\n'.join(page.extract_text() for page in PdfReader(BytesIO(buffer.getvalue())).pages)


@pytest.mark.parametrize('lang', ['en', 'tr'])
def test_site_pdf_carries_the_page_verdict_and_the_evidence(lang):
    result = site_result()
    receipt = issue_receipt('site', result, '7', SECRET)
    text = text_of(generate_site_report(load_receipt('site', receipt, '7', SECRET), 'ahmed', lang=lang))
    if lang == 'en':
        for words in ('WEBSITE SECURITY REPORT', result['plain']['headline'], 'SCORE BY AREA', 'Site setup', 'Example Hosting',
                      'WordPress', 'paypal-secure.example.org', '/iletisim', 'Let’s Encrypt'):
            assert words in text, words
    else:
        for words in ('WEB SİTESİ GÜVENLİK RAPORU', 'ALANLARA GÖRE PUAN', 'Site kurulumu', 'Eski yazılım kullanıyor'):
            assert words in text, words


@pytest.mark.parametrize('lang', ['en', 'tr'])
def test_email_pdf_says_what_the_page_says(lang):
    result = email_result()
    receipt = issue_receipt('email', result, '7', SECRET)
    text = text_of(generate_email_report(load_receipt('email', receipt, '7', SECRET), 'ahmed', lang=lang))
    if lang == 'en':
        for words in ('EMAIL ADDRESS REPORT', result['plain']['headline'], result['plain']['label'], 'v=DMARC1; p=reject', 'Example Registrar', '96'):
            assert words in text, words
    else:
        assert 'E-POSTA ADRESİ RAPORU' in text and 'UYARI İŞARETİ YOK' in text


def test_receipts_belong_to_their_owner_and_kind():
    receipt = issue_receipt('site', site_result(), '7', SECRET)
    with pytest.raises(BadData):
        load_receipt('site', receipt, '8', SECRET)
    with pytest.raises(BadData):
        load_receipt('email', receipt, '7', SECRET)
    with pytest.raises(BadData):
        load_receipt('site', receipt[:-4] + 'AAAA', '7', SECRET)


def test_area_scores_count_only_judging_checks():
    checks = [{'name': 'Threat lists', 'state': 'ok'}, {'name': 'Domain age', 'state': 'warn'}, {'name': 'Hosted in', 'state': 'info'},
              {'name': 'Secure connection', 'state': 'ok'}, {'name': 'Redirects', 'state': 'info'}, {'name': 'Software', 'state': 'na'}]
    rows = {area: (score, n) for area, score, n in area_scores(checks)}
    assert rows['Reputation and trust'] == (68, 2)
    assert rows['Connection security'] == (100, 1)
    assert rows['Site setup'] == (None, 0)
    assert passed_percent(checks) == 67


def test_routes_refuse_a_receipt_from_someone_else(client=None):
    from app import app
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.test_client() as web:
        assert web.post('/api/site-report/pdf', json={'receipt': 'x'}).status_code in (302, 401)


def test_a_big_site_keeps_its_hosting_and_email_details_in_the_receipt():
    """Long page lists used to spend the receipt budget before posture: the PDF said "SPF: none"."""
    result = site_result()
    result['crawl']['pages'] = [{'url': f'https://shop.example.com/p/{i}', 'status': 'read', 'title': 'x' * 900} for i in range(40)]
    result['content'] = {'status': 'completed', 'description': 'd' * 1200, 'headings': ['h' * 200] * 10, 'posture': {'big': 'y' * 50000}}
    result['dns'] = {k: {'values': ['v' * 500] * 16} for k in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME')}
    report = load_receipt('site', issue_receipt('site', result, '7', SECRET), '7', SECRET)
    assert report['posture']['mail']['spf'] == 'v=spf1 -all'
    assert report['posture']['hosting']['network'] == 'Example Hosting'
    assert 'posture' not in report['content']
    text = text_of(generate_site_report(report, 'ahmed', lang='tr'))
    assert 'v=spf1 -all' in text and 'Destination hostname changed' not in text
