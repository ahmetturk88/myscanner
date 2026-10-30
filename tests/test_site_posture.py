from bs4 import BeautifulSoup

from services import site_posture
from services.simple_report_view import plain_web_report

HTML = '''<html><head><meta name="generator" content="WordPress 5.2.3">
<script src="/wp-includes/js/jquery/jquery-1.12.4.min.js"></script>
<script src="https://cdn.example-cdn.net/lib.js"></script>
<script src="https://paypal-checkout-secure.com/pay.js"></script>
<script src="http://old.example.net/x.js"></script>
<img src="http://images.example.net/a.png"></head><body>shop</body></html>'''


def observe(cookies=()):
    return site_posture.page_observations(BeautifulSoup(HTML, 'html.parser'), HTML, 'https://shop.example.com/',
                                          {'Server': 'nginx'}, cookies)


def resolver(records):
    def resolve(name, kind):
        return records.get((name, kind), [])
    return resolve


def report(observed, final='https://shop.example.com/'):
    return {'structure': {'hostname': 'shop.example.com'}, 'dns': {'A': {'values': []}},
            'http': {'final_url': final}, 'content': {'posture': observed}}


def test_page_observations_name_the_platform_versions_and_outside_scripts():
    found = observe(['PHPSESSID=abc; Path=/', 'pref=1; Secure; HttpOnly; SameSite=Lax'])
    names = {t['name']: t['version'] for t in found['technology']}
    assert names['WordPress'] == '5.2.3' and names['jQuery'] == '1.12.4' and 'nginx' in names
    assert [s['host'] for s in found['outside_scripts']] == ['cdn.example-cdn.net', 'paypal-checkout-secure.com', 'old.example.net']
    assert found['mixed_content'] == {'scripts': 1, 'frames': 0, 'other': 1}
    assert found['cookies'][0] == {'name': 'PHPSESSID', 'secure': False, 'httponly': False, 'samesite': ''}
    assert found['cookies'][1]['secure'] and found['cookies'][1]['samesite'] == 'Lax'


def test_a_script_from_a_copied_brand_address_is_the_only_warning():
    evidence, findings = site_posture.assess(report(observe(['PHPSESSID=abc'])), resolve=resolver({}))
    severities = {f['code']: f['severity'] for f in findings}
    assert severities.pop('script_lookalike') == 'warning'
    assert set(severities.values()) == {'info'}
    assert {'old_software', 'mixed_content', 'cookie_flags', 'mail_spoofable'} <= set(severities)
    assert evidence['copied_scripts'][0]['brand'] == 'PayPal'
    assert evidence['old_software'] == ['WordPress 5.2.3', 'jQuery 1.12.4']


def test_enforced_dmarc_means_others_cannot_send_in_its_name():
    records = {('example.com', 'TXT'): ['v=spf1 include:_spf.example.net -all'], ('_spf.example.net', 'TXT'): ['v=spf1 ip4:192.0.2.1 -all'],
               ('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=reject'], ('example.com', 'MX'): ['10 mx.example.com.']}
    mail = site_posture.mail_security('example.com', resolver(records))
    assert mail['protected'] is True and mail['dmarc_policy'] == 'reject' and mail['spf_ends'] == '-all'
    records[('_dmarc.example.com', 'TXT')] = ['v=DMARC1; p=none']
    assert site_posture.mail_security('example.com', resolver(records))['protected'] is False
    del records[('_dmarc.example.com', 'TXT')]
    assert site_posture.mail_security('example.com', resolver(records))['dmarc_policy'] == 'missing'


def test_dns_failure_is_unavailable_not_unprotected():
    def broken(name, kind):
        raise OSError('DNS')
    evidence, findings = site_posture.assess(report({}), resolve=broken)
    assert evidence['mail']['status'] == 'unavailable'
    assert 'mail_spoofable' not in {f['code'] for f in findings}


def test_plain_report_shows_the_setup_rows():
    evidence, findings = site_posture.assess(report(observe()), resolve=resolver({}))
    result = {'url': 'https://shop.example.com/', 'verdict': 'suspicious', 'posture': evidence, 'findings': findings,
              'crawl': {'policy': 'site-crawl-v1', 'pages_read': 3, 'privacy_notice': True}}
    plain = plain_web_report(result, source='site')
    rows = {c['name']: (c['state'], c['result']) for c in plain['checks']}
    assert rows['Scripts from other sites'] == ('warn', 'Copied address')
    assert rows['Software'] == ('info', 'Old version')
    assert rows['Email in its name'] == ('info', 'Not protected')
    assert rows['Privacy notice'] == ('ok', 'Found')
    assert any(r['title'] == 'It loads code from a copied address' for r in plain['reasons'])


def test_privacy_notice_reads_turkish_and_english():
    assert site_posture.privacy_notice('KVKK Aydınlatma Metni')
    assert site_posture.privacy_notice('Read our Privacy Policy')
    assert not site_posture.privacy_notice('Sepete ekle')
