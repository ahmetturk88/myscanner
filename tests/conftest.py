"""Shared test setup: tests never reach a real website or registry."""
import pytest


@pytest.fixture(autouse=True)
def no_live_whois(monkeypatch):
    """Website checks look the domain's age up over WHOIS; tests never reach a registry.
    A test that needs an age patches services.site_trust.domain_age itself."""
    monkeypatch.setattr('services.site_trust.domain_age',
                        lambda url: {'status': 'unavailable', 'reason': 'No WHOIS in tests'})


@pytest.fixture(autouse=True)
def no_live_crawl(request, monkeypatch):
    """The website check walks the real site; CI has internet, so a test that reaches assess_site
    without its own fake crawl would read example.com for real. test_site_crawl drives the crawler
    itself through a fake response_chain, so it keeps the real function."""
    if request.module.__name__.endswith('test_site_crawl'):
        return
    walked = {'pages': [], 'external': {}, 'downloads': [], 'skipped_by_robots': 0, 'language': '',
              'contacts': {'phone_links': 0, 'email_links': 0, 'whatsapp_links': 0}, 'stopped': None, 'pages_read': 0, 'text': ''}
    monkeypatch.setattr('services.site_crawl.crawl', lambda *args, **kwargs: dict(walked))


@pytest.fixture(autouse=True)
def no_live_mail_lookup(request, monkeypatch):
    """The website check reads SPF and DMARC of the site's domain over DNS; tests never do.
    test_site_posture drives the audit through its own fake resolver."""
    if request.module.__name__.endswith('test_site_posture'):
        return
    monkeypatch.setattr('services.site_posture.mail_security', lambda domain, resolve=None: {'status': 'unavailable', 'domain': domain})
