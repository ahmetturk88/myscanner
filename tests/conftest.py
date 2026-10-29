"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def no_live_whois(monkeypatch):
    """Website checks look the domain's age up over WHOIS; tests never reach a registry.
    A test that needs an age patches services.site_trust.domain_age itself."""
    monkeypatch.setattr('services.site_trust.domain_age',
                        lambda url: {'status': 'unavailable', 'reason': 'No WHOIS in tests'})
