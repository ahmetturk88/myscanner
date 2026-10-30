"""Is this website who it says it is? (site-trust-v1)

The same evidence the URL scanner uses, for the website check and QR links:
Google Web Risk on the start and final address, a brand's name on someone else's
domain, the domain's age, and scam content on the page (gambling, prizes, fields
that ask for a card or phone number). Nothing here opens the site again: the page
text and form fields come from the read-only fetch in web_assessment.
"""
import concurrent.futures
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
NEW_DOMAIN_DAYS = 30
WHOIS_TIMEOUT = 6


def _registrable(url):
    from services.url_tricks import split_host
    try:
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''
    return split_host(host)[1] if host else ''


def domain_age(url):
    """{'status': 'completed' | 'unavailable', 'age_days', 'created'} from WHOIS."""
    domain = _registrable(url)
    if not domain:
        return {'status': 'unavailable', 'reason': 'No registrable domain'}
    try:
        import whois
        record = whois.whois(domain, timeout=WHOIS_TIMEOUT)
        created = record.creation_date[0] if isinstance(record.creation_date, list) else record.creation_date
        if not isinstance(created, datetime):
            return {'status': 'unavailable', 'domain': domain, 'reason': 'Registration date not published'}
        created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        return {'status': 'completed', 'domain': domain, 'created': created.date().isoformat(),
                'age_days': max(0, (datetime.now(timezone.utc) - created).days)}
    except Exception as error:  # registries differ and many ccTLDs publish no dates
        logger.info('Domain age unavailable: %s', type(error).__name__)
        return {'status': 'unavailable', 'domain': domain, 'reason': 'Registration lookup failed'}


def start_age_lookup(url):
    """Look the age up in the background while the page is fetched; returns a future."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(domain_age, url)
    pool.shutdown(wait=False)
    return future


def reputation(urls, lookup=None):
    """Google Web Risk for each distinct address: matched wins, then unavailable, then not_found."""
    if lookup is None:
        import requests
        from services.web_risk import check_web_risk
        session = requests.Session()
        lookup = lambda url: check_web_risk(url, session)  # noqa: E731
    results = []
    for url in dict.fromkeys(u for u in urls if u):
        try:
            from services.web_risk import validated_observation
            results.append((url, validated_observation(lookup(url))))
        except Exception:
            results.append((url, {'status': 'unavailable', 'threat_types': []}))
    matched = [(u, r) for u, r in results if r.get('status') == 'matched']
    if matched:
        return {'status': 'matched', 'url': matched[0][0], 'threat_types': list(matched[0][1].get('threat_types') or [])}
    statuses = [r.get('status') for _, r in results]
    if 'unavailable' in statuses:
        return {'status': 'unavailable', 'threat_types': []}
    if statuses and all(s == 'not_configured' for s in statuses):
        return {'status': 'not_configured', 'threat_types': []}
    return {'status': 'not_found' if statuses and all(s == 'not_found' for s in statuses) else 'unavailable', 'threat_types': []}


def assess(start_url, final_url, page_text, inputs, password_form, age_future=None, lookup=None):
    """(evidence, findings) for one website. findings use web_assessment's (code, severity, title, detail)."""
    from services.file_links import impersonation
    from services.scam_content import gambling_site, scam_signals
    findings = []

    def finding(code, severity, title, detail):
        findings.append({'code': code, 'severity': severity, 'title': title, 'detail': detail})

    risk = reputation([start_url, final_url], lookup)
    if risk['status'] == 'matched':
        finding('web_risk_listed', 'warning', 'Google lists this site as dangerous',
                'Google Web Risk reports it for ' + ', '.join(t.lower().replace('_', ' ') for t in risk['threat_types']) + '.')
    brand = impersonation(final_url) or impersonation(start_url)
    if brand:
        finding('lookalike_brand', 'warning', 'The address copies ' + brand,
                f'It uses the name {brand}, but it isn’t one of {brand}’s sites.')
    try:
        age = age_future.result(timeout=WHOIS_TIMEOUT + 2) if age_future else domain_age(final_url or start_url)
    except Exception:
        age = {'status': 'unavailable', 'reason': 'Registration lookup timed out'}
    signals = scam_signals(page_text, inputs) if page_text is not None else []
    if page_text is not None and gambling_site(page_text, final_url, start_url):
        signals.append('gambling')
    young = age.get('status') == 'completed' and age.get('age_days', 9999) < NEW_DOMAIN_DAYS
    asks = password_form or 'collects_phone_or_card' in signals
    if young:
        # A new shop is normal; a new site that asks for a password or a card is how scams look.
        finding('new_domain', 'warning' if asks or brand else 'info', 'The site is brand new',
                f'Its domain was registered {age["age_days"]} days ago. Scam shops and fake login pages rarely live longer than a few weeks.')
    if 'gambling' in signals:
        finding('gambling_site', 'info', 'An online gambling site',
                'Casino or betting content was observed. Licensing, legality and payment reliability were not verified; this category alone is not phishing or malware evidence.')
    if 'prize_offer' in signals:
        finding('prize_offer', 'warning', 'It promises a prize or a gift',
                'Prize and free-gift pages are a common way to collect card details.')
    if 'fake_comments' in signals:
        finding('fake_comments', 'warning', 'It shows fake comments',
                'The page imitates social media comments to look trustworthy.')
    if 'collects_phone_or_card' in signals and (young or brand):
        finding('collects_card', 'warning', 'It asks for a card or phone number',
                'A new or copied site asking for these details is a common scam.')
    evidence = {'policy': 'site-trust-v1', 'web_risk': risk, 'brand': brand, 'domain_age': age, 'scam_signals': sorted(set(signals))}
    return evidence, findings
