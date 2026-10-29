"""Links found inside a file (PDF, web page, saved email, QR image, Office document).

The links are never opened. Each distinct site is read for address tricks (a bank's
name on someone else's domain) and, for the first few, looked up in Google Web Risk.
A Web Risk listing makes the file a phishing lure; a look-alike name asks for review.
"""
import logging
from urllib.parse import urlsplit

from services import url_tricks

logger = logging.getLogger(__name__)
MAX_LOOKUPS = 5     # Web Risk lookups per file
MAX_SITES = 50      # sites read for address tricks
STRONG = ('lookalike_name', 'brand_in_subdomain', 'homograph_name', 'scheme_in_name')


def _host(url):
    try:
        return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def file_urls(metadata, inspection):
    """Every web link the parsers recorded, in order, without repeats."""
    urls = list(metadata.get('uris') or [])
    urls += [r.get('target', '') for r in metadata.get('external_relationships') or []
             if isinstance(r, dict) and str(r.get('type', '')).lower() == 'hyperlink']
    urls += list((inspection or {}).get('urls') or [])
    clean = []
    for url in urls:
        url = str(url).strip()[:2000]
        if url.lower().startswith('www.'):
            url = 'http://' + url
        if url.lower().startswith(('http://', 'https://')) and url not in clean:
            clean.append(url)
    return clean


def impersonation(url):
    """The brand a link pretends to be, or None."""
    for signal in url_tricks.address_signals(url):
        brand = signal.get('brand') or ''
        brand = brand.split('.')[0] if signal['code'] == 'brand_in_subdomain' else brand
        brand = brand or signal.get('looks_like') or ''  # a homograph names the address it imitates
        if signal['code'] in STRONG and signal.get('strong') and brand:
            return url_tricks.display(brand)
        if signal['code'] == 'brand_in_name' and brand in url_tricks.IMPERSONATED:
            return url_tricks.display(brand)
    return None


def check_links(urls, lookup=None):
    """{'status', 'checked', 'listed': [{'host', 'threat_types'}], 'lookalikes': [{'host', 'brand'}]}"""
    sites = []
    for url in urls:
        host = _host(url)
        if host and host not in [h for h, _ in sites]:
            sites.append((host, url))
    sites = sites[:MAX_SITES]
    lookalikes = []
    for host, url in sites:
        brand = impersonation(url)
        if brand:
            lookalikes.append({'host': host, 'brand': brand})
    if not sites:
        return {'status': 'no_links', 'checked': 0, 'listed': [], 'lookalikes': []}
    if lookup is None:
        import requests
        from services.web_risk import check_web_risk
        session = requests.Session()
        lookup = lambda url: check_web_risk(url, session)  # noqa: E731
    # Look-alikes first: they are the links most worth a reputation lookup.
    suspects = {item['host'] for item in lookalikes}
    ordered = sorted(sites, key=lambda site: site[0] not in suspects)[:MAX_LOOKUPS]
    listed, statuses = [], []
    for host, url in ordered:
        try:
            result = lookup(url)
        except Exception as error:  # one failed lookup must not lose the file report
            logger.warning('Link reputation lookup failed: %s', type(error).__name__)
            result = {'status': 'unavailable', 'threat_types': []}
        statuses.append(result.get('status'))
        if result.get('status') == 'matched':
            listed.append({'host': host, 'threat_types': list(result.get('threat_types') or [])})
    status = ('not_configured' if statuses and all(s == 'not_configured' for s in statuses)
              else 'unavailable' if 'unavailable' in statuses else 'checked')
    return {'status': status, 'checked': len(ordered), 'sites': len(sites), 'listed': listed, 'lookalikes': lookalikes[:8]}
