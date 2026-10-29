"""Walk a website the way a careful visitor would, and check what it links to (site-crawl-v1).

The website check reads more than the home page: it follows the site's own links
(same registrable domain, up to MAX_PAGES pages, two clicks deep), honours
robots.txt, and never submits a form, runs a script or logs in. Then it checks what
it found:

* every outside site it links to: a brand's name on someone else's domain, betting,
  and Google Web Risk for the most suspicious ones;
* pages of its own: a hidden login page in a phishing-kit folder, betting spam that
  hacked sites carry, Google Web Risk;
* files it offers for download (apps, programs, archives): ClamAV;
* for an online shop: the details a real Turkish shop publishes (phone, address,
  company number, return policy, ETBİS) and the ones fake shops show (bank transfer
  only, WhatsApp only, huge discounts).

Every request goes through PublicHTTPSession, so private addresses stay unreachable.
"""
import logging
import re
import time
from collections import deque
from urllib.parse import urldefrag, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

MAX_PAGES = 25
MAX_DEPTH = 2
BUDGET_SECONDS = 45
PAGE_LIMIT = 1024 * 1024
TEXT_LIMIT = 300_000
MAX_EXTERNAL_HOSTS = 200
MAX_DOWNLOADS = 3
DOWNLOAD_LIMIT = 15 * 1024 * 1024
WEB_RISK_EXTERNAL = 10
WEB_RISK_INTERNAL = 3
PAUSE = 0.15  # between requests: a visitor, not a load test
USER_AGENT = 'MyScanner/1.0 (read-only website check; +https://myscanners.com)'
# Our people are in Turkey and the server is not: ask for the Turkish page, or a shop like
# trendyol.com sends the German one (it went to /de from the server).
ACCEPT_LANGUAGE = 'tr-TR,tr;q=0.9,en;q=0.6'
DOWNLOAD_EXTENSIONS = {'apk', 'xapk', 'apks', 'exe', 'msi', 'scr', 'bat', 'cmd', 'jar', 'dmg', 'pkg', 'zip', 'rar', '7z', 'iso'}
PROGRAMS = DOWNLOAD_EXTENSIONS - {'zip', 'rar', '7z', 'iso'}

# Online shop words (Turkish and English), and the details a real Turkish shop publishes.
SHOP = re.compile(r'sepete ekle|sepetim|add to cart|checkout|ödemeye geç|alışverişe devam|kargo bedava|ücretsiz kargo|'
                  r'in den warenkorb|warenkorb|kasse|'
                  r'\b\d{1,3}(?:[.,]\d{3})*(?:,\d{2})?\s?(?:₺|TL|€|EUR)\b|₺\s?\d', re.I)
# Product data shops publish for search engines (schema.org JSON-LD): present in the HTML even when
# prices and buttons are drawn by scripts.
SHOP_SCHEMA = re.compile(r'"@type"\s*:\s*"(?:Product|Offer|AggregateOffer|OnlineStore|Store)"')
PHONE = re.compile(r'(?:\+90|0)\s?\(?(?:[2-5]\d{2})\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}|\b0?850[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}')
ADDRESS = re.compile(r'\b(?:mah(?:allesi)?\.?|cad(?:desi)?\.?|sok(?:ak|ağı)?\.?|bulvarı)\s', re.I)
COMPANY_ID = re.compile(r'mersis|vergi\s*(?:no|numarası|dairesi)|\bvkn\b|ticaret sicil', re.I)
RETURNS = re.compile(r'iade|cayma hakkı|iptal ve iade|return policy|refund policy', re.I)
ETBIS = re.compile(r'etbis', re.I)
BANK_TRANSFER = re.compile(r'havale|\beft\b|\biban\b', re.I)
CARD_PAYMENT = re.compile(r'kredi kartı|banka kartı|3d secure|iyzico|paytr|shopier|param\b|masterpass|visa|mastercard|troy', re.I)
BIG_DISCOUNT = re.compile(r'%\s?(?:[7-9]\d)\b|\b(?:[7-9]\d)\s?%\s*(?:indirim|off)', re.I)


def _registrable(url):
    from services.url_tricks import split_host
    try:
        host = (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''
    return split_host(host)[1] if host else ''


def _robots(session, origin, deadline):
    """A parser for the site's robots.txt, or None when it has none."""
    from urllib import robotparser
    from services.web_assessment import response_chain
    try:
        response, _, _ = response_chain(session, origin + '/robots.txt', deadline)
    except Exception:
        return None
    if response is None:
        return None
    try:
        if response.status_code != 200 or 'html' in response.headers.get('Content-Type', '').lower():
            return None
        parser = robotparser.RobotFileParser()
        parser.parse(response.text[:128 * 1024].splitlines())
        return parser
    finally:
        response.close()


def crawl(start_url, budget=BUDGET_SECONDS, max_pages=MAX_PAGES, pause=PAUSE):
    """Pages, outside links, downloads and contact links of one site. Never raises for a site problem."""
    from services.safe_http import PublicHTTPSession, TargetResolutionError, UnsafeTargetError, normalize_url
    from services.scam_content import gambling_site, scam_signals
    from services.web_assessment import response_chain
    deadline = time.monotonic() + budget
    site = _registrable(start_url)
    parts = urlsplit(start_url)
    origin = f'{parts.scheme}://{parts.netloc}'
    result = {'policy': 'site-crawl-v1', 'pages': [], 'external': {}, 'downloads': [], 'skipped_by_robots': 0,
              'contacts': {'phone_links': 0, 'email_links': 0, 'whatsapp_links': 0}, 'stopped': None}
    texts, seen = [], set()
    queue = deque([(start_url, 0)])
    with PublicHTTPSession(response_limit=PAGE_LIMIT, deadline=deadline) as session:
        session.headers.update({'User-Agent': USER_AGENT, 'Accept-Language': ACCEPT_LANGUAGE})
        robots = _robots(session, origin, deadline)
        while queue:
            if len(result['pages']) >= max_pages:
                result['stopped'] = 'page_limit'
                break
            if time.monotonic() >= deadline - 1:
                result['stopped'] = 'time_budget'
                break
            url, depth = queue.popleft()
            url = urldefrag(url)[0]
            if url in seen:
                continue
            seen.add(url)
            if robots is not None and not robots.can_fetch(USER_AGENT, url):
                result['skipped_by_robots'] += 1
                continue
            page = {'url': url[:500], 'depth': depth}
            result['pages'].append(page)
            if len(result['pages']) > 1 and pause:
                time.sleep(pause)
            try:
                response, chain, reason = response_chain(session, url, deadline)
            except (UnsafeTargetError, TargetResolutionError):
                page['status'] = 'blocked'
                continue
            except requests.RequestException:
                page['status'] = 'unavailable'
                continue
            if response is None:
                page.update(status='unavailable', reason=reason)
                continue
            try:
                final = chain[-1]['url']
                page.update(url=final[:500], status_code=response.status_code)
                if _registrable(final) != site:
                    page['status'] = 'left_site'
                    continue
                if 'html' not in response.headers.get('Content-Type', '').lower() or response.status_code >= 400:
                    page['status'] = 'not_a_page'
                    continue
                soup = BeautifulSoup(response.content[:PAGE_LIMIT], 'html.parser')
            finally:
                response.close()
            page['status'] = 'read'
            text = soup.get_text(' ', strip=True)[:TEXT_LIMIT // 4]
            title = soup.title.get_text(' ', strip=True)[:200] if soup.title else ''
            inputs = [(i.get('type', 'text'), i.get('name', ''), i.get('placeholder', '')) for i in soup.find_all('input', limit=200)]
            page.update(title=title, password_form=any(str(k).lower() == 'password' for k, _, _ in inputs),
                        signals=sorted(set(scam_signals(text, inputs)) | ({'gambling'} if gambling_site(f'{title} {text}', final) else set())))
            schema = ' '.join(tag.get_text() for tag in soup.find_all('script', attrs={'type': 'application/ld+json'}, limit=20))[:200_000]
            if SHOP_SCHEMA.search(schema):
                result['shop_schema_pages'] = result.get('shop_schema_pages', 0) + 1
            if sum(len(t) for t in texts) < TEXT_LIMIT:
                texts.append(f'{title} {text}')
            for anchor in soup.find_all(['a', 'area'], href=True, limit=600):
                href = str(anchor.get('href') or '').strip()
                lower = href.lower()
                if lower.startswith('tel:'):
                    result['contacts']['phone_links'] += 1
                    continue
                if lower.startswith('mailto:'):
                    result['contacts']['email_links'] += 1
                    continue
                try:
                    link = urldefrag(normalize_url(urljoin(final, href)))[0]
                except Exception:
                    continue
                host = (urlsplit(link).hostname or '').lower()
                if host in ('wa.me', 'api.whatsapp.com', 'whatsapp.com', 'web.whatsapp.com'):
                    result['contacts']['whatsapp_links'] += 1
                    continue
                path = urlsplit(link).path.lower()
                extension = path.rsplit('.', 1)[-1] if '.' in path.rsplit('/', 1)[-1] else ''
                if extension in DOWNLOAD_EXTENSIONS:
                    if link not in [d['url'] for d in result['downloads']] and len(result['downloads']) < 20:
                        result['downloads'].append({'url': link[:500], 'extension': extension, 'found_on': final[:500]})
                elif _registrable(link) == site:
                    if depth < MAX_DEPTH and link not in seen:
                        queue.append((link, depth + 1))
                elif len(result['external']) < MAX_EXTERNAL_HOSTS or host in result['external']:
                    links = result['external'].setdefault(host, [])
                    if link not in links and len(links) < 3:
                        links.append(link[:500])
    result['pages_read'] = sum(p.get('status') == 'read' for p in result['pages'])
    result['text'] = ' '.join(texts)[:TEXT_LIMIT]  # used by assess(); dropped before the report is saved
    return result


def shop_signals(text, contacts, age_days=None, schema_pages=0):
    """What an online shop shows about itself. None when the site doesn't look like a shop."""
    if len(SHOP.findall(text)) < 3 and not schema_pages:
        return None
    card = bool(CARD_PAYMENT.search(text))
    shop = {'phone': bool(PHONE.search(text)) or contacts.get('phone_links', 0) > 0,
            'address': bool(ADDRESS.search(text)),
            'company_id': bool(COMPANY_ID.search(text)),
            'returns': bool(RETURNS.search(text)),
            'etbis': bool(ETBIS.search(text)),
            'card_payment': card,
            'bank_transfer_only': bool(BANK_TRANSFER.search(text)) and not card,
            'whatsapp_only': contacts.get('whatsapp_links', 0) > 0 and not contacts.get('phone_links') and not PHONE.search(text),
            'big_discounts': len(BIG_DISCOUNT.findall(text)) >= 2}
    missing = [k for k in ('phone', 'address', 'company_id', 'returns', 'etbis') if not shop[k]]
    red = [k for k in ('bank_transfer_only', 'whatsapp_only', 'big_discounts') if shop[k]]
    young = age_days is not None and age_days < 180
    shop.update(missing=missing, red_flags=red,
                fake_signs=len(red) >= 2 or (young and (len(missing) >= 3 or bool(red))) or (len(missing) >= 4 and bool(red)))
    return shop


def _download(url, scan=None):
    """ClamAV's answer for one downloadable file, without saving it."""
    from services.safe_http import PublicHTTPSession
    if scan is None:
        from services.clamav_client import scan_bytes as scan
    try:
        with PublicHTTPSession(response_limit=DOWNLOAD_LIMIT, deadline=time.monotonic() + 20) as session:
            session.headers['User-Agent'] = USER_AGENT
            response = session.get(url, timeout=(3, 10))
            try:
                if response.status_code != 200:
                    return {'status': 'unavailable'}
                return scan(response.content or b'')
            finally:
                response.close()
    except Exception:
        return {'status': 'unavailable'}


def assess(found, age_days=None, lookup=None, scan=None):
    """(evidence, findings) from a crawl. Findings use web_assessment's (code, severity, title, detail)."""
    from services.file_links import impersonation
    from services.scam_content import gambling_site
    from services.url_tricks import kit_path
    findings = []

    def finding(code, severity, title, detail):
        findings.append({'code': code, 'severity': severity, 'title': title, 'detail': detail})

    if lookup is None:
        from services.web_risk import check_web_risk
        session = requests.Session()
        lookup = lambda url: check_web_risk(url, session)  # noqa: E731

    # Outside links: names that copy a brand, betting sites, then Google for the most suspicious ones.
    lookalikes, betting, others = [], [], []
    for host, links in found['external'].items():
        brand = impersonation(links[0])
        if brand:
            lookalikes.append({'host': host, 'brand': brand, 'url': links[0]})
        elif gambling_site('', links[0]):
            betting.append({'host': host, 'url': links[0]})
        else:
            others.append({'host': host, 'url': links[0]})
    listed, statuses = [], []
    for item in (lookalikes + betting + others)[:WEB_RISK_EXTERNAL]:
        try:
            answer = lookup(item['url'])
        except Exception:
            answer = {'status': 'unavailable'}
        statuses.append(answer.get('status'))
        if answer.get('status') == 'matched':
            listed.append({'host': item['host'], 'url': item['url'], 'threat_types': list(answer.get('threat_types') or [])})
    # Its own pages, after the home page (site_trust already looked the start address up).
    pages = [p for p in found['pages'] if p.get('status') == 'read']
    listed_pages = []
    for page in pages[1:1 + WEB_RISK_INTERNAL]:
        try:
            answer = lookup(page['url'])
        except Exception:
            answer = {'status': 'unavailable'}
        statuses.append(answer.get('status'))
        if answer.get('status') == 'matched':
            listed_pages.append(page['url'])
    hidden_logins = [p['url'] for p in pages if p.get('password_form') and kit_path(p['url'])]
    gambling_pages = [p['url'] for p in pages if 'gambling' in (p.get('signals') or [])]
    downloads = []
    for item in found['downloads'][:MAX_DOWNLOADS]:
        answer = _download(item['url'], scan)
        downloads.append({**item, 'antivirus': {k: answer.get(k) for k in ('status', 'kind', 'signature') if k in answer}})
    infected = [d for d in downloads if d['antivirus'].get('status') == 'found' and d['antivirus'].get('kind') == 'malware']
    shop = shop_signals(found.get('text') or '', found['contacts'], age_days, found.get('shop_schema_pages', 0))

    if listed_pages:
        finding('crawl_page_listed', 'warning', 'Google lists pages of this site as dangerous',
                f'{len(listed_pages)} of its pages are on Google’s phishing or malware lists, for example {listed_pages[0]}.')
    if listed:
        finding('crawl_link_listed', 'warning', 'It links to dangerous sites',
                f'{len(listed)} of the sites it links to are on Google’s phishing or malware lists, for example {listed[0]["host"]}.')
    if infected:
        finding('crawl_malware_download', 'warning', 'It offers malware for download',
                f'Antivirus found {infected[0]["antivirus"].get("signature") or "malware"} in {infected[0]["url"]}.')
    if hidden_logins:
        finding('crawl_hidden_login', 'warning', 'A hidden login page',
                f'{hidden_logins[0]} asks for a password from a folder phishing kits use. Hacked sites carry these.')
    if lookalikes:
        finding('crawl_lookalike_links', 'warning', 'It links to copies of well-known sites',
                f'{lookalikes[0]["host"]} uses the name {lookalikes[0]["brand"]} but isn’t its site.')
    if gambling_pages and (len(gambling_pages) < len(pages) or len(pages) == 1):
        finding('crawl_gambling_pages', 'warning', 'Betting content on its pages',
                f'{len(gambling_pages)} of its pages show casino or betting content. Hacked sites often carry betting spam.')
    if betting:
        finding('crawl_betting_links', 'warning', 'It links to betting sites',
                f'It links to {len(betting)} betting sites, for example {betting[0]["host"]}.')
    if shop and shop['fake_signs']:
        finding('fake_shop_signs', 'warning', 'It looks like a fake shop',
                'It sells online but hides who runs it, or asks for bank transfer only. Fake shops take the money and send nothing.')
    if any(d['extension'] in PROGRAMS for d in found['downloads']) and not infected:
        finding('crawl_offers_programs', 'info', 'It offers programs for download',
                'Antivirus found nothing in the files we checked. Install apps only from Google Play or the maker’s official site.')
    risk_status = ('matched' if listed or listed_pages else 'unavailable' if 'unavailable' in statuses
                   else 'not_configured' if statuses and all(s == 'not_configured' for s in statuses) else 'checked')
    evidence = {'policy': 'site-crawl-v1', 'pages_read': found.get('pages_read', 0), 'pages': found['pages'],
                'external_sites': len(found['external']), 'links_checked': len(statuses) - len(pages[1:1 + WEB_RISK_INTERNAL]),
                'web_risk': risk_status, 'listed_links': listed, 'listed_pages': listed_pages, 'lookalike_links': lookalikes[:10],
                'betting_links': betting[:10], 'hidden_logins': hidden_logins[:5], 'gambling_pages': gambling_pages[:10],
                'downloads': downloads, 'downloads_found': len(found['downloads']), 'shop': shop,
                'contacts': found['contacts'], 'skipped_by_robots': found['skipped_by_robots'], 'stopped': found['stopped']}
    return evidence, findings
