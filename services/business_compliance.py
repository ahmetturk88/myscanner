"""MyScanner Business: the KVKK and legal-pages checklist (Türkiye).

Once a week, with the site inspection, we read the home page and up to six of the
site's own legal pages it links to (KVKK, privacy, cookies, contact, returns,
distance-selling contract…) and check what a Turkish customer and the law expect
to find. Read-only and passive: public pages only, nothing is submitted.

This is a checklist, not legal advice: a found page is not a judgement of its
content, and a missing one may sit where we did not look.
"""
import json
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from extensions import db

MAX_PAGES = 6
PAGE_LIMIT = 1024 * 1024
LEGAL_LINK = re.compile(r'kvkk|ki[sş]isel-?veri|aydinlatma|ayd[ıi]nlatma|gizlilik|privacy|cerez|çerez|cookie|iletisim|ileti[sş]im|'
                        r'contact|iade|cayma|mesafeli|satis-sozlesmesi|sat[ıi][sş]-s[oö]zle[sş]mesi|on-bilgilendirme|terms|kosullar|ko[sş]ullar', re.I)
KVKK = re.compile(r'kvkk|ki[sş]isel verilerin korunmas[ıi]|ayd[ıi]nlatma metni|6698 say[ıi]l[ıi]', re.I)
PRIVACY = re.compile(r'gizlilik politikas[ıi]|gizlilik s[oö]zle[sş]mesi|gizlilik bildirimi|privacy policy|privacy notice', re.I)
COOKIE_POLICY = re.compile(r'[cç]erez politikas[ıi]|[cç]erez ayd[ıi]nlatma|cookie policy|cookie notice', re.I)
CONSENT_TOOL = re.compile(r'cookiebot|onetrust|cookielaw|cookieyes|cookie-script|iubenda|complianz|osano|usercentrics|quantcast|'
                          r'didomi|termly|cookiefirst|klaro|tarteaucitron|cookie-law-info|cookie-notice|cookieconsent', re.I)
CONSENT_TEXT = re.compile(r'[cç]erezleri kabul|t[uü]m[uü]n[uü] kabul|kabul et ve kapat|[cç]erez tercihleri|[cç]erez ayarlar[ıi]|'
                          r'accept all cookies|accept cookies|cookie settings|cookie preferences', re.I)
TRACKERS = (('Google Analytics', re.compile(r'google-analytics\.com|googletagmanager\.com|gtag\(', re.I)),
            ('Meta Pixel', re.compile(r'connect\.facebook\.net|fbq\(', re.I)),
            ('Hotjar', re.compile(r'hotjar\.com', re.I)),
            ('Yandex Metrica', re.compile(r'mc\.yandex\.(ru|com)', re.I)),
            ('Microsoft Clarity', re.compile(r'clarity\.ms', re.I)),
            ('TikTok Pixel', re.compile(r'analytics\.tiktok\.com', re.I)))
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
DISTANCE = re.compile(r'mesafeli sat[ıi][sş] s[oö]zle[sş]mesi|mesafeli s[oö]zle[sş]me|[oö]n bilgilendirme formu', re.I)
ITEMS = ('kvkk', 'privacy', 'cookies', 'consent', 'contact', 'forms')
SHOP_ITEMS = ('distance', 'returns', 'company', 'etbis')


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ------------------------------------------------------------------ reading the pages (network; replaced in tests)

def _get(session, url):
    response = session.get(url, timeout=(4, 10), allow_redirects=True,
                           headers={'User-Agent': 'MyScanner/1.0 (read-only legal pages check; +https://myscanners.com)',
                                    'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.6'})
    try:
        if response.status_code != 200 or 'html' not in (response.headers.get('Content-Type') or 'text/html'):
            return None, None
        return response.url, response.content[:PAGE_LIMIT].decode(response.encoding or 'utf-8', 'replace')
    finally:
        response.close()


def probe_pages(domain):
    """[(url, html)] for the home page and up to MAX_PAGES of its own legal pages."""
    from bs4 import BeautifulSoup
    from services.safe_http import PublicHTTPSession
    pages = []
    with PublicHTTPSession(response_limit=PAGE_LIMIT) as session:
        url, html = _get(session, f'https://{domain}/')
        if html is None:
            return pages
        pages.append((url, html))
        host = urlsplit(url).hostname or domain
        seen, links = {url}, []
        for anchor in BeautifulSoup(html, 'html.parser').find_all('a', href=True):
            target = urljoin(url, anchor['href']).split('#')[0]
            parts = urlsplit(target)
            same = (parts.hostname or '').removeprefix('www.') == host.removeprefix('www.')
            if parts.scheme in ('http', 'https') and same and target not in seen and \
                    (LEGAL_LINK.search(parts.path) or LEGAL_LINK.search(anchor.get_text(' ', strip=True)[:80])):
                seen.add(target)
                links.append(target)
        for target in links[:MAX_PAGES]:
            try:
                page_url, page_html = _get(session, target)
            except Exception:
                continue
            if page_html is not None:
                pages.append((page_url, page_html))
    return pages


# ------------------------------------------------------------------ judging

def _where(pages, pattern):
    """The path of the first page whose address or text matches, or None."""
    for url, text in pages:
        if pattern.search(urlsplit(url).path) or pattern.search(text):
            return urlsplit(url).path or '/'
    return None


def assess(pages):
    """{'items': {name: {'state', ...}}, 'shop': bool, 'pages': [paths]} from [(url, html)]."""
    from bs4 import BeautifulSoup
    from services.site_crawl import ADDRESS, COMPANY_ID, ETBIS, PHONE, RETURNS, SHOP, SHOP_ACTION
    texts, raw, forms = [], [], []
    for url, html in pages:
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = urljoin(url, form.get('action') or url)
            forms.append(action)
        raw.append(html)
        full = soup.get_text(' ', strip=True)
        for anchor in soup.find_all('a'):
            anchor.decompose()  # a footer link named "KVKK" is not the notice: the linked page (read too) must show it
        texts.append((url, soup.get_text(' ', strip=True), full))
    everything = ' '.join(t for _, _, t in texts)
    texts = [(u, t) for u, t, _ in texts]
    source = ' '.join(raw)
    items = {}

    def found(name, pattern):
        where = _where(texts, pattern)
        items[name] = {'state': 'ok', 'where': where} if where else {'state': 'warn'}

    found('kvkk', KVKK)
    found('privacy', PRIVACY)
    found('cookies', COOKIE_POLICY)
    trackers = [name for name, pattern in TRACKERS if pattern.search(source)]
    has_tool = bool(CONSENT_TOOL.search(source) or CONSENT_TEXT.search(everything))
    if has_tool:
        items['consent'] = {'state': 'ok', 'trackers': trackers}
    elif trackers:
        items['consent'] = {'state': 'warn', 'trackers': trackers}
    else:
        items['consent'] = {'state': 'info', 'trackers': []}
    contact = bool(EMAIL.search(everything) or PHONE.search(everything) or 'mailto:' in source or 'tel:' in source)
    items['contact'] = {'state': 'ok' if contact else 'warn', 'address': bool(ADDRESS.search(everything))}
    insecure = [f for f in forms if f.startswith('http://')]
    items['forms'] = {'state': 'bad' if insecure else 'ok' if forms else 'info'}
    shop = bool(SHOP_ACTION.search(everything) and len(SHOP.findall(everything)) >= 2)
    if shop:
        found('distance', DISTANCE)
        found('returns', RETURNS)
        found('company', COMPANY_ID)
        found('etbis', ETBIS)
    return {'items': items, 'shop': shop, 'pages': [urlsplit(u).path or '/' for u, _ in pages][:MAX_PAGES + 1]}


# ------------------------------------------------------------------ one run

def run_compliance(domain_row, probe=None, now=None):
    """Check the legal pages once; report items that went missing or were added. Returns the snapshot or None."""
    from models import BusinessEvent, BusinessSnapshot
    from services.business_monitor import latest_snapshot
    now = now or _now()
    if domain_row.verified_at is None:
        return None
    try:
        pages = (probe or probe_pages)(domain_row.domain)
    except Exception:
        pages = []
    if not pages:
        return None  # the site did not answer: no conclusion, the previous result stays
    current = assess(pages)
    previous_row = latest_snapshot(domain_row.id, kind='kvkk')
    previous = json.loads(previous_row.results).get('items', {}) if previous_row else None
    snapshot = BusinessSnapshot(domain_id=domain_row.id, kind='kvkk', created_at=now, score=None,
                                results=json.dumps(current, ensure_ascii=False, sort_keys=True))
    db.session.add(snapshot)
    db.session.flush()
    if previous is not None:
        for name, item in current['items'].items():
            before = (previous.get(name) or {}).get('state')
            if before == 'ok' and item['state'] in ('warn', 'bad'):
                code, severity = 'kvkk_missing', 'warn'
            elif before in ('warn', 'bad') and item['state'] == 'ok':
                code, severity = 'kvkk_fixed', 'good'
            else:
                continue
            db.session.add(BusinessEvent(domain_id=domain_row.id, snapshot_id=snapshot.id, created_at=now, code=code,
                                         severity=severity, params=json.dumps({'item': name})))
    db.session.commit()
    return snapshot


def view(domain_id, text):
    """[(name, state, value)] for the workspace and the report, or None before the first check."""
    from services.business_monitor import latest_snapshot
    row = latest_snapshot(domain_id, kind='kvkk')
    if row is None:
        return None
    data = json.loads(row.results)
    names, values = text['kvkk_names'], text['kvkk_values']
    rows = []
    for name in ITEMS + (SHOP_ITEMS if data.get('shop') else ()):
        item = (data.get('items') or {}).get(name)
        if not item:
            continue
        state = item['state']
        if name == 'consent':
            trackers = ', '.join(item.get('trackers') or [])
            value = values['consent_ok'] if state == 'ok' else values['consent_needed'].format(trackers=trackers) \
                if state == 'warn' else values['consent_none']
        elif name == 'forms':
            value = {'bad': values['forms_bad'], 'ok': values['forms_ok']}.get(state, values['forms_none'])
        elif name == 'contact':
            value = values['found'] if state == 'ok' else values['missing']
        else:
            value = (values['found'] + (f" · {item['where']}" if item.get('where') and item['where'] != '/' else '')) \
                if state == 'ok' else values['missing']
        rows.append((names[name], state, value))
    return {'rows': rows, 'checked': row.created_at, 'shop': bool(data.get('shop'))}
