"""MyScanner Business: watch for registered names that imitate a company's domain.

Two sources, both public:
1. Generated candidates: typos of the name (missing, doubled, swapped or
   neighbouring letters, look-alike digits), the same name under other endings
   (.net, .com.tr, .shop…), and the name joined with words scams use (giris,
   odeme, destek…). Each run checks the next batch in DNS, so the whole list is
   covered every few days without hammering resolvers.
2. Certificate Transparency (crt.sh): certificates issued for any name that
   contains the brand, which catches combinations no list can guess.

A name that resolves is recorded once. If it also answers on the web, its home
page is read once (bounded, through the public-network session; nothing is
submitted) to judge the risk: high when it shows the brand or asks for a
password or card, medium when it is a live site, low when it only exists in DNS.
New names and names that go live become events; the owner can dismiss a name.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver

from extensions import db
from services.url_tricks import skeleton, split_host

ENDINGS = ('com', 'net', 'org', 'com.tr', 'net.tr', 'org.tr', 'biz.tr', 'co', 'info', 'biz', 'shop', 'store', 'online',
           'site', 'xyz', 'top', 'app', 'live', 'click')
WORDS = ('giris', 'login', 'destek', 'odeme', 'kampanya', 'indirim', 'online', 'tr', 'secure', 'hesap', 'musteri', 'iade',
         'hediye', 'shop', 'resmi', 'kargo', 'bonus', 'apply')
WORD_ENDINGS = ('com', 'net', 'com.tr', 'online', 'site', 'shop')
NEIGHBOURS = {'q': 'wa', 'w': 'qes', 'e': 'wrd', 'r': 'etf', 't': 'ryg', 'y': 'tuh', 'u': 'yij', 'i': 'uok', 'o': 'ipl',
              'p': 'ol', 'a': 'qsz', 's': 'adwx', 'd': 'sfe', 'f': 'dgr', 'g': 'fht', 'h': 'gjy', 'j': 'hku', 'k': 'jli',
              'l': 'ko', 'z': 'xa', 'x': 'zcs', 'c': 'xvd', 'v': 'cbf', 'b': 'vng', 'n': 'bmh', 'm': 'n'}
LOOKS = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5', 'm': 'rn', 'w': 'vv', 'b': '8'}
BATCH = 120
EVERY = timedelta(hours=23)
LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
TITLE = re.compile(rb'<title[^>]*>(.*?)</title>', re.I | re.S)
PASSWORD = re.compile(rb'type\s*=\s*["\']?password', re.I)
CARD = re.compile(rb'(card|kart)[^<>]{0,40}(number|numaras)|cvv|cvc|son kullanma', re.I)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def brand_of(domain):
    """('magazam', 'com.tr') for magazam.com.tr; the label is what imitations copy."""
    _, registrable, _ = split_host(domain)
    label, _, ending = registrable.partition('.')
    return label, ending


def typos(label):
    found = set()
    for i in range(len(label)):
        found.add(label[:i] + label[i + 1:])                                  # missing letter
        found.add(label[:i] + label[i] + label[i:])                           # doubled letter
        if i + 1 < len(label):
            found.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])     # swapped letters
            found.add(label[:i + 1] + '-' + label[i + 1:])                     # inserted hyphen
        for near in NEIGHBOURS.get(label[i], ''):
            found.add(label[:i] + near + label[i + 1:])                        # neighbouring key
        if label[i] in LOOKS:
            found.add(label[:i] + LOOKS[label[i]] + label[i + 1:])             # look-alike digit or letters
    return {t for t in found if t != label and len(t) >= 2 and LABEL.match(t)}


def candidates(domain):
    """Every generated look-alike registrable name, most likely first; never the domain itself."""
    label, ending = brand_of(domain)
    own = f'{label}.{ending}'
    names = [f'{label}.{e}' for e in ENDINGS]
    for t in sorted(typos(label)):
        names += [f'{t}.{ending}'] + ([f'{t}.com'] if ending != 'com' else [])
    for word in WORDS:
        for joined in (f'{label}-{word}', f'{word}-{label}', f'{label}{word}'):
            if LABEL.match(joined):
                names += [f'{joined}.{e}' for e in WORD_ENDINGS]
    seen, ordered = {own}, []
    for name in names:
        if name not in seen and len(name) <= 253:
            seen.add(name)
            ordered.append(name)
    return ordered


def resembles(name, label):
    """A certificate name counts when its registrable part carries the brand (also in look-alike letters)."""
    _, registrable, _ = split_host(name)
    part = registrable.split('.')[0]
    brand = skeleton(label)
    return len(brand) >= 4 and brand in skeleton(part)


# ------------------------------------------------------------------ probes (network; replaced in tests)

def probe_resolve(name):
    """Addresses of a name; [] when it does not exist; None when DNS could not answer."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    try:
        return sorted(str(r) for r in resolver.resolve(name + '.', 'A', search=False, lifetime=3))[:4]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return None


def probe_ct(label):
    """Registrable names from certificates whose names contain the label (crt.sh)."""
    from services.safe_http import PublicHTTPSession
    from services.source_switches import source_enabled
    if not source_enabled('crtsh') or len(label) < 4:
        return set()
    names = set()
    with PublicHTTPSession(response_limit=4 * 1024 * 1024) as session:
        response = session.get('https://crt.sh/', params={'q': f'%{label}%', 'output': 'json'}, timeout=(3, 20),
                               allow_redirects=False)
        try:
            if response.status_code != 200:
                return set()
            data = response.json()
        finally:
            response.close()
    for row in data[:3000] if isinstance(data, list) else []:
        value = row.get('name_value') if isinstance(row, dict) else None
        for name in (value.splitlines()[:50] if isinstance(value, str) else []):
            name = name.strip().lower().lstrip('*.').rstrip('.')
            if name and len(name) <= 253 and all(LABEL.match(part) for part in name.split('.')):
                names.add(split_host(name)[1])
    return names


def probe_inspect(name, label):
    """Read the home page once: is it live, its title, and does it show the brand or ask for a password or card?"""
    from services.safe_http import PublicHTTPSession
    with PublicHTTPSession(response_limit=1024 * 1024) as session:
        for scheme in ('https', 'http'):
            try:
                response = session.get(f'{scheme}://{name}/', timeout=(4, 8), allow_redirects=True)
            except Exception:
                continue
            try:
                body = response.content[:1024 * 1024] if response.status_code < 500 else b''
            finally:
                response.close()
            if not body:
                continue
            match = TITLE.search(body)
            title = re.sub(r'\s+', ' ', match.group(1).decode('utf-8', 'replace')).strip()[:200] if match else ''
            page = skeleton(body.decode('utf-8', 'replace'))
            return {'live': True, 'title': title, 'brand': skeleton(label) in page,
                    'asks': bool(PASSWORD.search(body) or CARD.search(body))}
    return {'live': False, 'title': '', 'brand': False, 'asks': False}


PROBES = {'resolve': probe_resolve, 'ct': probe_ct, 'inspect': probe_inspect}


def risk_of(info):
    if not info.get('live'):
        return 'low'
    return 'high' if info.get('brand') or info.get('asks') else 'medium'


# ------------------------------------------------------------------ one run

def run_lookalikes(domain_row, probes=None, now=None):
    """Check the next batch of candidates and the certificate names; record and report new imitations."""
    import json
    from models import BusinessEvent, BusinessLookalike
    probes = {**PROBES, **(probes or {})}
    now = now or _now()
    if domain_row.verified_at is None:
        return []
    label, _ = brand_of(domain_row.domain)
    own = split_host(domain_row.domain)[1]
    pool = candidates(domain_row.domain)
    start = (domain_row.lookalike_cursor or 0) % max(len(pool), 1)
    batch = (pool[start:] + pool[:start])[:BATCH]
    sources = {name: 'typo' for name in batch}
    try:
        for name in probes['ct'](label):
            if name != own and resembles(name, label):
                sources.setdefault(name, 'ct')
    except Exception:
        pass  # the certificate index is a bonus; a failure only means fewer names this run
    known = {row.name: row for row in BusinessLookalike.query.filter_by(domain_id=domain_row.id).all()}
    names = list(sources)
    with ThreadPoolExecutor(max_workers=8) as pool_exec:
        answers = dict(zip(names, pool_exec.map(lambda n: _safe(probes['resolve'], n), names)))
    found = []
    for name in names:
        addresses = answers.get(name)
        row = known.get(name)
        if addresses is None:
            continue  # DNS did not answer: no conclusion either way
        if not addresses:
            if row is not None:
                row.resolves = False
            continue
        if row is None:
            info = _safe(probes['inspect'], name, label) or {'live': False}
            row = BusinessLookalike(domain_id=domain_row.id, name=name, source=sources[name], first_seen=now, last_seen=now,
                                    resolves=True, live=bool(info.get('live')), risk=risk_of(info), title=(info.get('title') or None))
            db.session.add(row)
            found.append(('lookalike_found', 'bad' if row.risk == 'high' else 'warn', {'name': name, 'risk': row.risk}))
            continue
        row.last_seen, row.resolves = now, True
        if row.status == 'open' and not row.live and now - row.first_seen >= timedelta(days=1):
            info = _safe(probes['inspect'], name, label) or {'live': False}
            if info.get('live'):
                row.live, row.risk, row.title = True, risk_of(info), (info.get('title') or row.title)
                found.append(('lookalike_live', 'bad', {'name': name, 'risk': row.risk}))
    for code, severity, params in found:
        db.session.add(BusinessEvent(domain_id=domain_row.id, created_at=now, code=code, severity=severity,
                                     params=json.dumps(params, ensure_ascii=False, sort_keys=True)))
    domain_row.lookalike_cursor = (start + len(batch)) % max(len(pool), 1)
    domain_row.lookalike_at = now
    db.session.commit()
    return found


def _safe(function, *args):
    try:
        return function(*args)
    except Exception:
        return None


def lookalike_due(now=None, limit=5):
    from models import BusinessDomain
    now = now or _now()
    rows = BusinessDomain.query.filter(BusinessDomain.verified_at.isnot(None)).filter(
        (BusinessDomain.lookalike_at.is_(None)) | (BusinessDomain.lookalike_at <= now - EVERY)).all()
    rows.sort(key=lambda d: d.lookalike_at or datetime.min)
    return rows[:limit]


def open_lookalikes(domain_id, limit=20):
    from models import BusinessLookalike
    order = {'high': 0, 'medium': 1, 'low': 2}
    rows = BusinessLookalike.query.filter_by(domain_id=domain_id, status='open', resolves=True).all()
    rows.sort(key=lambda r: (order.get(r.risk, 3), -(r.first_seen.timestamp())))
    return rows[:limit]
