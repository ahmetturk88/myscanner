"""MyScanner Business: help the owner get an imitation taken down.

For one recorded look-alike name we gather public facts (DNS, and the registrar's
and the network owner's abuse contacts from RDAP; the fake site is never opened
here), then write ready-to-send reports:
- to the registrar's abuse desk and to the hosting network's abuse desk (email,
  sent by the owner from their own mail app: we never send on their behalf);
- to USOM (Türkiye's national CERT), Google Safe Browsing and, when the name is on
  Cloudflare, Cloudflare's abuse form.
Addresses in the texts are defanged (magazam-giris[.]com, hxxps://) as abuse desks
expect, so no mail app turns them into links. The owner marks the name "reported";
the daily look-alike watch then tells them when it disappears from DNS.
"""
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from extensions import db

FACTS_MAX_AGE = timedelta(days=1)
EMAIL = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$')
USOM_URL = 'https://www.usom.gov.tr/'
GOOGLE_URL = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl={lang}'
CLOUDFLARE_URL = 'https://abuse.cloudflare.com/'


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def defang(name):
    return str(name).replace('.', '[.]')


# ------------------------------------------------------------------ probes (network; replaced in tests)

def _rdap(path):
    from services.safe_http import PublicHTTPSession
    with PublicHTTPSession(response_limit=512 * 1024) as session:
        response = session.get(f'https://rdap.org/{path}', timeout=(4, 10), allow_redirects=True,
                               headers={'Accept': 'application/rdap+json'})
        try:
            return response.json() if response.status_code == 200 else None
        finally:
            response.close()


def _vcard_value(entity, field):
    card = entity.get('vcardArray') if isinstance(entity, dict) else None
    rows = card[1] if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list) else []
    for row in rows:
        if isinstance(row, list) and len(row) == 4 and row[0] == field and isinstance(row[3], str):
            return row[3].strip()
    return None


def _abuse_email(entities, depth=0):
    """The first abuse contact's email in an RDAP entity tree."""
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict):
            continue
        if 'abuse' in (entity.get('roles') or []):
            email = _vcard_value(entity, 'email')
            if email and EMAIL.match(email):
                return email.lower()
        if depth < 3:
            found = _abuse_email(entity.get('entities'), depth + 1)
            if found:
                return found
    return None


def probe_domain(name):
    """{'abuse': email | None} for the registrar of `name`."""
    data = _rdap(f'domain/{quote(name)}')
    return {'abuse': _abuse_email(data.get('entities'))} if isinstance(data, dict) else None


def probe_ip(ip):
    """{'org': network owner | None, 'abuse': email | None}."""
    data = _rdap(f'ip/{quote(ip)}')
    if not isinstance(data, dict):
        return None
    org = None
    for entity in data.get('entities') or []:
        if isinstance(entity, dict) and 'registrant' in (entity.get('roles') or []):
            org = _vcard_value(entity, 'fn')
            break
    org = org or (data.get('name') if isinstance(data.get('name'), str) else None)
    return {'org': org[:120] if org else None, 'abuse': _abuse_email(data.get('entities'))}


def probe_records(name):
    from services.business_monitor import probe_dns
    return probe_dns(name)


PROBES = {'domain': probe_domain, 'ip': probe_ip, 'records': probe_records}


# ------------------------------------------------------------------ facts and reports

def gather(row, probes=None, now=None, force=False):
    """Fill the host and abuse contacts of a look-alike (at most once a day). Returns the DNS records read now."""
    probes = {**PROBES, **(probes or {})}
    now = now or _now()
    records = _safe(probes['records'], row.name) or {}
    if not force and row.abuse_at and now - row.abuse_at < FACTS_MAX_AGE:
        return records
    addresses = list(records.get('A') or []) + list(records.get('AAAA') or [])
    row.host_ip = addresses[0][:45] if addresses else None
    domain = _safe(probes['domain'], row.name) or {}
    row.abuse_registrar = domain.get('abuse')
    host = _safe(probes['ip'], row.host_ip) if row.host_ip else None
    host = host or {}
    row.host_org, row.abuse_host = host.get('org'), host.get('abuse')
    row.abuse_at = now
    db.session.commit()
    return records


def on_cloudflare(row, records):
    names = ' '.join(records.get('NS') or []).lower()
    return '.ns.cloudflare.com' in names or 'cloudflare' in (row.host_org or '').lower()


REASONS = {
    'en': {'brand': 'its page shows our brand name', 'asks': 'its page asks for a password or card details',
           'new': 'it was registered only {days} days ago', 'live': 'it is online', 'dns': 'it is registered but shows no website yet'},
    'tr': {'brand': 'sayfasında markamızın adı geçiyor', 'asks': 'sayfası şifre veya kart bilgisi istiyor',
           'new': 'yalnızca {days} gün önce kaydedilmiş', 'live': 'yayında', 'dns': 'kayıtlı ama henüz web sitesi yok'},
}

TEMPLATES = {
    'en': ('Brand impersonation / possible phishing: {name}',
           'Hello,\n\n'
           'The domain {name} imitates our company\'s official website {own}. We are the verified owner of {own}.\n\n'
           'Evidence:\n'
           '- Look-alike address: {url}\n'
           '- Imitates: {own}\n'
           '- Facts: {reasons}\n'
           '{title_line}'
           '- Registered: {registered}\n'
           '- First seen by our monitoring: {first_seen}\n'
           '- Hosting: {host}\n\n'
           'Customers may be misled into entering their details on this site. Please investigate and suspend the '
           'domain or the hosted content if it violates your terms.\n\n'
           'Addresses are written with [.] on purpose so they do not become links.\n\n'
           'Regards,\n{company}\n{email}\n'),
    'tr': ('Marka taklidi / olası oltalama: {name}',
           'Merhaba,\n\n'
           '{name} alan adı, şirketimizin resmi web sitesi {own} adresini taklit ediyor. {own} alan adının doğrulanmış sahibiyiz.\n\n'
           'Kanıtlar:\n'
           '- Taklit adres: {url}\n'
           '- Taklit edilen: {own}\n'
           '- Tespitler: {reasons}\n'
           '{title_line}'
           '- Kayıt tarihi: {registered}\n'
           '- İzlememizin ilk gördüğü tarih: {first_seen}\n'
           '- Barındırma: {host}\n\n'
           'Müşterilerimiz bu sitede bilgilerini girmeye yönlendirilebilir. Lütfen inceleyip kurallarınızı ihlal ediyorsa '
           'alan adını veya içeriği askıya alın.\n\n'
           'Adresler bağlantıya dönüşmesin diye bilerek [.] ile yazılmıştır.\n\n'
           'Saygılarımızla,\n{company}\n{email}\n'),
}


def report_text(row, own, company, email, lang='en', now=None):
    """(subject, body) for an abuse report in `lang` (English for international abuse desks, Turkish for USOM)."""
    from services.business_lookalike import is_new
    lang = 'tr' if lang == 'tr' else 'en'
    now = now or _now()
    words = REASONS[lang]
    reasons = [words['live'] if row.live else words['dns']]
    if row.risk == 'high' and row.live:
        reasons.append(words['brand'] + ' / ' + words['asks'])
    if is_new(row, now):
        reasons.append(words['new'].format(days=(now.date() - row.registered).days))
    subject, body = TEMPLATES[lang]
    unknown = 'bilinmiyor' if lang == 'tr' else 'unknown'
    host = ' '.join(x for x in (row.host_ip, f'({row.host_org})' if row.host_org else '') if x) or unknown
    title_line = (f'- {"Sayfa başlığı" if lang == "tr" else "Page title"}: "{row.title[:120]}"\n' if row.title else '')
    values = {'name': defang(row.name), 'own': defang(own), 'url': 'hxxps://' + defang(row.name) + '/',
              'reasons': '; '.join(reasons), 'title_line': title_line,
              'registered': row.registered.strftime('%d.%m.%Y') if row.registered else unknown,
              'first_seen': row.first_seen.strftime('%d.%m.%Y'), 'host': host,
              'company': company or own, 'email': email or ''}
    return subject.format(**values), body.format(**values)


def mailto(to, subject, body):
    return f'mailto:{quote(to)}?subject={quote(subject)}&body={quote(body)}'


def reports(row, own, company, email, records, lang='tr', now=None):
    """The ready-to-send reports for the takedown page, most direct first."""
    subject_en, body_en = report_text(row, own, company, email, 'en', now)
    subject_tr, body_tr = report_text(row, own, company, email, 'tr', now)
    items = []
    if row.abuse_registrar:
        items.append({'key': 'registrar', 'to': row.abuse_registrar, 'subject': subject_en, 'body': body_en,
                      'mailto': mailto(row.abuse_registrar, subject_en, body_en)})
    if row.abuse_host and row.abuse_host != row.abuse_registrar:
        items.append({'key': 'host', 'to': row.abuse_host, 'subject': subject_en, 'body': body_en,
                      'mailto': mailto(row.abuse_host, subject_en, body_en)})
    if on_cloudflare(row, records):
        items.append({'key': 'cloudflare', 'link': CLOUDFLARE_URL, 'subject': subject_en, 'body': body_en})
    items.append({'key': 'usom', 'link': USOM_URL, 'subject': subject_tr, 'body': body_tr})
    items.append({'key': 'google', 'link': GOOGLE_URL.format(lang='tr' if lang == 'tr' else 'en'), 'subject': subject_en,
                  'body': body_en})
    return items


def _safe(function, *args):
    try:
        return function(*args)
    except Exception:
        return None
