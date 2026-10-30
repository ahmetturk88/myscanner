"""What a website is built on and how carefully it is run (site-posture-v1).

Free, local evidence only: the home page already fetched by web_assessment, DNS,
the DB-IP Lite database on this server and the email policy audit. Nothing here
is a vulnerability test. Old software, missing cookie flags and a domain anyone
can send email as are configuration observations (info); only a script loaded
from an address that copies a brand, the way card skimmers hide, is a warning.
"""
import ipaddress
import re
from urllib.parse import urljoin, urlsplit

POLICY = 'site-posture-v1'
MAX_SCRIPT_HOSTS = 30
MAX_COOKIES = 20
MAIL_DNS_SECONDS = 4
# Networks that sit in front of the real server: their location says nothing about where the site runs.
CDN = re.compile(r'cloudflare|akamai|fastly|amazon cloudfront|cloudfront|incapsula|imperva|sucuri|stackpath|bunny|cdn77|edgecast|verizon digital', re.I)

# (name, regex over the page HTML) for platforms that leave a plain mark in the page.
PLATFORMS = [
    ('WordPress', re.compile(r'/wp-content/|/wp-includes/', re.I)),
    ('WooCommerce', re.compile(r'woocommerce', re.I)),
    ('Shopify', re.compile(r'cdn\.shopify\.com|Shopify\.theme', re.I)),
    ('ikas', re.compile(r'cdn\.myikas\.com|ikas\.com', re.I)),
    ('Ticimax', re.compile(r'ticimax', re.I)),
    ('IdeaSoft', re.compile(r'ideasoft', re.I)),
    ('T-Soft', re.compile(r'tsoft|t-soft', re.I)),
    ('Magento', re.compile(r'mage/cookies|Magento_', re.I)),
    ('OpenCart', re.compile(r'catalog/view/theme|route=common/home', re.I)),
    ('PrestaShop', re.compile(r'prestashop', re.I)),
    ('Wix', re.compile(r'static\.wixstatic\.com|wix\.com', re.I)),
    ('Squarespace', re.compile(r'squarespace', re.I)),
    ('Joomla', re.compile(r'/media/jui/|joomla', re.I)),
    ('Drupal', re.compile(r'drupal-settings-json|/sites/default/files/', re.I)),
]
GENERATOR_VERSION = re.compile(r'^(WordPress|Joomla!?|Drupal)\s+(\d+(?:\.\d+)*)', re.I)
JQUERY = re.compile(r'jquery[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.I)
# The oldest major versions still receiving security fixes (as of 2026).
OLD = {'wordpress': (6, 0), 'joomla': (4, 0), 'drupal': (10, 0), 'jquery': (3, 0)}
PRIVACY = re.compile(r'kvkk|kişisel veriler|aydınlatma metni|gizlilik politikası|çerez politikası|privacy policy|cookie policy', re.I)
SESSION_COOKIE = re.compile(r'sess|sid$|^sid|token|auth|login|phpsessid|jsessionid|asp\.net', re.I)


def _version(text):
    try:
        return tuple(int(part) for part in text.split('.')[:2])
    except ValueError:
        return None


def _host(url):
    try:
        return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def _registrable(host):
    from services.url_tricks import split_host
    return split_host(host)[1] if host else ''


def cookie_flags(set_cookies):
    """[{'name', 'secure', 'httponly', 'samesite'}] from raw Set-Cookie header values; values are never kept."""
    cookies = []
    for raw in set_cookies[:MAX_COOKIES]:
        if not isinstance(raw, str) or '=' not in raw:
            continue
        name, _, rest = raw.partition('=')
        attributes = [part.strip() for part in rest.split(';')[1:]]
        flags = {a.lower() for a in attributes}
        samesite = next((a.split('=', 1)[1].strip() for a in attributes if a.lower().startswith('samesite=')), '')
        cookies.append({'name': name.strip()[:60], 'secure': 'secure' in flags, 'httponly': 'httponly' in flags,
                        'samesite': samesite[:10]})
    return cookies


def page_observations(soup, html, final_url, headers, set_cookies=()):
    """Read-only facts about the fetched home page: platform, outside scripts, plain-HTTP parts, cookies."""
    page_host = _host(final_url)
    site = _registrable(page_host)
    https = final_url.lower().startswith('https://')
    technology = []

    def add(name, version=None, source='page'):
        if name not in [t['name'] for t in technology]:
            technology.append({'name': name, 'version': version, 'source': source})
    generator = soup.find('meta', attrs={'name': re.compile('^generator$', re.I)})
    generator = str(generator.get('content') or '')[:120] if generator else ''
    match = GENERATOR_VERSION.match(generator)
    if match:
        add(match.group(1).rstrip('!').title() if match.group(1).lower() != 'wordpress' else 'WordPress', match.group(2), 'generator')
    elif generator:
        add(generator.split(' ')[0][:40], None, 'generator')
    sample = html[:400_000]
    for name, pattern in PLATFORMS:
        if pattern.search(sample):
            add(name)
    for header in ('Server', 'X-Powered-By'):
        value = str(headers.get(header) or '')[:80]
        if value:
            add(value, None, header)

    scripts, mixed, script_hosts = [], {'scripts': 0, 'frames': 0, 'other': 0}, []
    for tag, attribute in (('script', 'src'), ('iframe', 'src'), ('img', 'src'), ('link', 'href')):
        for element in soup.find_all(tag, limit=300):
            value = str(element.get(attribute) or '').strip()
            if not value or value.startswith(('data:', '#', 'javascript:')):
                continue
            try:
                absolute = urljoin(final_url, value)
            except ValueError:
                continue
            if https and absolute.lower().startswith('http://'):
                mixed['scripts' if tag == 'script' else 'frames' if tag == 'iframe' else 'other'] += 1
            if tag != 'script':
                continue
            scripts.append(absolute)
            version = JQUERY.search(absolute)
            if version:
                add('jQuery', version.group(1), 'script')
            host = _host(absolute)
            if host and _registrable(host) != site and host not in [s['host'] for s in script_hosts]:
                if len(script_hosts) < MAX_SCRIPT_HOSTS:
                    script_hosts.append({'host': host, 'url': absolute[:500]})
    return {'technology': technology[:12], 'script_count': len(scripts), 'outside_scripts': script_hosts,
            'mixed_content': mixed, 'cookies': cookie_flags(list(set_cookies))}


def hosting(dns):
    """Where the site's server is, from the A record and the local DB-IP Lite files."""
    values = ((dns or {}).get('A') or {}).get('values') or ((dns or {}).get('AAAA') or {}).get('values') or []
    address = next((v for v in values if isinstance(v, str)), '')
    if not address:
        return {'status': 'unavailable', 'reason': 'No address record'}
    try:
        ipaddress.ip_address(address)
        from services import ip_location
        found = ip_location.lookup(address)
    except (ValueError, ImportError, OSError):
        return {'status': 'unavailable', 'ip': address, 'reason': 'Location lookup failed'}
    if not found:
        return {'status': 'not_configured', 'ip': address}
    if CDN.search(found.get('org') or ''):
        return {'status': 'completed', 'ip': address, 'addresses': len(values), 'cdn': True, 'network': found.get('org'),
                'asn': found.get('asn'), 'source': 'DB-IP Lite'}
    return {'status': 'completed', 'ip': address, 'addresses': len(values), 'country': found.get('country'),
            'country_code': found.get('country_code'), 'city': found.get('city'), 'asn': found.get('asn'),
            'network': found.get('org'), 'source': 'DB-IP Lite'}


def mail_security(domain, resolve=None):
    """Can someone send email that claims to come from this domain? SPF and DMARC of the registrable domain."""
    from services.email_policy_audit import audit_dmarc, audit_spf
    if resolve is None:
        import dns.exception
        import dns.resolver

        def resolve(name, kind):
            # Big domains publish long TXT sets that need more than the page check's one-second budget.
            try:
                answer = dns.resolver.resolve(name + '.', kind, search=False, lifetime=MAIL_DNS_SECONDS)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except (dns.exception.DNSException, OSError) as error:
                raise OSError('DNS unavailable') from error
            if kind == 'TXT':
                return [b''.join(record.strings).decode('utf-8', 'replace') for record in answer][:30]
            return [str(record) for record in answer][:16]
    if not domain:
        return {'status': 'unavailable'}
    try:
        txt = resolve(domain, 'TXT')
        dmarc_txt = resolve('_dmarc.' + domain, 'TXT')
        mx = resolve(domain, 'MX')
    except Exception:
        return {'status': 'unavailable', 'domain': domain}
    spf_records = [r for r in txt if r.lower().startswith('v=spf1')]
    spf = audit_spf(domain, txt, lambda name, kind: (resolve(name, kind), 'completed')) if spf_records else {'status': 'not_found'}
    dmarc = audit_dmarc(dmarc_txt) if any(r.lower().startswith('v=dmarc1') for r in dmarc_txt) else {'status': 'not_found'}
    policy = str((dmarc.get('tags') or {}).get('p') or '').lower() if dmarc.get('status') != 'not_found' else ''
    spf_all = next((term for term in (spf_records[0].split() if spf_records else []) if term.lstrip('+-~?').lower() == 'all'), '')
    protected = policy in ('quarantine', 'reject')
    return {'status': 'completed', 'domain': domain, 'mail_servers': len(mx), 'spf': spf_records[0][:300] if spf_records else '',
            'spf_ends': spf_all, 'dmarc_policy': policy or ('missing' if dmarc.get('status') == 'not_found' else 'invalid'),
            'protected': protected}


def assess(report, resolve=None):
    """(evidence, findings) for the website check; never changes a verdict on its own except a copied script host."""
    from services.file_links import impersonation
    content = report.get('content') or {}
    observed = content.get('posture') or {}
    findings = []

    def finding(code, severity, title, detail):
        findings.append({'code': code, 'severity': severity, 'title': title, 'detail': detail})

    host = (report.get('structure') or {}).get('hostname') or ''
    domain = _registrable(host)
    place = hosting(report.get('dns'))
    mail = mail_security(domain, resolve)

    copied = []
    for item in observed.get('outside_scripts') or []:
        brand = impersonation(item['url'])
        if brand:
            copied.append({'host': item['host'], 'brand': brand})
    if copied:
        finding('script_lookalike', 'warning', 'It loads code from a copied address',
                f'A script comes from {copied[0]["host"]}, which uses the name {copied[0]["brand"]} but isn’t its site. Card-stealing code hides like this.')
    old = []
    for item in observed.get('technology') or []:
        version = _version(item.get('version') or '')
        floor = OLD.get(str(item.get('name')).lower())
        if version and floor and version < floor:
            old.append(f'{item["name"]} {item["version"]}')
    if old:
        finding('old_software', 'info', 'It runs old software',
                f'{", ".join(old[:3])} no longer gets security fixes. Hacked sites often run old versions; this isn’t proof of a problem.')
    mixed = observed.get('mixed_content') or {}
    if mixed.get('scripts') or mixed.get('frames'):
        finding('mixed_content', 'info', 'Some parts load without encryption',
                f'{mixed.get("scripts", 0) + mixed.get("frames", 0)} scripts or frames load over plain http:// on a secure page. Browsers block them; the site may look broken.')
    loose = [c['name'] for c in observed.get('cookies') or []
             if SESSION_COOKIE.search(c.get('name') or '') and not (c.get('secure') and c.get('httponly'))]
    if loose and str(report.get('http', {}).get('final_url', '')).startswith('https://'):
        finding('cookie_flags', 'info', 'Its login cookie isn’t fully protected',
                f'The cookie {loose[0]} is missing the Secure or HttpOnly flag. If it is your site, set both.')
    if mail.get('status') == 'completed' and not mail.get('protected'):
        finding('mail_spoofable', 'info', 'Others could send email in its name',
                f'{domain} has no enforced DMARC policy, so scammers can send email that looks like it comes from this site. Be careful with emails claiming to be from it.')
    evidence = {'policy': POLICY, 'hosting': place, 'mail': mail, 'technology': observed.get('technology') or [],
                'outside_scripts': (observed.get('outside_scripts') or [])[:MAX_SCRIPT_HOSTS], 'copied_scripts': copied,
                'mixed_content': mixed, 'cookies': observed.get('cookies') or [], 'old_software': old}
    return evidence, findings


def privacy_notice(text):
    """Whether the pages read mention a KVKK or privacy notice."""
    return bool(PRIVACY.search(text or ''))
