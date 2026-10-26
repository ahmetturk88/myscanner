"""Tricks hidden in a link's address, read the way a browser reads it (url-evidence-v12).

`unmask` runs on what the user pasted, before the usual public-address checks:
it removes what browsers ignore or decode (a fake name before "@", an IP
address written as one big number or in hex, %-encoded letters in the name)
and records each trick. `address_signals` reads the cleaned address itself:
look-alike letters from other alphabets, a bank's or shop's domain used as a
decoy in front of the real one, or a brand name in an address the brand does
not own.

Nothing here makes a network request.
"""
import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit, urlunsplit

import Levenshtein

# Public suffixes with two or more labels that matter for the links people get
# in Turkey, and hosting platforms where each customer gets their own subdomain
# (the platform's age and fame say nothing about the customer's page).
MULTI_SUFFIXES = {
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'gen.tr', 'biz.tr', 'info.tr', 'web.tr', 'av.tr',
    'bel.tr', 'k12.tr', 'tsk.tr', 'pol.tr', 'name.tr', 'tel.tr', 'tv.tr', 'dr.tr', 'bbs.tr',
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp',
    'co.kr', 'com.br', 'com.cn', 'com.sa', 'com.eg', 'co.in', 'com.mx', 'co.za', 'com.sg', 'com.my',
    'com.ar', 'com.co', 'com.pk', 'com.ng', 'com.ua', 'com.cy', 'com.az', 'co.il', 'com.hk', 'com.tw',
}
# Default names of rented servers (vmi123.contaboserver.net): a site under one has no name of its own.
SERVER_HOSTS = {'contaboserver.net', 'your-server.de', 'vultrusercontent.com', 'hostwindsdns.com', 'linodeusercontent.com',
                'ip.linodeusercontent.com', 'hosted-by-vultr.com', 'kimsufi.com', 'ovh.net', 'vps.ovh.net', 'secureserver.net',
                'hetzner.cloud', 'digitaloceanspaces.com'}
# Files a link can make a phone or computer install or run (url-evidence-v12). "com" and "js"
# are left out when read from the address alone: they are also ordinary names and web scripts.
PROGRAM_EXTENSIONS = {'apk', 'xapk', 'apks', 'exe', 'msi', 'scr', 'bat', 'cmd', 'com', 'pif', 'js', 'jse', 'vbs', 'vbe',
                      'wsf', 'hta', 'ps1', 'jar', 'dmg', 'pkg', 'lnk', 'dll', 'appx', 'msix', 'appxbundle', 'ipa'}
ADDRESS_PROGRAM_EXTENSIONS = PROGRAM_EXTENSIONS - {'com', 'js'}
# Under a two-letter country ending these are part of the ending, not the site's name.
COUNTRY_SECOND_LEVELS = {'com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'or', 'ne', 'gen', 'nom', 'biz', 'info', 'gob', 'mil', 'web'}
SHARED_HOSTING = {
    'github.io', 'gitlab.io', 'blogspot.com', 'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev',
    'netlify.app', 'vercel.app', 'herokuapp.com', 'glitch.me', 'weebly.com', 'wixsite.com', 'wordpress.com',
    '000webhostapp.com', 'ngrok-free.app', 'ngrok.io', 'ngrok.app', 'duckdns.org', 'azurewebsites.net',
    'appspot.com', 'r2.dev', 'godaddysites.com', 'square.site', 'webflow.io', 'framer.app', 'framer.website',
    'replit.app', 'repl.co', 'surge.sh', 'onrender.com', 'fly.dev', 'translate.goog', 'myshopify.com',
    'tilda.ws', 'mystrikingly.com', 'jimdosite.com', 'site123.me', 'carrd.co', 'notion.site', 'yolasite.com',
    'trycloudflare.com', 'loca.lt', 'serveo.net', 'cloudfront.net', 'amazonaws.com', 'b-cdn.net',
    'ipfs.io', 'dweb.link', 'web.core.windows.net', 'blob.core.windows.net', 'storage.googleapis.com',
    'cloudworkstations.dev', 'idx.dev', 'firebasestorage.app', 'ondigitalocean.app', 'up.railway.app', 'deno.dev',
    'pythonanywhere.com', 'zapier.app', 'softr.app', 'glide.page', 'bubbleapps.io', 'webnode.page', 'mobirisesite.com',
} | SERVER_HOSTS

# Brands that scam links in Turkey imitate most, with the domains each one owns.
BRANDS = {
    'garanti': {'garantibbva.com.tr', 'garanti.com.tr', 'garantibbva.com', 'bonus.com.tr'},
    'garantibbva': {'garantibbva.com.tr', 'garanti.com.tr', 'garantibbva.com'},
    'akbank': {'akbank.com', 'akbank.com.tr', 'axess.com.tr'},
    'isbank': {'isbank.com.tr', 'maximum.com.tr'},
    'isbankasi': {'isbank.com.tr'},
    'ziraat': {'ziraatbank.com.tr', 'ziraat.com.tr', 'bankkart.com.tr'},
    'ziraatbank': {'ziraatbank.com.tr'},
    'yapikredi': {'yapikredi.com.tr', 'worldcard.com.tr'},
    'halkbank': {'halkbank.com.tr', 'paraf.com.tr'},
    'vakifbank': {'vakifbank.com.tr'},
    'denizbank': {'denizbank.com', 'denizbank.com.tr', 'fastpay.com.tr'},
    'qnb': {'qnb.com.tr', 'qnb.com', 'qnbfinansbank.com', 'enpara.com'},
    'finansbank': {'qnbfinansbank.com', 'qnb.com.tr'},
    'enpara': {'enpara.com'},
    'papara': {'papara.com'},
    'ininal': {'ininal.com'},
    'turkcell': {'turkcell.com.tr', 'paycell.com.tr', 'bip.com'},
    'vodafone': {'vodafone.com.tr', 'vodafone.com'},
    'turktelekom': {'turktelekom.com.tr', 'turktelekom.com'},
    'edevlet': {'turkiye.gov.tr'},
    'turkiyegov': {'turkiye.gov.tr'},
    'ptt': {'ptt.gov.tr', 'pttavm.com', 'pttbank.gov.tr'},
    'pttkargo': {'ptt.gov.tr'},
    'yurtici': {'yurticikargo.com'},
    'yurticikargo': {'yurticikargo.com'},
    'araskargo': {'araskargo.com.tr'},
    'mngkargo': {'mngkargo.com.tr', 'dhlecommerce.com.tr'},
    'suratkargo': {'suratkargo.com.tr'},
    'trendyol': {'trendyol.com', 'ty.gl', 'trendyol-milla.com', 'trendyolgo.com'},
    'hepsiburada': {'hepsiburada.com', 'hepsiburada.com.tr', 'hepsipay.com', 'hepsijet.com'},
    'sahibinden': {'sahibinden.com'},
    'migros': {'migros.com.tr', 'macroonline.com.tr'},
    'turkishairlines': {'turkishairlines.com', 'thy.com'},
    'paypal': {'paypal.com', 'paypal.me', 'paypalobjects.com'},
    'apple': {'apple.com', 'icloud.com', 'apple.co', 'mzstatic.com'},
    'icloud': {'icloud.com', 'apple.com'},
    'google': {'google.com', 'google.com.tr', 'youtube.com', 'gmail.com', 'goo.gl', 'g.co', 'gstatic.com',
               'googleapis.com', 'googleusercontent.com', 'googlevideo.com', 'withgoogle.com', 'blogger.com',
               'googleblog.com', 'googlesource.com', 'googletagmanager.com', 'google-analytics.com'},
    'gmail': {'gmail.com', 'google.com'},
    'microsoft': {'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com',
                  'office365.com', 'windows.com', 'azure.com', 'msn.com', 'bing.com', 'sharepoint.com'},
    'outlook': {'outlook.com', 'live.com', 'office.com', 'microsoft.com'},
    'office365': {'office365.com', 'office.com', 'microsoft.com'},
    'netflix': {'netflix.com', 'netflix.net', 'nflxext.com'},
    'amazon': {'amazon.com', 'amazon.com.tr', 'amazon.de', 'amazon.co.uk', 'amazonaws.com', 'media-amazon.com'},
    'facebook': {'facebook.com', 'fb.com', 'fb.me', 'fbcdn.net', 'meta.com'},
    'instagram': {'instagram.com', 'cdninstagram.com'},
    'whatsapp': {'whatsapp.com', 'whatsapp.net', 'wa.me'},
    'binance': {'binance.com', 'binance.tr'},
    'steam': {'steampowered.com', 'steamcommunity.com'},
    'steamcommunity': {'steamcommunity.com'},
    'dhl': {'dhl.com', 'dhl.com.tr', 'dhl.de'},
    'ups': {'ups.com'},
    'fedex': {'fedex.com'},
    'spotify': {'spotify.com', 'spotify.link'},
    'linkedin': {'linkedin.com', 'lnkd.in'},
    'twitter': {'twitter.com', 'x.com', 't.co'},
    'telegram': {'telegram.org', 't.me', 'telegram.me'},
    'xfinity': {'xfinity.com', 'comcast.net', 'comcast.com'},
    'comcast': {'comcast.com', 'comcast.net', 'xfinity.com'},
    'verizon': {'verizon.com', 'verizonwireless.com'},
    'chase': {'chase.com', 'jpmorganchase.com'},
    'wellsfargo': {'wellsfargo.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'usps': {'usps.com'},
    'royalmail': {'royalmail.com'},
    'roblox': {'roblox.com', 'rbxcdn.com'},
    'coinbase': {'coinbase.com'},
    'metamask': {'metamask.io'},
    'adobe': {'adobe.com', 'adobelogin.com'},
    'docusign': {'docusign.com', 'docusign.net'},
    'dropbox': {'dropbox.com', 'dropboxusercontent.com'},
    'onedrive': {'onedrive.com', 'onedrive.live.com', 'live.com', 'microsoft.com'},
    'wetransfer': {'wetransfer.com', 'we.tl'},
    'yahoo': {'yahoo.com', 'yahoo.co.jp', 'yimg.com'},
    'santander': {'santander.com', 'santander.co.uk', 'santander.com.br'},
    'revolut': {'revolut.com'},
    'samsung': {'samsung.com'},
}
# Brands with a site under many country endings (amazon.de, paypal.fr); for the
# others, the brand's exact name on another ending is a swapped-ending fake (roblox.rw).
MULTI_COUNTRY = {'amazon', 'google', 'apple', 'microsoft', 'paypal', 'netflix', 'dhl', 'ups', 'fedex', 'vodafone',
                 'facebook', 'instagram', 'spotify', 'linkedin', 'yahoo', 'adobe', 'samsung', 'santander', 'twitter'}
RISKY_ENDINGS = {'xyz', 'top', 'buzz', 'club', 'icu', 'shop', 'online', 'site', 'live', 'click', 'link', 'rest', 'fit', 'cfd',
                 'sbs', 'bond', 'lol', 'mom', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support', 'help', 'info', 'vip', 'cyou'}
# Words that name a phishing page on a free host ("xfinityhelplogin.weebly.com").
CREDENTIAL_WORDS = re.compile(r'log-?in|sign-?in|verif|secur|account|update|support|help|wallet|recover|unlock|confirm|billing'
                              r'|payment|refund|odeme|giris|dogrula|hesap|sifre|iade|onay', re.I)
OFFICIAL = {domain for domains in BRANDS.values() for domain in domains}
# Banks, cargo, payments and government: the brands scam messages imitate most. Their name in a
# subdomain of someone else's site (dhl.smarthub.example.ai) counts even when that site is old.
IMPERSONATED = {'garanti', 'garantibbva', 'akbank', 'isbank', 'isbankasi', 'ziraat', 'ziraatbank', 'yapikredi', 'halkbank',
                'vakifbank', 'denizbank', 'qnb', 'finansbank', 'enpara', 'papara', 'ininal', 'edevlet', 'turkiyegov', 'ptt',
                'pttkargo', 'yurtici', 'yurticikargo', 'araskargo', 'mngkargo', 'suratkargo', 'paypal', 'dhl', 'ups', 'fedex',
                'usps', 'royalmail', 'chase', 'wellsfargo', 'bankofamerica', 'santander', 'revolut', 'coinbase', 'binance'}
DISPLAY = {'garanti': 'Garanti BBVA', 'garantibbva': 'Garanti BBVA', 'isbank': 'İş Bankası', 'isbankasi': 'İş Bankası',
           'ziraat': 'Ziraat Bankası', 'ziraatbank': 'Ziraat Bankası', 'yapikredi': 'Yapı Kredi', 'vakifbank': 'VakıfBank',
           'qnb': 'QNB', 'turktelekom': 'Türk Telekom', 'edevlet': 'e-Devlet', 'turkiyegov': 'e-Devlet', 'ptt': 'PTT',
           'pttkargo': 'PTT Kargo', 'yurtici': 'Yurtiçi Kargo', 'yurticikargo': 'Yurtiçi Kargo', 'araskargo': 'Aras Kargo',
           'mngkargo': 'MNG Kargo', 'suratkargo': 'Sürat Kargo', 'turkishairlines': 'Turkish Airlines', 'paypal': 'PayPal',
           'icloud': 'iCloud', 'whatsapp': 'WhatsApp', 'linkedin': 'LinkedIn', 'office365': 'Office 365', 'dhl': 'DHL',
           'ups': 'UPS', 'fedex': 'FedEx', 'steamcommunity': 'Steam', 'hepsiburada': 'Hepsiburada', 'n11': 'n11'}


def display(brand):
    """A brand key or official name as people write it."""
    return DISPLAY.get(brand, brand[:1].upper() + brand[1:]) if isinstance(brand, str) else ''
OFFICIAL_NAMES = {domain.split('.')[0] for domain in OFFICIAL if len(domain.split('.')[0]) >= 5}
# Ordinary words among those names; a near miss of these is not a look-alike.
LOOKALIKE_EXCLUDE = {'turkiye', 'office', 'outlook', 'windows', 'bonus', 'maximum', 'paraf', 'axess', 'azure', 'steam',
                     'blogger', 'worldcard', 'bankkart', 'fastpay', 'media-amazon', 'telegram', 'spotify'}

# Letters from other alphabets that look like Latin ones (the confusables that matter in domains).
CONFUSABLE = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ь': 'b', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't',
    'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'υ': 'u', 'τ': 't', 'ε': 'e', 'χ': 'x',
    'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i', 'ӧ': 'o', 'ё': 'e', 'ӱ': 'u',
}
# Latin letters with marks; normal in Turkish names, so only a match with a brand counts.
ACCENTS = {'ı': 'i', 'ş': 's', 'ç': 'c', 'ğ': 'g', 'ö': 'o', 'ü': 'u', 'â': 'a', 'î': 'i', 'û': 'u'}
DIGIT_SWAPS = (('rn', 'm'), ('vv', 'w'), ('0', 'o'), ('1', 'l'), ('3', 'e'), ('4', 'a'), ('5', 's'), ('7', 't'), ('8', 'b'))


def loose_ipv4(host):
    """The address a browser opens for a host like 3232235777, 0xC0A80101 or 0300.0250.1.1."""
    parts = host.rstrip('.').split('.') if host else []
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        try:
            if re.fullmatch(r'0[xX][0-9a-fA-F]*', part):
                values.append(int(part[2:] or '0', 16))
            elif re.fullmatch(r'0[0-7]+', part):
                values.append(int(part, 8))
            elif re.fullmatch(r'\d+', part):
                values.append(int(part))
            else:
                return None
        except ValueError:
            return None
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(values)):
        return None
    number = 0
    for value in head:
        number = number * 256 + value
    number = number * 256 ** (5 - len(values)) + last
    return ipaddress.IPv4Address(number) if number < 2 ** 32 else None


def unmask(raw):
    """(address a browser would really open, [tricks]) for a pasted link. Never raises."""
    if not isinstance(raw, str):
        return raw, []
    value = raw.strip()
    tricks = []
    try:
        candidate = value if '://' in value else 'https://' + value
        parts = urlsplit(candidate)
        netloc = parts.netloc
        if '@' in netloc:
            shown, netloc = netloc.rsplit('@', 1)
            if shown:
                tricks.append({'code': 'userinfo_trick', 'shown': unquote(shown)[:80]})
        hostport = netloc
        port = ''
        if hostport.startswith('['):
            host = hostport
        else:
            host, _, port = hostport.partition(':')
        if '%' in host:
            decoded = unquote(host)
            if decoded != host:
                tricks.append({'code': 'encoded_host', 'shown': host[:80]})
                host = decoded
        address = loose_ipv4(host)
        if address is not None and host.rstrip('.') != str(address):
            tricks.append({'code': 'encoded_ip', 'shown': host[:80], 'real': str(address)})
            host = str(address)
        if not tricks:
            return value, []
        netloc = host + (':' + port if port else '')
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), tricks
    except ValueError:
        return value, []


def split_host(host):
    """(subdomain labels, registrable domain, on a shared hosting platform)."""
    labels = [label for label in (host or '').lower().rstrip('.').split('.') if label]
    if len(labels) < 2:
        return [], '.'.join(labels), False
    for size in (4, 3, 2):
        suffix = '.'.join(labels[-size:])
        if suffix in SHARED_HOSTING and len(labels) > size:
            return labels[:-size - 1], '.'.join(labels[-size - 1:]), True
    two_part = '.'.join(labels[-2:]) in MULTI_SUFFIXES or (
        len(labels[-1]) == 2 and labels[-2] in COUNTRY_SECOND_LEVELS)   # com.es, co.id, org.pl
    keep = 3 if two_part and len(labels) >= 3 else 2
    return labels[:-keep], '.'.join(labels[-keep:]), False


def other_site(first, second):
    """True when two addresses belong to different registrable domains."""
    try:
        hosts = [(urlsplit(u).hostname or '').lower() for u in (first, second)]
    except (ValueError, TypeError, AttributeError):
        return False
    return all(hosts) and split_host(hosts[0])[1] != split_host(hosts[1])[1]


def unicode_label(label):
    if label.startswith('xn--'):
        try:
            return label.encode('ascii').decode('idna')
        except (UnicodeError, ValueError):
            return label
    return label


def plain(text):
    """Look-alike letters and Turkish marks turned into plain Latin."""
    return ''.join(CONFUSABLE.get(c, ACCENTS.get(c, c)) for c in unicodedata.normalize('NFC', text.lower()))


def skeleton(text):
    """plain() plus digit swaps (paypa1, g00gle) and no hyphens: what the name is made to look like."""
    text = plain(text)
    for old, new in DIGIT_SWAPS:
        text = text.replace(old, new)
    return text.replace('-', '')


def brand_tokens(text):
    tokens = [t for t in re.split(r'[^a-z0-9]+', text) if t]
    joined = ''.join(tokens)
    found = set()
    for brand in BRANDS:
        if brand in tokens or (len(brand) >= 5 and any(t.startswith(brand) for t in tokens)) \
                or (len(brand) >= 6 and (any(t.endswith(brand) for t in tokens) or brand in joined)):
            found.add(brand)
    return found


def owns(brand, registrable):
    """True when the domain belongs to the brand: one it lists, or brand.<country> for a brand with many country sites."""
    if registrable in BRANDS[brand]:
        return True
    name, _, ending = registrable.partition('.')
    return name == brand and brand in MULTI_COUNTRY and ending.rsplit('.', 1)[-1] not in RISKY_ENDINGS


def address_signals(url):
    """Signals read from the address alone: [{'code', 'strong', ...}]."""
    try:
        host = (urlsplit(url).hostname or '').lower().rstrip('.') if isinstance(url, str) else ''
    except ValueError:
        return []
    if not host or ':' in host or loose_ipv4(host) is not None:
        return []
    subdomain, registrable, shared = split_host(host)
    if not registrable or (registrable in OFFICIAL and not shared):
        return []
    signals = []
    labels = [unicode_label(label) for label in host.split('.')]
    for label in labels:
        letters = [c for c in label if c.isalpha()]
        other_script = [c for c in letters if c in CONFUSABLE]
        latin = [c for c in letters if 'a' <= c <= 'z']
        if other_script and (latin or len(other_script) == len(letters)):
            signals.append({'code': 'homograph_name', 'strong': True, 'looks_like': '.'.join(plain(l) for l in labels)[:80]})
            break
    name = unicode_label(registrable.split('.')[0])
    if not signals and not shared and name in BRANDS and not owns(name, registrable):
        # The brand's exact name on an ending it doesn't use (roblox.rw, garanti.xyz).
        signals.append({'code': 'lookalike_name', 'strong': True, 'brand': name, 'tld_swap': True})
    if not signals and not any(owns(b, registrable) for b in BRANDS):
        raw, look = name.replace('-', ''), skeleton(name)
        for official in sorted(OFFICIAL_NAMES - LOOKALIKE_EXCLUDE):
            if look == official and raw != official:
                signals.append({'code': 'lookalike_name', 'strong': True, 'brand': official})
                break
            if len(official) >= 6 and look != official and Levenshtein.distance(look, official) == 1:
                signals.append({'code': 'lookalike_name', 'strong': False, 'brand': official})
                break
    for domain in sorted(OFFICIAL, key=len, reverse=True):
        if len(domain.split('.')[0]) >= 4 and re.search(r'(?:^|\.)' + re.escape(domain) + r'[.-]', host) \
                and not any(owns(b, registrable) for b in BRANDS if domain in BRANDS[b]):
            signals.append({'code': 'brand_in_subdomain', 'strong': True, 'brand': domain, 'real': registrable})
            break
    if not any(s['code'] == 'brand_in_subdomain' for s in signals):
        brands = {b for b in brand_tokens(plain('.'.join(subdomain + [name]))) if not owns(b, registrable)}
        if brands:
            brand = sorted(brands, key=len, reverse=True)[0]
            in_front = brand in brand_tokens(plain('.'.join(subdomain))) if subdomain and not shared else False
            signals.append({'code': 'brand_in_name', 'strong': False, 'brand': brand, 'subdomain': in_front})
    if shared and registrable.split('.', 1)[1] in SERVER_HOSTS:
        signals.append({'code': 'server_hostname', 'strong': False})
    elif shared:
        signals.append({'code': 'free_hosting', 'strong': False})
    if shared:
        if CREDENTIAL_WORDS.search(name):
            signals.append({'code': 'credential_bait', 'strong': False})
    return signals


def program_in_address(url):
    """The file type at the end of the address when it is an app or program (…/SS.ps1, …/guardian.hta)."""
    try:
        path = urlsplit(url).path if isinstance(url, str) else ''
    except ValueError:
        return ''
    name = path.rsplit('/', 1)[-1]
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    return extension if extension in ADDRESS_PROGRAM_EXTENSIONS else ''


def looks_like_short_link(url):
    """A short-link service we don't list: a very short name and one short mixed code (s4w.in/jZlxQ)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
    except ValueError:
        return False
    subdomain, registrable, shared = split_host(host)
    code = parts.path.strip('/')
    return (not shared and not subdomain and registrable not in OFFICIAL and len(registrable.split('.')[0]) <= 4
            and re.fullmatch(r'[A-Za-z0-9_-]{4,12}', code or '') is not None and not parts.query
            and (bool(re.search(r'[A-Z]', code)) and bool(re.search(r'[a-z]', code)) or bool(re.search(r'\d', code)) and bool(re.search(r'[A-Za-z]', code))))
