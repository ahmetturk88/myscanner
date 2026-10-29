"""Format-specific inspection for the file scanner (file-evidence-v5).

Each inspector reads one kind of file that scams use and returns facts plus
findings written for the plain report. Nothing is executed, rendered or
fetched. Findings never confirm malware on their own: the strongest outcome is
"review" (suspicious); only an antivirus or hash match confirms a threat.

Result shape:
    {'format': 'apk' | 'html' | 'svg' | 'email' | 'office' | 'image',
     'status': 'assessed' | 'unavailable', 'facts': {...},
     'findings': [{'level': 'warn' | 'info', 'title': str, 'detail': str}],
     'raises_review': bool, 'row': {'name', 'state', 'result'}}
Titles and details come from fixed templates so they can be translated.
"""
import email
import email.policy
import io
import re
import struct
import zipfile
from urllib.parse import urlparse

MAX_TEXT = 5 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_LIST = 8


def _finding(level, title, detail):
    return {'level': level, 'title': title, 'detail': detail}


def _host(url):
    try:
        host = urlparse(url.strip()).hostname or ''
    except ValueError:
        return ''
    return host.lower().rstrip('.')


def _hosts(urls):
    seen = []
    for url in urls:
        host = _host(url)
        if host and host not in seen:
            seen.append(host)
    return seen


def _linked(hosts):
    return f'1 site is linked: {hosts[0]}.' if len(hosts) == 1 else f'{len(hosts)} sites are linked, for example {hosts[0]}.'


def _unavailable(kind, reason, row_name):
    return {'format': kind, 'status': 'unavailable', 'error': reason, 'facts': {}, 'findings': [],
            'raises_review': False, 'row': {'name': row_name, 'state': 'na', 'result': 'Not checked'}}


# ---------------------------------------------------------------- Android apps

# android:name and android:permission resource ids, for manifests that strip attribute names.
_ATTRIBUTE_IDS = {0x01010003: 'name', 0x01010006: 'permission'}
# Capabilities that banking trojans and SMS stealers combine.
RISKY_PERMISSIONS = {
    'android.permission.RECEIVE_SMS': 'read incoming text messages',
    'android.permission.READ_SMS': 'read your text messages',
    'android.permission.SEND_SMS': 'send text messages',
    'android.permission.BIND_ACCESSIBILITY_SERVICE': 'control the screen through accessibility',
    'android.permission.SYSTEM_ALERT_WINDOW': 'draw over other apps',
    'android.permission.REQUEST_INSTALL_PACKAGES': 'install other apps',
    'android.permission.BIND_DEVICE_ADMIN': 'become a device administrator',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 'read your notifications',
    'android.permission.READ_CALL_LOG': 'read your call history',
    'android.permission.CALL_PHONE': 'make phone calls',
    'android.permission.READ_CONTACTS': 'read your contacts',
}


class _Axml:
    """Minimal reader for Android's binary XML (AndroidManifest.xml)."""

    def __init__(self, data):
        self.data, self.strings, self.resource_ids = data, [], []

    def _u16(self, at):
        return struct.unpack_from('<H', self.data, at)[0]

    def _u32(self, at):
        return struct.unpack_from('<I', self.data, at)[0]

    def _string_pool(self, start):
        count, flags, strings_start = self._u32(start + 8), self._u32(start + 16), self._u32(start + 20)
        utf8 = bool(flags & 0x100)
        for index in range(min(count, 100000)):
            at = start + strings_start + self._u32(start + 28 + index * 4)
            try:
                if utf8:
                    at += 2 if self.data[at] & 0x80 else 1  # length in characters
                    size = self.data[at]
                    if size & 0x80:
                        size, at = ((size & 0x7F) << 8) | self.data[at + 1], at + 2
                    else:
                        at += 1
                    self.strings.append(self.data[at:at + size].decode('utf-8', 'replace'))
                else:
                    size = self._u16(at)
                    if size & 0x8000:
                        size, at = ((size & 0x7FFF) << 16) | self._u16(at + 2), at + 4
                    else:
                        at += 2
                    self.strings.append(self.data[at:at + size * 2].decode('utf-16-le', 'replace'))
            except (IndexError, struct.error):
                self.strings.append('')

    def _string(self, index):
        return self.strings[index] if 0 <= index < len(self.strings) else ''

    def elements(self):
        """Yields (tag, {attribute: value}) for every start element."""
        if len(self.data) < 8 or self._u16(0) != 0x0003:
            raise ValueError('not binary XML')
        at, end = self._u16(2), min(len(self.data), self._u32(4))
        while at + 8 <= end:
            kind, header, size = self._u16(at), self._u16(at + 2), self._u32(at + 4)
            if size < 8 or header < 8:
                break
            if kind == 0x0001 and not self.strings:
                self._string_pool(at)
            elif kind == 0x0180:
                self.resource_ids = [self._u32(at + 8 + 4 * i) for i in range((size - 8) // 4)]
            elif kind == 0x0102:
                tag = self._string(self._u32(at + 20))
                first, step, count = self._u16(at + 24), self._u16(at + 26), self._u16(at + 28)
                attributes = {}
                for i in range(min(count, 200)):
                    base = at + 16 + first + i * max(step, 20)
                    name_index = self._u32(base + 4)
                    name = self._string(name_index)
                    if not name and name_index < len(self.resource_ids):
                        name = _ATTRIBUTE_IDS.get(self.resource_ids[name_index], '')
                    raw = self._u32(base + 8)
                    value = self._string(raw) if raw != 0xFFFFFFFF else self._u32(base + 16)
                    if name:
                        attributes[name] = value
                yield tag, attributes
            at += size


def _apk_signer(archive):
    from cryptography.hazmat.primitives.serialization import pkcs7
    for info in archive.infolist():
        upper = info.filename.upper()
        if upper.startswith('META-INF/') and upper.endswith(('.RSA', '.DSA', '.EC')) and info.file_size < 256 * 1024:
            try:
                certificates = pkcs7.load_der_pkcs7_certificates(archive.read(info))
            except ValueError:
                continue
            if certificates:
                return certificates[0].subject.rfc4514_string()[:200]
    return None


def apk_brand(package, filename):
    """The bank, cargo or government brand an app file is named after (e-Devlet.apk, com.ptt.kargo)."""
    from services.url_tricks import IMPERSONATED, display, plain
    stem = (filename or '').rsplit('.', 1)[0] if '.' in (filename or '') else (filename or '')
    for text in (package or '', stem):
        tokens = [t for t in re.split(r'[^a-z0-9]+', plain(text)) if t]
        # Short names must stand alone (ptt, but not "chaser" for Chase); long ones may run together (edevlet).
        found = [b for b in IMPERSONATED if b in tokens or (len(b) >= 6 and b in ''.join(tokens))]
        if found:
            return display(max(found, key=len))
    return None


def inspect_apk(content, filename=''):
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
        info = archive.getinfo('AndroidManifest.xml')
        if info.file_size > MAX_MANIFEST:
            return _unavailable('apk', 'Manifest too large', 'App permissions')
        manifest = archive.read(info)
    except (KeyError, zipfile.BadZipFile, ValueError, RuntimeError, OSError):
        return _unavailable('apk', 'Manifest unreadable', 'App permissions')
    package, permissions, sms_receiver, seen = None, [], False, 0
    try:
        for tag, attributes in _Axml(manifest).elements():
            seen += 1
            if tag == 'manifest' and isinstance(attributes.get('package'), str):
                package = attributes['package'][:120]
            elif tag in ('uses-permission', 'uses-permission-sdk-23') and isinstance(attributes.get('name'), str):
                permissions.append(attributes['name'])
            elif tag in ('service', 'receiver') and isinstance(attributes.get('permission'), str):
                permissions.append(attributes['permission'])
            elif tag == 'action' and attributes.get('name') == 'android.provider.Telephony.SMS_RECEIVED':
                sms_receiver = True
    except (ValueError, struct.error, IndexError):
        return _unavailable('apk', 'Manifest unreadable', 'App permissions')
    if not seen:
        return _unavailable('apk', 'Manifest unreadable', 'App permissions')
    try:
        signer = _apk_signer(archive)
    except Exception:  # certificate parsing is best effort
        signer = None
    risky = [RISKY_PERMISSIONS[p] for p in dict.fromkeys(permissions) if p in RISKY_PERMISSIONS]
    if sms_receiver and 'read incoming text messages' not in risky:
        risky.append('read incoming text messages')
    findings = [_finding('info', 'It is an Android app',
                         'Install apps only from Google Play. Scam messages often send app files that steal bank codes.')]
    takeover = {'read incoming text messages', 'read your text messages', 'control the screen through accessibility',
                'draw over other apps', 'read your notifications', 'become a device administrator'}
    serious = [r for r in risky if r in takeover]
    if serious:
        detail = (f'It can {serious[0]}. Banking malware uses this to steal one-time codes.' if len(serious) == 1 else
                  f'It can {serious[0]}, and asks for 1 more risky permission. Banking malware uses these to steal one-time codes.' if len(serious) == 2 else
                  f'It can {serious[0]}, and asks for {len(serious) - 1} more risky permissions. Banking malware uses these to steal one-time codes.')
        findings.insert(0, _finding('warn', 'The app asks for risky permissions', detail))
    brand = apk_brand(package, filename)
    if brand:
        # Banks, cargo companies and e-Devlet publish their apps only in the app stores.
        findings.insert(0, _finding('warn', 'The app pretends to be ' + brand,
                                    f'It uses the name {brand}. {brand} publishes its app only on Google Play; an app file with its name is a common scam.'))
    debug = bool(signer and 'Android Debug' in signer)
    if debug:
        findings.append(_finding('warn', 'Signed with a test key', 'It was signed with Android’s debug key, which real published apps don’t use.'))
    return {'format': 'apk', 'status': 'assessed',
            'facts': {'package': package, 'permissions': sorted(set(permissions))[:60], 'risky_capabilities': risky,
                      'signer': signer, 'receives_sms': sms_receiver, 'brand': brand},
            # One takeover permission is enough: many banking trojans ask only for accessibility.
            'findings': findings, 'raises_review': bool(serious or brand or debug),
            'row': {'name': 'App permissions', 'state': 'warn' if serious else 'ok',
                    'result': f'{len(serious)} risky' if serious else 'None risky'}}


# ---------------------------------------------------------------- web pages and SVG

_REDIRECT = re.compile(r'''(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*['"](https?://[^'"]+)|location\.(?:replace|assign)\(\s*['"](https?://[^'"]+)''', re.I)
_OBFUSCATION = re.compile(r'\batob\s*\(|\bunescape\s*\(|String\.fromCharCode|\beval\s*\(', re.I)
_LONG_BASE64 = re.compile(rb'[A-Za-z0-9+/=]{4000,}')


def inspect_html(content, svg=False):
    from bs4 import BeautifulSoup
    kind, row_name = ('svg', 'Image content') if svg else ('html', 'Page content')
    text = content[:MAX_TEXT].decode('utf-8', 'replace')
    try:
        soup = BeautifulSoup(text, 'html.parser')
    except Exception:
        return _unavailable(kind, 'Markup unreadable', row_name)
    passwords = soup.find_all('input', attrs={'type': re.compile('^password$', re.I)})
    actions = [form.get('action') or '' for form in soup.find_all('form')]
    external_actions = _hosts(a for a in actions if a.lower().startswith(('http://', 'https://')))
    scripts = soup.find_all('script')
    script_text = ' '.join(s.get_text() for s in scripts)[:MAX_TEXT]
    handlers = sum(1 for tag in soup.find_all(True) for name in tag.attrs if name.lower().startswith('on'))
    redirects = [m.group(1) or m.group(2) for m in _REDIRECT.finditer(script_text)]
    for meta in soup.find_all('meta', attrs={'http-equiv': re.compile('^refresh$', re.I)}):
        found = re.search(r'url\s*=\s*([^;]+)', meta.get('content') or '', re.I)
        if found:
            redirects.append(found.group(1).strip(' \'"'))
    redirect_hosts = _hosts(redirects)
    hrefs = [a.get('href') or '' for a in soup.find_all('a')]
    links = _hosts(hrefs)
    obfuscated = bool(_OBFUSCATION.search(script_text)) or bool(_LONG_BASE64.search(content[:MAX_TEXT]))
    foreign = bool(soup.find_all(re.compile('^foreignobject$', re.I))) if svg else False
    findings, review = [], False
    if passwords:
        review = True
        findings.append(_finding('warn', 'It asks for a password',
                                 f'This file shows a login form that sends what you type to {external_actions[0]}. Real companies don’t send login pages as files.'
                                 if external_actions else
                                 'This file shows a login form. Real companies don’t send login pages as files; this is a common phishing trick.'))
    if svg and (scripts or handlers or foreign):
        review = True
        findings.append(_finding('warn', 'The image contains code',
                                 'Normal pictures don’t run code. Scammers hide web pages and scripts inside SVG images.'))
    elif scripts and obfuscated:
        review = True
        findings.append(_finding('warn', 'It hides its code', 'The page scrambles its scripts, a trick used to get past security filters.'))
    if redirect_hosts:
        review = True
        findings.append(_finding('warn', 'It sends you to another site', f'Opening it jumps straight to {redirect_hosts[0]}.'))
    if links and not findings:
        findings.append(_finding('info', 'It contains links', _linked(links)))
    state = 'warn' if review else 'ok'
    result = ('Asks for a password' if passwords else 'Contains code' if svg and (scripts or handlers or foreign)
              else 'Redirects' if redirect_hosts else 'Hidden code' if review else 'Nothing risky')
    return {'format': kind, 'status': 'assessed',
            'facts': {'password_fields': len(passwords), 'forms': len(actions), 'form_targets': external_actions[:MAX_LIST],
                      'scripts': len(scripts), 'event_handlers': handlers, 'redirects_to': redirect_hosts[:MAX_LIST],
                      'linked_sites': links[:MAX_LIST], 'obfuscation': obfuscated},
            'urls': (redirects + [a for a in actions if a.lower().startswith(('http://', 'https://'))] + hrefs)[:200],
            'findings': findings, 'raises_review': review, 'row': {'name': row_name, 'state': state, 'result': result}}


# ---------------------------------------------------------------- saved emails

RISKY_ATTACHMENTS = {'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'ps1', 'msi',
                     'jar', 'lnk', 'iso', 'img', 'vhd', 'vhdx', 'html', 'htm', 'shtml', 'svg', 'one', 'apk', 'docm',
                     'xlsm', 'pptm', 'cpl', 'reg'}
_URL = re.compile(r'https?://[^\s<>"\')]+', re.I)


def _domain(address):
    address = str(address or '')
    match = re.search(r'@([A-Za-z0-9.-]+)', address)
    return match.group(1).lower().rstrip('.') if match else ''


def inspect_email(content):
    try:
        message = email.message_from_bytes(content[:MAX_TEXT], policy=email.policy.default)
    except Exception:
        return _unavailable('email', 'Email unreadable', 'Attachments')
    sender = _domain(message.get('From'))
    reply_to = _domain(message.get('Reply-To'))
    results = ' '.join(str(v) for v in message.get_all('Authentication-Results') or []).lower()
    failed = [name for name in ('spf', 'dkim', 'dmarc') if re.search(name + r'\s*=\s*(fail|softfail)', results)]
    attachments, bodies = [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name:
            attachments.append(str(name)[:120])
        elif part.get_content_type() in ('text/plain', 'text/html'):
            try:
                bodies.append(part.get_content()[:MAX_TEXT])
            except (LookupError, ValueError):
                continue
    body_urls = _URL.findall(' '.join(bodies))
    sites = _hosts(body_urls)
    from services.file_deep_analyzer import disguised_filename
    risky = [n for n in attachments if n.rsplit('.', 1)[-1].lower() in RISKY_ATTACHMENTS or disguised_filename(n)]
    findings, review = [], False
    if risky:
        review = True
        findings.append(_finding('warn', 'It has a risky attachment',
                                 f'“{risky[0]}” is a type of file scammers use to install malware or show fake login pages.'))
    if failed:
        review = True
        findings.append(_finding('warn', 'The sender couldn’t be verified',
                                 f'The email failed its {", ".join(f.upper() for f in failed)} check, so it may not come from who it claims.'))
    if sender and reply_to and reply_to != sender and not reply_to.endswith('.' + sender) and not sender.endswith('.' + reply_to):
        findings.append(_finding('info', 'Replies go somewhere else', f'It comes from {sender}, but replies go to {reply_to}.'))
    if sites:
        findings.append(_finding('info', 'It contains links', _linked(sites) + ' Check links with the URL scanner before opening them.'))
    return {'format': 'email', 'status': 'assessed',
            'facts': {'from_domain': sender, 'reply_to_domain': reply_to, 'subject': str(message.get('Subject') or '')[:200],
                      'failed_checks': failed, 'attachments': attachments[:MAX_LIST * 2], 'linked_sites': sites[:MAX_LIST]},
            'urls': body_urls[:200],
            'findings': findings, 'raises_review': review,
            'row': {'name': 'Attachments', 'state': 'warn' if risky else 'ok',
                    'result': 'Risky attachment' if risky else f'{len(attachments)} safe-looking' if attachments else 'None'}}


# ---------------------------------------------------------------- Office macros

# olevba lists every event handler as AutoExec; only these run without a click.
_ON_OPEN = re.compile(r'auto_?open|autoexec|auto_?close|(document|workbook)_(open|close|beforeclose|activate)|_layout$|_painted$|_resize$|_gotfocus$', re.I)
_ACTIONS = re.compile(r'shell|createobject|urldownloadtofile|powershell|wscript|run|exec|kill|open|write|xmlhttp|adodb', re.I)


def _has_macro_sheets(content):
    if not content.startswith(b'PK'):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return any(name.lower().startswith('xl/macrosheets/') for name in archive.namelist())
    except (zipfile.BadZipFile, ValueError, OSError):
        return False


def inspect_office_macros(content, filename):
    try:
        from oletools.olevba import VBA_Parser
        parser = VBA_Parser(filename or 'document', data=content)
    except Exception:
        return _unavailable('office', 'Office macro parser unavailable', 'Macro behaviour')
    try:
        if parser.detect_is_encrypted():
            return {'format': 'office', 'status': 'assessed', 'facts': {'has_macros': None, 'encrypted': True},
                    'findings': [_finding('warn', 'The document is password-locked',
                                          'We couldn’t look inside. Scammers lock documents so security tools can’t check them, then send the password in the message.')],
                    'raises_review': True, 'row': {'name': 'Macro behaviour', 'state': 'na', 'result': 'Locked'}}
        # olevba reads Excel 4.0 macros from .xls only; newer workbooks keep them in xl/macrosheets/.
        macro_sheets = _has_macro_sheets(content)
        if not macro_sheets and not parser.detect_macros():
            return {'format': 'office', 'status': 'assessed', 'facts': {'has_macros': False}, 'findings': [],
                    'raises_review': False, 'row': {'name': 'Macro behaviour', 'state': 'ok', 'result': 'No macros'}}
        xlm = macro_sheets or bool(parser.detect_xlm_macros())
        analysis = parser.analyze_macros() or []
    except Exception:
        return _unavailable('office', 'Office macro parser failed', 'Macro behaviour')
    finally:
        try:
            parser.close()
        except Exception:
            pass
    auto = sorted({keyword for kind, keyword, _ in analysis if kind == 'AutoExec' and _ON_OPEN.search(keyword)})[:MAX_LIST]
    suspicious = sorted({keyword for kind, keyword, _ in analysis if kind == 'Suspicious' and _ACTIONS.search(keyword)})[:MAX_LIST]
    findings = []
    if xlm:
        findings.append(_finding('warn', 'It has old Excel 4.0 macros',
                                 'This hidden macro type is rarely used today except by malware, because many security tools miss it.'))
    if auto and suspicious:
        findings.append(_finding('warn', 'The macros run by themselves',
                                 'They start as soon as the document opens and can run programs or download files ('
                                 + ', '.join(suspicious[:3]) + ').'))
    elif auto:
        findings.append(_finding('warn', 'The macros run by themselves', 'They start as soon as the document opens, before you click anything.'))
    elif suspicious:
        findings.append(_finding('warn', 'The macros can run programs',
                                 'They contain commands that run programs or download files (' + ', '.join(suspicious[:3]) + ').'))
    return {'format': 'office', 'status': 'assessed',
            'facts': {'has_macros': True, 'excel4_macros': xlm, 'auto_run': auto, 'suspicious_keywords': suspicious},
            'findings': findings, 'raises_review': True,
            'row': {'name': 'Macro behaviour', 'state': 'warn',
                    'result': 'Runs on open' if auto else 'Can run programs' if suspicious else 'Excel 4.0 macros' if xlm else 'Has macros'}}


# ---------------------------------------------------------------- images with QR codes

def inspect_image(content):
    try:
        from PIL import Image
        import zxingcpp
        Image.MAX_IMAGE_PIXELS = 40_000_000
        with Image.open(io.BytesIO(content)) as image:
            image.load()
            codes = zxingcpp.read_barcodes(image.convert('RGB'))
    except Exception:
        return _unavailable('image', 'Image could not be decoded', 'QR code')
    texts = [code.text[:500] for code in codes if code.text][:MAX_LIST]
    links = [t for t in texts if t.lower().startswith(('http://', 'https://', 'www.'))]
    findings = []
    if links:
        findings.append(_finding('info', 'It contains a QR code with a link',
                                 f'The code leads to {_host(links[0] if "://" in links[0] else "http://" + links[0]) or links[0][:80]}. '
                                 'Check that link with the URL scanner before you open it.'))
    elif texts:
        findings.append(_finding('info', 'It contains a QR code', 'The code holds text, not a website link.'))
    return {'format': 'image', 'status': 'assessed', 'facts': {'qr_texts': texts, 'qr_links': links}, 'urls': links,
            'findings': findings, 'raises_review': False,
            'row': {'name': 'QR code', 'state': 'info' if texts else 'ok',
                    'result': 'Contains a link' if links else 'Contains text' if texts else 'None'}}


# ---------------------------------------------------------------- dispatch

_HTML_NAMES = ('html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml')


def inspect(content, filename, file_type):
    """The matching inspector's result, or None when no inspector applies."""
    result = _inspect(content, filename, file_type)
    if result and any(f.get('level') == 'warn' for f in result.get('findings', [])):
        result['raises_review'] = True  # a warning never sits under a "no warning signs" verdict
    return result


def _inspect(content, filename, file_type):
    name = (filename or '').lower()
    extension = name.rsplit('.', 1)[-1] if '.' in name else ''
    actual = file_type.get('actual_type')
    head = content[:2048].lstrip().lower()
    if actual == 'zip' and extension in ('apk', 'xapk', 'apks', 'zip', ''):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                is_apk = 'AndroidManifest.xml' in archive.namelist()
        except (zipfile.BadZipFile, ValueError, OSError):
            is_apk = False
        return inspect_apk(content, filename) if is_apk else None
    if file_type.get('is_office'):
        return inspect_office_macros(content, filename)
    if file_type.get('is_image'):
        return inspect_image(content)
    textual = actual == 'txt' or (actual == 'unknown' and b'\x00' not in content[:4096])
    if textual:
        if extension == 'svg' or head.startswith(b'<svg') or (head.startswith(b'<?xml') and b'<svg' in head):
            return inspect_html(content, svg=True)
        if extension in _HTML_NAMES or head.startswith((b'<!doctype html', b'<html')):
            return inspect_html(content)
        if extension == 'eml' or re.match(rb'^(?:(?:received|return-path|from|to|subject|date|message-id|mime-version|delivered-to):)', head):
            return inspect_email(content)
    return None
