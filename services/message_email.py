"""Read an original email (.eml, from Gmail's "Download message" and the like) for the message check.

A screenshot can't show where an email's buttons lead; the original file can. It is parsed as data only:
nothing in it is rendered, run or opened, attachments are counted but never read, and the file is not kept.
What comes out is plain text for the message check: the sender's name and domain, the subject, the real
addresses behind the buttons and the body, plus the sender checks the receiving server recorded (SPF, DKIM,
DMARC) when the file has them.
"""
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

MAX_BYTES = 8 * 1024 * 1024
MAX_PARTS = 60
MAX_HTML = 2 * 1024 * 1024
MAX_LINKS = 20


class EmailError(Exception):
    """bad_email or too_large."""


def is_email(filename, mimetype):
    return (filename or '').lower().endswith('.eml') or (mimetype or '').lower() == 'message/rfc822'


def _auth(message):
    """SPF, DKIM and DMARC results from the receiving server's Authentication-Results header (the top one)."""
    header = str(message.get('Authentication-Results') or '')
    found = {}
    for check in ('spf', 'dkim', 'dmarc'):
        match = re.search(rf'\b{check}=(\w+)', header, re.I)
        if match:
            found[check] = match.group(1).lower()
    return found


# Footer links every mailing has; the button the reader is meant to press comes first.
_FOOTER = re.compile(r'unsubscribe|abonelik|aboneliği|privacy|gizlilik|terms|koşullar|view (?:it )?in (?:your )?browser|'
                     r'tarayıcıda görüntüle|manage (?:alerts|preferences|notifications)|tercih|إلغاء الاشتراك', re.I)


def _html_text_and_links(html):
    """(the page's text, its http(s) links with the main buttons first and footer links last)."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html[:MAX_HTML], 'html.parser')
    ranked = []
    for order, tag in enumerate(soup.find_all(['a', 'area'], href=True)):
        href = str(tag['href']).strip()
        if not re.match(r'^https?://', href, re.I):
            continue
        label = ' '.join(tag.get_text(' ').split())[:80]
        footer = bool(_FOOTER.search(label) or _FOOTER.search(href))
        ranked.append((footer, order, href[:500]))
    links = []
    for _, _, href in sorted(ranked):
        if href not in links:
            links.append(href)
    for tag in soup(['script', 'style', 'head', 'title']):
        tag.decompose()
    return soup.get_text('\n'), links


def read_email(data):
    """(text for the message check, {'sender_domain', 'auth', 'attachments'})."""
    if len(data) > MAX_BYTES:
        raise EmailError('too_large')
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        raise EmailError('bad_email') from None
    if not message.get('From') and not message.get('Subject'):
        raise EmailError('bad_email')
    name, address = parseaddr(str(message.get('From') or ''))
    domain = address.rpartition('@')[2].lower()[:120]
    subject = re.sub(r'\s+', ' ', str(message.get('Subject') or '')).strip()[:300]
    plain, html, attachments, parts = [], [], 0, 0
    for part in message.walk():
        parts += 1
        if parts > MAX_PARTS:
            break
        if part.is_multipart():
            continue
        if part.get_content_disposition() == 'attachment':
            attachments += 1  # counted, never opened
            continue
        kind = part.get_content_type()
        if kind not in ('text/plain', 'text/html'):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        (plain if kind == 'text/plain' else html).append(str(content))
    body, links = '\n'.join(plain), []
    for page in html:
        text, found = _html_text_and_links(page)
        links += [l for l in found if l not in links]
        if not body.strip():
            body += '\n' + text
    body = '\n'.join(' '.join(line.split()) for line in body.splitlines())
    body = re.sub(r'\n{2,}', '\n', body).strip()
    head = [f'Email from: {name.strip()[:80] or "(no name)"} (sender domain: {domain or "unknown"})', f'Subject: {subject}']
    if links:
        head.append('Links behind its buttons and text:\n' + '\n'.join(links[:MAX_LINKS]))
    if attachments:
        head.append(f'Attachments: {attachments} (not opened)')
    text = '\n'.join(head) + '\n\n' + body
    shown = '\n'.join(head[:2]) + '\n\n' + body  # what the reader sees: no list of long addresses
    return text[:6000], {'sender_domain': domain, 'sender_name': name.strip()[:80], 'auth': _auth(message),
                         'attachments': attachments, 'shown': shown[:6000]}
