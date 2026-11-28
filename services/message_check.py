"""Message check: is this SMS / WhatsApp / email text a scam?

A pasted message goes through four steps, and every step works without the next:
1. Personal data is masked first (phone numbers, IBANs, card numbers, emails, Turkish ID
   numbers, one-time codes). Only the masked text is ever stored or sent to an AI provider.
2. Local reading: the links in it (also "site.com/path" without http, the form scam texts
   use) and the tricks scam messages are known for in Turkey (parcel fees, a blocked bank
   account, e-Devlet refunds, prizes, a code or password request, pressure to act now…).
3. Up to 3 links are checked against threat lists (Google Web Risk, URLhaus, the local
   phishing list) and URL tricks (shorteners, look-alike brand names). Nothing is opened
   or visited: the message's links are never fetched.
4. An AI provider, only when MESSAGE_CHECK_AI=1 (off by default), reads the masked text with
   those findings. It can make the verdict stricter, never milder, and by one step only
   unless the rules found real evidence; the advice shown is always our own fixed text.

The result is a "plain" summary in the same shape as every other tool's report.
"""
import json
import re
from urllib.parse import urlparse

from services.simple_report_view import check, ordered, reason, tally

MAX_TEXT = 4000
MAX_LINKS = 3

# ------------------------------------------------------------------ 1. personal data

_MASKS = (
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b'), '[IBAN]'),
    ('card', re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[card number]'),
    ('email', re.compile(r'\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b'), '[email]'),
    ('phone', re.compile(r'(?<![\w/.])(?:\+|00)?(?:90[ ]?)?\(?0?5\d{2}\)?[ .-]?\d{3}[ .-]?\d{2}[ .-]?\d{2}\b'
                         r'|(?<![\w/.])(?:\+|00)\d{1,3}[ .-]?\d{2,4}[ .-]?\d{3,4}[ .-]?\d{2,4}\b'
                         r'|(?<![\w/.])0?8[58]0[ ]?\d{3}[ ]?\d{2}[ ]?\d{2}\b'), '[phone]'),
    ('national_id', re.compile(r'\b[1-9]\d{10}\b'), '[ID number]'),
    # One-time codes: 4-8 digits next to "kod / şifre / code / رمز", on either side.
    ('code', re.compile(r'((?:kod|şifre|sifre|parola|code|otp|pin|رمز|الرمز|كود|الكود)\w*[^\d\n]{0,30}?)\b\d{4,8}\b'
                        r'|\b\d{4,8}\b(?=[^\d\n]{0,25}?(?:kod|code|otp|şifre|sifre|parola|رمز|كود))', re.I), None),
)


def redact(text):
    """(masked text, {kind: count}). Order matters: an IBAN is masked before its digits look like a card."""
    counts = {}
    for kind, pattern, label in _MASKS:
        if label is None:  # keep the words between the code word and the digits
            text, n = pattern.subn(lambda m: (m.group(1) or '') + '[code]', text)
        else:
            text, n = pattern.subn(label, text)
        if n:
            counts[kind] = n
    return text, counts


# ------------------------------------------------------------------ 2. links and signals

_LINK = re.compile(r'\b(?:https?://[^\s<>"\']+|www\.[^\s<>"\']+|(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>"\']*)', re.I)
SHORTENERS = {'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 't.co', 'cutt.ly', 'shorturl.at', 'rb.gy',
              'tiny.cc', 'rebrand.ly', 'shorte.st', 'bc.vc', 'v.gd', 's.id', 't.ly', 'u.to', 'kısa.link', 'kisa.link'}


# Real addresses of the names scam texts borrow most. A link exactly on one of these (or a sub-address of it)
# is the real company, so the message's mention of a parcel or a bank is not held against it.
OFFICIAL = {'turkiye.gov.tr', 'ptt.gov.tr', 'gib.gov.tr', 'sgk.gov.tr', 'egm.gov.tr', 'kgm.gov.tr', 'ptt.com.tr',
            'yurticikargo.com', 'araskargo.com.tr', 'mngkargo.com.tr', 'suratkargo.com.tr', 'trendyol.com', 'hepsiburada.com',
            'n11.com', 'amazon.com.tr', 'ziraatbank.com.tr', 'garantibbva.com.tr', 'akbank.com', 'yapikredi.com.tr',
            'isbank.com.tr', 'halkbank.com.tr', 'vakifbank.com.tr', 'qnb.com.tr', 'enpara.com', 'papara.com', 'denizbank.com',
            'teb.com.tr', 'kuveytturk.com.tr', 'turkcell.com.tr', 'vodafone.com.tr', 'turktelekom.com.tr'}


def is_official(host):
    host = (host or '').lower().rstrip('.')
    return host.endswith('.gov.tr') or any(host == d or host.endswith('.' + d) for d in OFFICIAL)


def find_links(text, limit=10):
    """Links in the order they appear, without repeats; email addresses are not links."""
    found = []
    for match in _LINK.finditer(text):
        link = re.sub(r'[).,;:!?\'"]+$', '', match.group(0))
        if len(link) > 3 and link.lower() not in (f.lower() for f in found):
            found.append(link)
        if len(found) >= limit:
            break
    return found


def as_url(link):
    return link if re.match(r'^https?://', link, re.I) else 'http://' + link


def defang(link):
    """hxxps://site[.]com/…: shown as text, never as something to click."""
    host = urlparse(as_url(link)).hostname or link
    return link.replace(host, host.replace('.', '[.]'), 1).replace('http', 'hxxp', 1) if host else link


# (key, weight, patterns in Turkish / English / Arabic). Weight 2 = a strong scam sign on its own.
SIGNALS = (
    # Someone asking for the code that just came to your phone: how WhatsApp and bank accounts are stolen.
    ('code_ask', 4, r'(?:yanlışlıkla|yanlislikla).{0,40}(?:kod|şifre)|gelen.{0,40}(?:kod|şifre)\w*\s+(?:bana|bize)|'
                    r'(?:kod|kodu|şifreyi|sifreyi)\w*\s+(?:bana|bize|buraya)\s*(?:gönder|ilet|at|yaz|söyle|paylaş)|'
                    r'(?:kod|kodu)\w*\s+(?:gönderir|iletir|atar|yazar|söyler)\s*mi|'
                    r'send (?:me|us) (?:the|that|your) (?:\d-digit )?code|code (?:i|we) sent (?:you )?by mistake|'
                    r'(?:share|forward|tell me) (?:the|that|your) code|'
                    r'(?:أرسل|ارسل|ابعت|ابعتلي|أعطني)\w*\s+(?:لي\s+)?(?:الرمز|الكود|رمز|كود)|(?:الرمز|الكود) (?:اللي|الذي) وصل'),
    ('secret', 2, r'şifre|parola|doğrulama kodu|onay kodu|tek kullanımlık|sms kodu|kart bilgi|cvv|\bpin\b|password|'
                  r'verification code|one[- ]time code|card details|كلمة (?:السر|المرور)|رمز التحقق|الرمز'),
    ('payment', 2, r'\biban\b|\[IBAN\]|ödeme yap|ödeyin|ödeyiniz|ücret(?:i)? öde|gümrük (?:vergisi|ücreti)|ek ücret|hizmet bedeli|'
                   r'pay (?:a|the) fee|customs fee|transfer (?:the )?money|ادفع|رسوم|تحويل'),
    ('account', 2, r'hesab(?:ınız|iniz)?\s+(?:askıya|bloke|kapatıl|dondurul|kısıtlan)|kartınız\s+(?:bloke|iptal)|'
                   r'account (?:has been )?(?:suspended|locked|blocked)|unusual activity|şüpheli işlem|suspicious transaction|تم (?:إيقاف|تعليق) حسابك'),
    ('prize', 2, r'kazandınız|ödül|hediye çeki|çekiliş|ücretsiz (?:iphone|telefon)|you(?:\'ve| have)? won|prize|'
                 r'gift card|ربحت|جائزة|فزت'),
    ('parcel', 1, r'kargo(?:nuz)?|paket(?:iniz)?|teslimat|adres(?:iniz)? (?:eksik|hatalı)|gönderi(?:niz)?|\bptt\b|\baras kargo|yurtiçi|'
                  r'\bmng\b|parcel|delivery|package|shipment|شحنة|طرد'),
    ('debt', 1, r'\bhgs\b|\bogs\b|geçiş ihlali|gecis ihlali|köprü (?:ve )?otoyol|borcunuz|ödenmemiş (?:borç|fatura|ceza)|'
                r'trafik cezası|trafik cezasi|\bicra\b|haciz|unpaid (?:toll|fine|bill)|traffic fine|toll (?:fee|violation)|'
                r'مخالفة مرور|غرامة|دين مستحق'),
    ('refund', 1, r'iade|e-?devlet|vergi iadesi|sgk|tazminat|refund|tax return|استرداد'),
    ('urgent', 1, r'son gün|hemen|acil|24 saat|bugün içinde|aksi halde|kapatılacak|iptal edilecek|urgent|immediately|'
                  r'within 24 hours|last chance|عاجل|فوراً|خلال 24'),
    ('call', 1, r'\b(?:arayın|arayınız|arayiniz|arayin)\b|call (?:us|this number|the number|now|back)|اتصل (?:بنا|على|بالرقم)'),
    ('click', 1, r'tıkla(?:yın|yınız)?|linke gir|bağlantıya|click (?:here|the link)|اضغط|انقر'),
    # Strangers' romance and "someone near you" lures, fake voice notes and location shares (sextortion, dating scams).
    ('romance', 1, r'thinking about you|near each other|near you|see who i am|photos? on my profile|lonely|'
                   r'seni düşünüyorum|yakınında(?:yım)?|profilimde(?:ki)? fotoğraf|kim olduğumu|أفكر فيك|قريب(?:ة)? منك|صوري'),
    ('voice', 1, r'voice (?:message|note|mail)|voicemail|sesli mesaj|ses kaydı|رسالة صوتية|بريد صوتي'),
    ('location', 1, r'shared (?:their|his|her) (?:live )?location|live location|konum(?:unu)? paylaştı|canlı konum|شارك موقع'),
    # A button whose address the screenshot can't show.
    ('hidden_cta', 1, r'listen to the (?:full )?message|open in maps|tap to see|view (?:the )?message|see (?:the )?photos|'
                      r'get the offer|claim (?:now|your)|mesajı dinle|haritada aç|teklifi al|احصل على العرض|استمع إلى الرسالة'),
    # Mail apps show these only on messages they already filed as spam.
    ('spam_mark', 1, r'spam ?de[ğg]il|not ?spam|report not spam|\bin:? ?spam\b|this message (?:was|has been) (?:marked as|identified as) spam|'
                     r'istenmeyen e-posta|ليست رسالة غير مرغوب'),
    ('bank', 1, r'\bbanka\b|ziraat|garanti|akbank|yapı kredi|iş ?bankası|halkbank|vakıfbank|qnb|enpara|papara|bank'),
)
_SIGNAL_RE = [(key, weight, re.compile(pattern, re.I)) for key, weight, pattern in SIGNALS]

SIGNAL_TEXT = {
    'code_ask': ('Asks for the code sent to your phone', 'Anyone asking for a code that came to you is trying to take over your WhatsApp, bank or e-Devlet account.'),
    'debt': ('Talks about a debt or a fine', 'Fake HGS, traffic fine and “you have a debt” messages push you to pay through a link. Check on e-Devlet instead.'),
    'secret': ('Asks for a password or code', 'Real banks and companies never ask for a password, card number or SMS code in a message.'),
    'payment': ('Asks you to pay', 'A small “fee” or a money transfer is how most of these messages turn into theft.'),
    'account': ('Says your account is blocked', 'Fake “your account is suspended” warnings push you to act before you think.'),
    'prize': ('Promises a prize', 'You can’t win a draw you never entered.'),
    'parcel': ('Talks about a parcel', 'Fake delivery notices are the most common scam text in Türkiye.'),
    'refund': ('Promises a refund', 'Fake e-Devlet, tax and insurance refunds are a common lure.'),
    'urgent': ('Puts you under time pressure', '“Today only” and “or your account will be closed” are pressure tactics.'),
    'call': ('Asks you to call a number', 'Scammers often skip links and ask you to call, then talk you into a code or a transfer.'),
    'click': ('Pushes you to tap a link', 'The message is built around getting you to open the link.'),
    'romance': ('A stranger’s friendly or romantic lure', 'Messages from strangers who want to meet or show you photos are a common way into blackmail and dating scams.'),
    'voice': ('Pretends to bring a voice message', 'Real chat apps don’t send voice messages by email or SMS; the button leads somewhere else.'),
    'location': ('Pretends someone shared a location', 'Fake “someone near you” alerts are used to get you to tap a link.'),
    'hidden_cta': ('A button hides where it goes', 'The button’s address isn’t visible in a screenshot, so it couldn’t be checked.'),
    'spam_mark': ('Your mail app filed it as spam', 'Your email provider already put this message in the spam folder.'),
    'bank': ('Mentions a bank', 'Scam texts often borrow a bank’s name; your bank’s app shows its real messages.'),
}


WEIGHT = {key: weight for key, weight, _ in SIGNALS} | {'auth_fail': 2}  # auth_fail: from an original email's headers
SIGNAL_TEXT['auth_fail'] = ('The sender’s address failed its checks',
                            'The receiving mail server could not confirm that this email really came from the address it shows.')

# The app around a message in a screenshot: mail and chat buttons, menus and banners. Dropped from what is shown
# and sent for review (the signs are read before, so a spam folder still counts).
_CHROME = re.compile(r'kal[ıi]c[ıi] ?olarak ?sil|spam ?de[ğg]il|yan[ıi]tla|y[öo]nlendir|ileti ?dizisinden|iletinin .* anlaşılıyor|diline ?çevir|'
                     r'not ?spam|report spam|translate to|show original|\bin:? ?spam\b|\breply\b|\bforward\b|\barchive\b|'
                     r'arşivle|غير مرغوب|ترجم', re.I)


def tidy(text):
    """The message without the app around it: short lines of app buttons and lines of stray symbols are dropped."""
    kept = []
    for line in text.splitlines():
        letters = sum(c.isalpha() for c in line)
        if letters < 3 or letters < 0.55 * sum(not c.isspace() for c in line):
            continue  # stray icons read as symbols and single letters
        if len(line) <= 90 and _CHROME.search(line):
            continue
        kept.append(line)
    return '\n'.join(kept) or text

# "Kodunuz 482913, kimseyle paylaşmayın": the real code messages say never to share it.
_DONT_SHARE = re.compile(r'kimseyle paylaşma|paylaşmayın|paylasmayin|paylaşmayınız|kimseye (?:vermeyin|söylemeyin)|'
                         r'(?:do not|don\'t|never) share|لا تشارك|لا تعطي', re.I)


def find_signals(text):
    found = [key for key, _, pattern in _SIGNAL_RE if pattern.search(text)]
    if 'secret' in found and 'code_ask' not in found and _DONT_SHARE.search(text):
        found = [k for k in found if k != 'secret'] + ['code_notice']  # a real code message, not a request
    return found


def is_code_notice(signals):
    return 'code_notice' in signals


# ------------------------------------------------------------------ 3. links against threat lists

def check_link(link, analyzer):
    """{'link', 'shown', 'state': bad|warn|ok|na, 'notes': [...]}: lists and URL tricks only; the link is never visited."""
    url = as_url(link)
    host = (urlparse(url).hostname or '').lower()
    notes, state = [], 'ok'
    if host in SHORTENERS:
        notes.append('short link: the real address is hidden')
        state = 'warn'
    try:
        tricks = analyzer.check_phishing_indicators(url)
        if tricks.get('issues'):
            notes += [str(i) for i in tricks['issues'][:2]]
            state = 'warn'
    except Exception:
        pass
    answered = False
    try:
        osint = analyzer.check_osint_sources(url)
        web_risk = osint.get('web_risk') or {}
        if osint.get('urlhaus') or web_risk.get('status') == 'matched' or osint.get('osint_risk_score', 0) >= 30:
            notes.insert(0, 'listed as dangerous by a threat list')
            state = 'bad'
        answered = web_risk.get('status') in ('matched', 'not_found') or osint.get('urlhaus_status') in ('matched', 'not_found')
    except Exception:
        pass
    if state == 'ok' and is_official(host):
        state = 'official'  # the real company's own address (a listed one is still 'bad' above)
    elif state == 'ok' and not answered:
        state = 'na'
    return {'link': link, 'shown': defang(link), 'host': host, 'state': state, 'notes': notes[:3]}


# ------------------------------------------------------------------ 4. the reviewer (services.message_ai)

FROM_AI = {'scam': 'danger', 'suspicious': 'caution', 'safe': 'safe', 'unsure': 'unknown'}


def ai_switched_on():
    from services.message_ai import ai_on
    return ai_on()


# ------------------------------------------------------------------ the verdict

# ------------------------------------------------------------------ what to check, and where

# Where to check the claim yourself: our own list, never an address from the message.
# (key, what the message is about, official address or None, how to check it there)
_EDEVLET = 'https://www.turkiye.gov.tr'
_PARCEL_HOW = 'Track it with the number from your order, on the company’s own site or app.'
_BANK_HOW = 'Open your bank’s own app, or call the number on the back of your card.'
VERIFY = (
    ('hgs', r'\bhgs\b|\bogs\b|geçiş ihlali|gecis ihlali|köprü (?:ve )?otoyol|ihlalli geçiş', 'HGS / OGS toll', _EDEVLET,
     'Log in to e-Devlet yourself and search for “İhlalli Geçiş” to see any real toll debt.'),
    ('fine', r'trafik cezas|traffic fine|مخالفة مرور', 'Traffic fine', _EDEVLET,
     'Log in to e-Devlet yourself and search for “Trafik Cezası” to see any real fine.'),
    ('court', r'\bicra\b|haciz|\buyap\b|mahkeme|savcılık|dava dosya', 'Court or enforcement case', _EDEVLET,
     'Log in to e-Devlet yourself and search for “UYAP” to see any real case. Courts don’t collect money by SMS.'),
    ('state', r'e-?devlet|vergi iade|\bsgk\b|\bgib\b|tazminat|tax refund', 'e-Devlet, tax or SGK', _EDEVLET,
     'Real notices and refunds appear inside e-Devlet. Type turkiye.gov.tr yourself and log in there.'),
    ('ptt', r'\bptt\b', 'PTT', 'https://gonderitakip.ptt.gov.tr', _PARCEL_HOW),
    ('yurtici', r'yurt ?içi kargo|yurtici kargo', 'Yurtiçi Kargo', 'https://www.yurticikargo.com', _PARCEL_HOW),
    ('aras', r'aras kargo', 'Aras Kargo', 'https://www.araskargo.com.tr', _PARCEL_HOW),
    ('mng', r'\bmng\b', 'MNG Kargo', 'https://www.mngkargo.com.tr', _PARCEL_HOW),
    ('surat', r'sürat kargo|surat kargo', 'Sürat Kargo', 'https://www.suratkargo.com.tr', _PARCEL_HOW),
    ('trendyol', r'trendyol', 'Trendyol', 'https://www.trendyol.com', 'Check the order in the Trendyol app or site, opened yourself.'),
    ('hepsiburada', r'hepsiburada', 'Hepsiburada', 'https://www.hepsiburada.com', 'Check the order in the Hepsiburada app or site, opened yourself.'),
    ('ziraat', r'ziraat', 'Ziraat Bankası', 'https://www.ziraatbank.com.tr', _BANK_HOW),
    ('garanti', r'garanti', 'Garanti BBVA', 'https://www.garantibbva.com.tr', _BANK_HOW),
    ('akbank', r'akbank', 'Akbank', 'https://www.akbank.com', _BANK_HOW),
    ('yapikredi', r'yapı ?kredi|yapi ?kredi', 'Yapı Kredi', 'https://www.yapikredi.com.tr', _BANK_HOW),
    ('isbank', r'iş ?bankası|is ?bankasi|isbank', 'İş Bankası', 'https://www.isbank.com.tr', _BANK_HOW),
    ('halkbank', r'halkbank|halk bankası', 'Halkbank', 'https://www.halkbank.com.tr', _BANK_HOW),
    ('vakifbank', r'vakıfbank|vakifbank', 'VakıfBank', 'https://www.vakifbank.com.tr', _BANK_HOW),
    ('qnb', r'\bqnb\b', 'QNB', 'https://www.qnb.com.tr', _BANK_HOW),
    ('enpara', r'enpara', 'Enpara', 'https://www.enpara.com', _BANK_HOW),
    ('papara', r'papara', 'Papara', 'https://www.papara.com', _BANK_HOW),
    ('parcel', r'kargo|paket|teslimat|gönderi|parcel|delivery|package|شحنة|طرد', 'A parcel', None,
     'Look up the order in the app or site where you bought it: the real tracking number is there.'),
    ('bank', r'\bbanka\b|\bbank\b|بنك|مصرف', 'Your bank', None, _BANK_HOW),
)
_VERIFY_RE = [(key, re.compile(pattern, re.I), name, url, how) for key, pattern, name, url, how in VERIFY]
COURIER_OR_SHOP = {'ptt', 'yurtici', 'aras', 'mng', 'surat', 'trendyol', 'hepsiburada'}
BANKS = {key for key, _, _, _, how in VERIFY if how == _BANK_HOW and key != 'bank'}


def where_to_check(text, limit=2):
    """[{key, name, url, how}]: the official place to check what the message claims, from our own list."""
    found = []
    for key, pattern, name, url, how in _VERIFY_RE:
        if not pattern.search(text):
            continue
        if key == 'parcel' and any(f['key'] in COURIER_OR_SHOP for f in found):
            continue  # a named company already covers "a parcel"
        if key == 'bank' and any(f['key'] in BANKS for f in found):
            continue
        if url and not is_official(urlparse(url).hostname):
            continue  # never show an address that is not on our official list
        found.append({'key': key, 'name': name, 'url': url, 'how': how})
        if len(found) >= limit:
            break
    return found


# What the message wants the reader to do; a scam without a link is still a request.
ASKS = (
    ('code_ask', 'Send a code that came to your phone'),
    ('secret', 'Give a password, code or card details'),
    ('payment', 'Send money or pay a fee'),
    ('call', 'Call a number'),
    ('click', 'Tap a link'),
)


def what_it_asks(signals, links):
    asks = [text for key, text in ASKS if key in signals]
    if links and 'Tap a link' not in asks:
        asks.append('Tap a link')
    return asks


RANK = {'unknown': 0, 'safe': 1, 'caution': 2, 'danger': 3}
BY_RANK = {rank: tone for tone, rank in RANK.items()}
FROM_AI = {'scam': 'danger', 'suspicious': 'caution', 'safe': 'safe', 'unsure': 'unknown'}
VERDICTS = {
    'danger': ('SCAM', 'This message looks like a scam',
               'It shows clear signs of fraud. Don’t tap its links, don’t reply and don’t send money or codes.'),
    'caution': ('SUSPICIOUS', 'Be careful with this message', 'It has signs scam messages use. Check it another way before you act.'),
    'safe': ('NO SIGNS FOUND', 'No scam signs found', 'We found no risky link and no request for money or codes. Stay alert anyway.'),
    'unknown': ('NOT SURE', 'We couldn’t decide', 'There isn’t enough in the message to tell. When in doubt, don’t tap links.'),
}
# Always our own fixed advice: an AI never writes what the reader is told to do.
ACTIONS = {
    'danger': ['Don’t tap the links and don’t reply.', 'Never share a password, card number or SMS code.',
               'Block the sender, delete the message and report it to your operator or usom.gov.tr.'],
    'caution': ['Don’t tap the links yet.', 'Check with the company through its official app or phone number, not through the message.',
                'Never share a password, card number or SMS code.'],
    'safe': ['If something feels wrong, check with the sender another way.'],
    'unknown': ['Don’t tap links you weren’t expecting.', 'Check with the company through its official app or phone number.'],
}
CODE_NOTICE_ACTIONS = ['Use the code only on the app or site where you asked for it.',
                       'Never give this code to anyone, even someone who says they are from the bank, the police or WhatsApp.']
# Shared to warn family and friends: general advice, never the message, its links or the sender.
SHARE = {
    'danger': 'Warning: scam messages are going around (fake parcel fees, blocked accounts, debts, prizes). Don’t tap links in '
              'unexpected messages and never share a code or card number. Check messages free at https://myscanners.com',
    'caution': 'Be careful with unexpected messages about parcels, payments or your accounts. Check with the company through its '
               'official app, never through the link. Check messages free at https://myscanners.com',
}
LURES = ('parcel', 'debt', 'refund', 'prize', 'account', 'romance', 'voice', 'location')
PUSHES = ('payment', 'urgent', 'click', 'secret', 'hidden_cta')


def rule_tone(signals, links, found=None):
    """The rules' verdict. `found` is how many links the message had (only MAX_LINKS are looked up)."""
    found = len(links) if found is None else found
    if any(l['state'] == 'bad' for l in links):
        return 'danger'
    risky = [l for l in links if l['state'] != 'official']
    score = sum(WEIGHT.get(key, 0) for key in signals)
    if risky:
        score += 1 + sum(1 for l in risky if l['state'] == 'warn')
        # The classic: a parcel / debt / refund / prize story + a link + a push to pay, hurry or tap.
        if any(k in signals for k in LURES) and any(k in signals for k in PUSHES):
            return 'danger'
    if score >= 4:
        return 'danger'
    if score >= 2:
        return 'caution'
    complete = found <= MAX_LINKS and all(l['state'] in ('ok', 'official') for l in links)
    if not complete:
        return 'unknown'  # "no signs" only when every link was really looked up
    calm = is_code_notice(signals) or (links and all(l['state'] == 'official' for l in links))
    if score == 0 or (score == 1 and calm):
        return 'safe'
    return 'unknown'


def decide(signals, links, found, opinion):
    """The verdict. The reviewer decides when it answered; hard evidence keeps it honest, so it can overrule our
    word-matching rules (a page that explains scams, a real code message) but never a dangerous link."""
    if any(l['state'] == 'bad' for l in links):
        return 'danger'  # a threat list or our link scan: whatever the message or the reviewer says
    if not opinion:
        return rule_tone(signals, links, found)
    tone = FROM_AI[opinion['verdict']]
    if not opinion['is_message']:
        return 'unknown'
    floor = 'unknown'
    if any(l['state'] == 'warn' for l in links) or 'code_ask' in signals or rule_tone(signals, links, found) == 'danger':
        # a short or look-alike link, someone asking for the code sent to your phone, or a full scam pattern our rules
        # matched (a story + a link + a push): when the reviewer disagrees with those, the reader is told to be careful
        floor = 'caution'
    if RANK[floor] > RANK[tone]:
        tone = floor
    incomplete = found > MAX_LINKS or any(l['state'] in ('na', 'scanning') for l in links)
    if tone == 'safe' and (opinion['hidden_link'] or 'hidden_cta' in signals or incomplete):
        tone = 'unknown'  # "no signs" only when every link could be looked at
    if tone == 'safe' and opinion['spam_folder']:
        tone = 'caution'
    return tone


# A full scan's verdict (services.url_assessment) as a link state.
FULL_SCAN = {'malicious': 'bad', 'high_risk': 'bad', 'suspicious': 'warn', 'harmless': 'ok'}
PENDING = ('queued', 'running')


def merge_scan(link, status, verdict):
    """Fold the full scan of a link (isolated browser, saved report) into its quick lookup. The worse one wins."""
    if status in PENDING:
        if link['state'] != 'bad':
            link['state'] = 'scanning'
        return link
    full = FULL_SCAN.get(verdict) if status != 'error' else None
    if full:
        link['scan_verdict'] = verdict
    if link['state'] == 'bad' or full == 'bad':
        link['state'] = 'bad'
    elif full == 'warn':
        link['state'] = 'warn'
    elif full == 'ok':
        link['state'] = 'official' if link['state'] == 'official' else 'ok'
    elif link['state'] == 'scanning':
        link['state'] = 'na'
    return link


def assess(text, language='en', analyzer=None, ai=None, image=None, email=None):
    """The whole check. `analyzer` and `ai` are replaced in tests; neither ever visits a link."""
    return build(prepare(text, language, analyzer, ai, image, email))


_LINKISH = re.compile(r'^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?$', re.I)


def _host(link):
    return (urlparse(as_url(link)).hostname or '').lower().removeprefix('www.')


def _lookups(found, analyzer):
    own = None
    if found and analyzer is None:
        import time
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = own = URLDeepAnalyzer()
        if hasattr(analyzer.session, 'set_deadline'):
            analyzer.session.set_deadline(time.monotonic() + 30)  # the whole lookup, all links together
    try:
        return [check_link(link, analyzer) for link in found]
    finally:
        if own is not None:
            own.session.close()


def prepare(text, language='en', analyzer=None, ai=None, image=None, email=None):
    """Read the message: masking, signs, quick link lookups and the reviewer's answer. Returns the state build()
    needs; it holds only the masked text, never the original or the image."""
    from services import message_ai
    text = (text or '').strip()[:MAX_TEXT]
    found = find_links(text, limit=6)  # from the original: masking must not change an address that gets checked
    masked, masked_counts = redact(text)
    signals = find_signals(masked)
    masked = tidy(masked)
    auth = (email or {}).get('auth') or {}
    if any(auth.get(k) in ('fail', 'softfail', 'permerror') for k in ('spf', 'dkim', 'dmarc')):
        signals.append('auth_fail')
    links = _lookups(found, analyzer)
    opinion = None
    if ai is not False:
        ask = None if ai is None else (lambda system, body, picture: ai(system, [{'role': 'user', 'text': body}]))
        evidence = message_ai.facts(signals, links, masked_counts)
        if email:
            evidence['original_email'] = {'sender_domain': email.get('sender_domain'), 'sender_checks': auth,
                                          'attachments_not_opened': email.get('attachments', 0)}
        opinion = message_ai.review(masked, evidence, language, image=image, ask=ask)
    if opinion:
        # A link on a threat list is kept whatever the reviewer says. Otherwise a web page or an app screen has no
        # message links, and an address the reviewer names as not part of the message (the browser's address bar,
        # the app's menus) is dropped. Leaving a link out is not enough to drop it.
        ignored = {_host(l) for l in opinion['ignored_links']} - {''}
        keep = lambda l: l['state'] == 'bad' or (opinion['is_message'] and _host(l['link']) not in ignored)  # noqa: E731
        links = [l for l in links if keep(l)]
        found = [f for f in found if any(l['link'] == f for l in links)] + [f for f in found[MAX_LINKS:] if opinion['is_message']
                                                                            and _host(f) not in ignored]
        if opinion['is_message']:  # addresses the text recognition missed
            seen = {_host(f) for f in found}
            extra = [l for l in opinion['visible_links'] if _LINKISH.match(l) and _host(l) not in seen and _host(l) not in ignored]
            found += extra
            links += _lookups(extra[:max(0, MAX_LINKS - len(links))], analyzer)
    return {'lang': language, 'masked': masked, 'masked_counts': masked_counts, 'signals': signals,
            'found': len(found), 'links': links[:MAX_LINKS], 'opinion': opinion,
            'email': {'sender_domain': email.get('sender_domain'), 'sender_checks': auth,
                      'attachments_not_opened': email.get('attachments', 0)} if email else None,
            'reviewer': opinion is not None or (ai is not False and message_ai.ai_on())}


def refresh_review(state, ai=None):
    """After the full link scans: ask the reviewer again (text only, never the image) when a scan found danger or
    warning signs, so its summary agrees with the evidence. Keeps the first answer when this one fails."""
    from services import message_ai
    if not state.get('opinion') or not any(l.get('scan_verdict') in FULL_SCAN and FULL_SCAN[l['scan_verdict']] in ('bad', 'warn')
                                            for l in state['links']):
        return state
    ask = None if ai is None else (lambda system, body, picture: ai(system, [{'role': 'user', 'text': body}]))
    evidence = message_ai.facts(state['signals'], state['links'], state['masked_counts'])
    if state.get('email'):
        evidence['original_email'] = state['email']
    again = message_ai.review(state['masked'], evidence, state['lang'], ask=ask)
    if again and again['is_message']:
        again['visible_links'], again['hidden_link'] = state['opinion']['visible_links'], state['opinion']['hidden_link']
        again['spam_folder'] = state['opinion']['spam_folder']
        state['opinion'] = again
    return state


NOT_MESSAGE = ('NO MESSAGE FOUND', 'We couldn’t find a message in this image',
               'It looks like a web page or an app screen, not a message someone sent you. Send a screenshot of the SMS, chat or email itself.')
ASK_TEXT = {'code': 'Send a code that came to your phone', 'password': 'Give a password, code or card details',
            'card': 'Give a password, code or card details', 'money': 'Send money or pay a fee', 'call': 'Call a number',
            'click_link': 'Tap a link', 'personal_data': 'Give personal details', 'install_app': 'Install an app',
            'reply': 'Reply to the message'}


def build(state):
    """The result for a prepared message, after any full link scans were merged into state['links']."""
    language, masked, masked_counts = state['lang'], state['masked'], state['masked_counts']
    signals, links, opinion = state['signals'], state['links'], state['opinion']
    found = [None] * state['found']  # only its length matters here
    tone = decide(signals, links, len(found), opinion)
    not_message = bool(opinion) and not opinion['is_message'] and tone != 'danger'
    label, headline, summary = NOT_MESSAGE if not_message else VERDICTS[tone]
    # When the reviewer read it, our word-matching signs are shown only where they agree with its verdict.
    shown = [] if not_message else signals if not opinion or tone in ('danger', 'caution') else \
        [k for k in signals if k == 'code_notice']
    hidden = bool(opinion and opinion['hidden_link']) or ('hidden_cta' in signals and not links)

    reasons = []
    for link in links:
        full = FULL_SCAN.get(link.get('scan_verdict'))
        if link['state'] == 'bad' and full == 'bad':
            reasons.append(reason('bad', 'Our link scan found a dangerous link', f'Our full scan of {link["shown"]} found it dangerous.'))
        elif link['state'] == 'bad':
            reasons.append(reason('bad', 'A link is on a threat list', f'{link["shown"]} is listed as dangerous.'))
        elif link['state'] == 'warn' and full == 'warn':
            reasons.append(reason('warn', 'Our link scan found warning signs', f'Our full scan of {link["shown"]} found warning signs.'))
        elif link['state'] in ('ok', 'official') and full == 'ok':
            reasons.append(reason('ok', 'Our link scan found no threats', f'Our full scan of {link["shown"]} found no threat signs.'))
        elif link['state'] == 'scanning':
            reasons.append(reason('na', 'A link is still being scanned', f'{link["shown"]} is still being checked. Open its report in a moment.'))
        elif link['state'] == 'warn':
            reasons.append(reason('warn', 'A link hides where it goes', f'{link["shown"]} uses a short link or a look-alike name.'))
        elif link['state'] == 'official':
            reasons.append(reason('ok', 'A link is the real company’s address', f'{link["shown"]} is the official site.'))
        elif link['state'] == 'na':
            reasons.append(reason('na', 'A link could not be checked', f'{link["shown"]} could not be looked up right now.'))
    if len(found) > MAX_LINKS:
        reasons.append(reason('na', 'Not every link was checked', f'We checked {MAX_LINKS} of the {len(found)} links.'))
    if hidden and not not_message:
        reasons.insert(0, reason('warn', 'The link is hidden behind a button',
                                 'A screenshot can’t show where the button leads. Send us the original email to check its real links.'))
    if opinion and opinion['spam_folder'] and not not_message:
        reasons.append(reason('warn', *SIGNAL_TEXT['spam_mark']))
    for key in shown:
        if key == 'code_notice':
            reasons.append(reason('info', 'Looks like a normal code message',
                                  'It sends you a code and says not to share it, as real ones do. Anyone who asks you for it is a scammer.'))
        elif not (key == 'hidden_cta' and hidden) and not (key == 'spam_mark' and opinion and opinion['spam_folder']):
            reasons.append(reason('bad' if WEIGHT[key] >= 2 else 'warn', *SIGNAL_TEXT[key]))
    if opinion and opinion['asks_for']:
        asks = list(dict.fromkeys(ASK_TEXT[a] for a in opinion['asks_for'] if a in ASK_TEXT))
    else:
        asks = what_it_asks(shown, links)
    if not found and tone in ('danger', 'caution') and (any(k in shown for k in ('code_ask', 'secret', 'payment', 'call'))
                                                        or (opinion and set(opinion['asks_for']) & {'code', 'password', 'card', 'money', 'call'})):
        reasons.insert(0, reason('bad', 'No link, but it asks you to act',
                                 'Scams without a link ask you to call, send a code or pay. That request is the risk.'))
    if state.get('reviewer') and not opinion:
        reasons.append(reason('na', 'Summary unavailable', 'Our summary could not be written right now, so only our checks decided.'))
    if not reasons:
        reasons.append(reason('ok' if tone == 'safe' else 'na', 'No scam signs found', 'No risky link and no request for money, codes or passwords.'))

    looked = sum(1 for l in links if l['state'] != 'na')
    link_result = 'None' if not found else f'{len(found)} found' if looked == len(found) else f'{looked} of {len(found)} checked'
    strong = [s for s in shown if WEIGHT.get(s, 0) >= 2]
    shown_signals = [s for s in shown if s != 'code_notice']
    review_state = {'danger': 'bad', 'caution': 'warn', 'safe': 'ok', 'unknown': 'info'}
    checks = [check('Links', 'bad' if any(l['state'] == 'bad' for l in links) else 'warn' if any(l['state'] == 'warn' for l in links)
                    else 'na' if any(l['state'] in ('na', 'scanning') for l in links) or len(found) > MAX_LINKS else 'ok' if links else 'info', link_result),
              check('Scam signs', 'bad' if strong else 'warn' if shown_signals else 'ok',
                    str(len(shown_signals)) if shown_signals else 'None'),
              check('Content review', ('info' if not_message else review_state[FROM_AI[opinion['verdict']]]) if opinion else 'na',
                    ('Not a message' if not_message else {'scam': 'Scam', 'suspicious': 'Suspicious', 'safe': 'Looks fine',
                                                          'unsure': 'Not sure'}[opinion['verdict']]) if opinion else 'Off')]
    if masked_counts:
        checks.append(check('Personal data hidden', 'info', str(sum(masked_counts.values()))))
    if not_message:
        actions = ['Take a screenshot of the message itself and check it again.']
    else:
        actions = CODE_NOTICE_ACTIONS if is_code_notice(signals) and tone == 'safe' else ACTIONS[tone]
    plain = {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
             'url': {'prefix': '', 'host': 'Message', 'rest': ''},
             'reasons': ordered(reasons), 'actions': list(actions),
             'checks': checks, 'tally': tally(checks), 'share_text': '' if not_message else SHARE.get(tone, '')}
    if opinion and (opinion['summary'] or opinion['reasons']):
        plain['ai_summary'] = opinion['summary']
        plain['ai_reasons'] = opinion['reasons']
    from services.report_i18n import translate
    say = lambda value: translate(value, language) if language != 'en' else value  # noqa: E731
    verify = [{**v, 'how': say(v['how']), 'name': say(v['name'])} for v in where_to_check(masked)] \
        if tone != 'safe' and not not_message else []
    return {'plain': plain, 'links': links, 'signals': [] if not_message else signals, 'masked': masked_counts,
            'ai': bool(opinion), 'asks': [say(a) for a in asks], 'verify': verify,
            'hidden_link': hidden and not not_message, 'not_message': not_message,
            'sender': opinion['claimed_sender'] if opinion and not not_message else None}
