"""Signs that a page is a scam lure, read from its text and forms (url-evidence-v11).

Each signal is something real scam pages need in order to work: a too-good
offer, a way to collect a phone number, card or code, or fake social proof.
Ordinary shops and news sites rarely combine them; the verdict still weighs
them together with the site's age, name and traffic, never alone on an
established site.
"""
import re

# Free money, prizes or gifts "for everyone" (English, Turkish, Arabic).
PRIZE = re.compile(
    r"you(?:'ve| have)? won|claim (?:your|the) (?:prize|reward|gift)|congratulations[,!]? you|free \$\s?\d+|\$\s?\d+ (?:cash|free|for everyone)"
    r"|get \$\s?\d+|gift card (?:winner|for you)|lucky (?:winner|draw)"
    r"|tebrikler|kazandınız|kazandin|kazandın|hediye (?:çeki|kazan|\d)|ücretsiz \d+\s?(?:tl|₺)|\d+\s?(?:tl|₺) (?:hediye|para ödülü)|çekiliş(?:i)? kazan"
    r"|مبروك|ربحت|فزت|لقد فزت|احصل على \d+|جائزة|هدية مجانية|\d+ دولار(?:ا|اً)? نقد|نقد(?:ا|اً) لكل",
    re.I)
# Asking for a phone number, card details or a one-time code.
COLLECT_FIELDS = re.compile(r'phone|mobile|gsm|telefon|tel\b|card|cvv|cvc|expir|iban|tckn|kimlik|otp|sms.?code|doğrulama|pin\b', re.I)
# Comment walls copied from social networks ("Like · Reply", "Beğen · Yanıtla", "يحب · رد").
FAKE_SOCIAL = re.compile(r'(?:like\s*·?\s*reply|beğen\s*·?\s*yanıtla|يحب\s*·?\s*رد|رد\s*·?\s*يحب)', re.I)


def scam_signals(text, inputs):
    """Signal codes for one page. `inputs` are (type, name, placeholder) triples."""
    text = text if isinstance(text, str) else ''
    signals = []
    if PRIZE.search(text):
        signals.append('prize_offer')
    collects = any((kind or '').lower() == 'tel' or COLLECT_FIELDS.search(f'{name or ""} {placeholder or ""}')
                   for kind, name, placeholder in inputs)
    if collects:
        signals.append('collects_phone_or_card')
    if len(FAKE_SOCIAL.findall(text)) >= 3:
        signals.append('fake_comments')
    return signals
