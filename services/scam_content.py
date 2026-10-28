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


# Casino and betting words (English, Turkish, Chinese, Vietnamese): one may be news, three distinct
# ones make a gambling site. Unlicensed betting is illegal in Turkey and often never pays out.
GAMBLING = re.compile(
    r"casino|kumarhane|\bslots?\b|slot oyun|\bbahis|deneme bonusu|free ?spins?|bedava spin|freespin|çevrimsiz|"
    r"canlı casino|live casino|\brulet|roulette|blackjack|baccarat|bakara|\bpoker|jackpot|sportsbook|sports betting|"
    r"yatırım bonusu|hoş ?geldin bonusu|kayıp bonusu|sweet bonanza|gates of olympus|\baviator\b|big bass|"
    r"\begame\b|百家乐|老虎机|娱乐城|棋牌|真人视讯|体育投注|彩票|nhà cái|cá cược|nổ hũ|đá gà|xổ số", re.I)
# Betting brands with no Turkish licence that scam and spam messages push (two terms with one of these are enough).
BETTING_BRANDS = re.compile(r'bet365|1xbet|mostbet|melbet|betway|pin-?up|betboo|bets10|mobilbahis|youwin|superbahis|tipobet|'
                            r'matadorbet|jojobet|casibom|betturkey|grandpashabet|holiganbet|marsbahis|meritking|onwin|sahabet|'
                            r'imajbet|dumanbet|kingroyal|betebet|vdcasino|padişahbet|padisahbet', re.I)
# Licensed Turkish betting and lottery (Spor Toto, Milli Piyango, TJK) are not flagged.
LICENSED_BETTING = {'iddaa.com', 'nesine.com', 'bilyoner.com', 'misli.com', 'oley.com', 'tjk.org', 'millipiyangoonline.com',
                    'millipiyango.gov.tr', 'sportoto.gov.tr', 'birebin.com', 'hipodrom.com', 'tuttur.com'}


def gambling_site(text, url='', *more_urls):
    """True when the page and its address name three distinct casino or betting terms, or two
    when one of them is in the address itself (hbhdyw.com/egame/… titled "GK Slots") or is an
    unlicensed betting brand. Extra addresses (where a redirect started) count as the address."""
    if more_urls:
        return any(gambling_site(text, u) for u in (url, *more_urls))
    from urllib.parse import urlsplit
    try:
        host = (urlsplit(url).hostname or '').lower() if isinstance(url, str) else ''
    except ValueError:
        host = ''
    if any(host == d or host.endswith('.' + d) for d in LICENSED_BETTING):
        return False
    def terms(value):
        found = {m.group(0).lower().replace(' ', '') for m in GAMBLING.finditer(value or '')}
        return {w[:-1] if w.endswith(('slots', 'spins')) else w for w in found}
    try:
        path = urlsplit(url).path.replace('-', ' ').replace('_', ' ') if isinstance(url, str) else ''
    except ValueError:
        path = ''
    words, in_address = terms(text) | terms(path), terms(path)
    brand = BETTING_BRANDS.search(f"{text or ''} {host}") is not None
    # With a brand, one game-page word is enough; plain "bahis" or "casino" next to a brand is how news reads.
    playing = words - {'bahis', 'casino', 'kumarhane', 'poker', 'sportsbetting'}
    return len(words) >= 3 or (len(words) >= 2 and bool(in_address)) or (brand and bool(playing))


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
