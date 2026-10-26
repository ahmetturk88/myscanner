"""Plain-language summary shown at the top of a URL report.

Built only from the saved assessment and the evidence behind it: every sentence
maps to a reason code or a recorded check, so the summary never says more than
the technical evidence below it does. The verdict itself is never changed here.
"""
from urllib.parse import urlsplit

import re

from services.url_assessment import NOT_VISITED, SHORT_UNRESOLVED, mapping
from services.url_tricks import display

VERDICTS = {
    'malicious': ('danger', 'DANGEROUS', 'Don’t open this link'),
    'high_risk': ('danger', 'HIGH RISK', 'Don’t trust this link'),
    'suspicious': ('caution', 'BE CAREFUL', 'Be careful with this link'),
    'unknown': ('unknown', 'NOT SURE', 'We couldn’t fully check this link'),
    'harmless': ('safe', 'LOOKS SAFE', 'No warning signs found'),
}
MALWARE = {'urlhaus_match', 'web_risk_malware', 'web_risk_unwanted_software', 'download_malware', 'page_malware'}
SCAM = {'verified_phishing', 'web_risk_social_engineering'}
LISTED = MALWARE | SCAM
LOOK_ALIKE = {'typosquatting', 'homoglyph', 'punycode', 'brand_mismatch', 'homograph_name', 'lookalike_name', 'brand_in_subdomain', 'brand_in_name'}
ADDRESS = {'ip_url', 'shortener', 'url_phishing_patterns', 'domain_randomness', 'risky_tld', 'userinfo_trick', 'encoded_ip', 'encoded_host', 'free_hosting', 'credential_bait'}
TRICKS = {'userinfo_trick', 'encoded_ip', 'encoded_host', 'homograph_name', 'brand_in_subdomain'}
PAGE_WARNINGS = {'content_indicators', 'hidden_iframe', 'scam_content', 'content_hidden', 'download_flagged', 'risky_download'}
# code: (tone, title, detail). Tones: bad, warn, info.
REASONS = {
    'urlhaus_match': ('bad', 'Reported for spreading malware', 'URLhaus, a public list run by abuse.ch, lists this link as a malware source.'),
    'web_risk_malware': ('bad', 'Google lists it as malware', 'Google Web Risk lists this link as spreading malware.'),
    'web_risk_unwanted_software': ('bad', 'Google lists it as unwanted software', 'Google Web Risk lists this link as spreading unwanted software.'),
    'verified_phishing': ('bad', 'A confirmed scam page', 'A phishing database has a confirmed, reviewed report for this link.'),
    'web_risk_social_engineering': ('bad', 'Google lists it as a scam', 'Google Web Risk lists this link as phishing or a scam page.'),
    'tls_invalid': ('bad', 'Its security certificate is invalid', 'Your browser would show a warning. Others could read or change what you send.'),
    'no_https': ('warn', 'No secure connection', 'The link uses plain HTTP, so what you type could be read by others on the network.'),
    'typosquatting': ('warn', 'The name may imitate another site', 'A look-alike check flagged this name but couldn’t say which site it copies. Check the spelling yourself.'),
    'homoglyph': ('warn', 'Look-alike letters in the address', 'Some letters only look like normal ones, a trick used to imitate real sites.'),
    'punycode': ('warn', 'Unusual characters in the address', 'The address uses international characters, sometimes used to imitate real sites.'),
    'brand_mismatch': ('warn', 'It uses another company’s name', 'The page shows a brand that doesn’t match its address.'),
    'ip_url': ('warn', 'A number instead of a name', 'The link uses an IP address instead of a website name. Real companies rarely do this.'),
    'shortener': ('info', 'A short link hides where it goes', 'Short links hide the real destination; we followed it and checked where it leads.'),
    'url_phishing_patterns': ('warn', 'Words often used in scam links', 'The address uses words like “login” or “verify” that scam links often contain.'),
    'domain_randomness': ('warn', 'A random-looking name', 'The site name looks randomly generated, which is common for throwaway scam sites.'),
    'domain_history': ('warn', 'The site’s history raises concerns', 'Its registration record shows signs common on scam sites.'),
    'hidden_iframe': ('warn', 'Hidden content on the page', 'The page loads hidden content, a technique used to track or attack visitors.'),
    'redirect_behavior': ('warn', 'It sends you through several addresses', 'The link redirects several times before reaching the final page.'),
    'content_indicators': ('warn', 'The page shows warning signs', 'The page has a form or wording that scam pages often use.'),
    'scam_content': ('bad', 'It promises free money or prizes', 'The page offers cash or gifts “for everyone”, or shows fake comments from happy winners. This is how prize scams work.'),
    'content_hidden': ('warn', 'The page hid itself from our check', 'It showed our scanner an error or an empty page, but may show something else on your phone. Scam pages do this to avoid security checks.'),
    'risky_tld': ('warn', 'A domain ending often used by scams', 'The address ends in a cheap domain type that scam sites use a lot.'),
    'new_domain': ('warn', 'A very new site', 'The site was registered less than a year ago. Scam sites are usually new.'),
    'userinfo_trick': ('bad', 'The link hides where it really goes', 'Browsers ignore everything before “@” in a link, so the name you see is not the site that opens.'),
    'encoded_ip': ('bad', 'It hides a numeric address', 'The site name is a disguised IP address. Real companies never write links like this.'),
    'encoded_host': ('bad', 'The site name is written in code', 'Letters in the site name are %-encoded to hide what it really is.'),
    'homograph_name': ('bad', 'Fake letters in the site name', 'The name uses letters from another alphabet that look like normal ones, to imitate another site.'),
    'lookalike_name': ('warn', 'The name is close to a well-known brand', 'The site name is one letter away from a well-known name. Check the spelling carefully.'),
    'brand_in_subdomain': ('bad', 'A fake address in front of the real one', 'The link starts with a well-known site’s address to look official, but opens a different site.'),
    'brand_in_name': ('warn', 'It uses a brand name it doesn’t own', 'The address contains a well-known brand’s name, but the site doesn’t belong to that brand.'),
    'free_hosting': ('info', 'On a free hosting service', 'Anyone can publish a page there, so the platform’s name says nothing about who made it.'),
    'download_malware': ('bad', 'It downloads a virus', 'The link downloads a file, and our antivirus scan found malware in it.'),
    'page_malware': ('bad', 'The page contains malware', 'Our antivirus scan found malware in this page.'),
    'download_flagged': ('warn', 'The download looks risky', 'Our antivirus flagged risky features in the file this link downloads.'),
    'risky_download': ('warn', 'It downloads an app or program', 'Fake apps sent by message can take over your phone. Install apps only from Google Play or the official site.'),
    'credential_bait': ('warn', 'A sign-in page on a free host', 'Its name on a free hosting service is about signing in, verifying or paying. Real companies don’t put these pages on free hosts.'),
    'odd_port_destination': ('warn', 'It sends you to an unusual server', 'The link redirects to a server on an unusual port, the way malware downloads are often delivered. We didn’t open it.'),
    'destination': ('warn', 'It sends you to a different site', 'The link opens a different site from the one in the link, and that site shows warning signs.'),
    'device_cloaking': ('bad', 'It hides from security checks', 'The link sends phones and computers to different sites. Scam links do this so checks see a harmless page.'),
    'redirect_loop': ('warn', 'It redirects too many times', 'The link keeps sending you on without reaching a page, a trick used to wear out security checks.'),
    'headers_weak': ('info', 'Some recommended protections are missing', 'Common on ordinary sites too; not a sign of a scam by itself.'),
    'unverified_report': ('info', 'An unconfirmed scam report', 'Someone reported this link as phishing; reviewers haven’t confirmed it yet.'),
}


def whole(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def age_text(days):
    if days < 60:
        return f'{days} day' + ('' if days == 1 else 's')
    if days < 730:
        return f'{days // 30} months'
    return f'{days // 365} years'


def tally(checks):
    """'2 bad · 1 warning · 3 fine': the count line above the checks list."""
    counts = {state: sum(c['state'] == state for c in checks) for state in ('bad', 'warn', 'ok', 'na')}
    return ' · '.join(text for text in (f"{counts['bad']} bad" if counts['bad'] else '',
                                        f"{counts['warn']} warning" + ('s' if counts['warn'] != 1 else '') if counts['warn'] else '',
                                        f"{counts['ok']} fine" if counts['ok'] else '',
                                        f"{counts['na']} not checked" if counts['na'] else '') if text)


def url_parts(url):
    """The address split so the host can be shown in bold."""
    try:
        parts = urlsplit(url if isinstance(url, str) else '')
        host = parts.hostname or ''
    except ValueError:
        host = ''
    if not host or not isinstance(url, str):
        return {'prefix': '', 'host': url if isinstance(url, str) else '', 'rest': ''}
    start = url.lower().find(host)
    if start < 0:
        return {'prefix': '', 'host': url, 'rest': ''}
    return {'prefix': url[:start], 'host': url[start:start + len(host)], 'rest': url[start + len(host):]}


def defang(url):
    """A copy of the address that chat apps will not turn into a clickable link."""
    text = url if isinstance(url, str) else ''
    for scheme, safe in (('https://', 'hxxps://'), ('http://', 'hxxp://')):
        if text.lower().startswith(scheme):
            text = safe + text[len(scheme):]
    return text.replace('.', '[.]')


def imitated(local, deep):
    """The well-known site a look-alike name copies, when our analyzer named one."""
    for data in (local, deep):
        for issue in mapping(data.get('phishing')).get('issues') or []:
            match = re.fullmatch(r'Possible typosquatting of ([a-z0-9-]{2,30}\.com)', issue) if isinstance(issue, str) else None
            if match:
                return match.group(1)
    return ''


def plain_report(assessment, local, deep, url):
    assessment, local, deep = mapping(assessment), mapping(local), mapping(deep)
    verdict = assessment.get('verdict') if assessment.get('verdict') in VERDICTS else 'unknown'
    tone, label, headline = VERDICTS[verdict]
    found = {r.get('code'): r for r in assessment.get('reasons') or [] if isinstance(r, dict) and r.get('code') in REASONS}
    components = mapping(assessment.get('components'))
    assessed = lambda key: mapping(components.get(key)).get('status') == 'assessed'
    reputation_only = local.get('reputation_only') is True
    provider = mapping(local.get('urlvet'))
    page = mapping(provider.get('content'))
    brand = page.get('brand_found') if isinstance(page.get('brand_found'), str) and 0 < len(page.get('brand_found')) <= 40 else ''
    whois = mapping(deep.get('whois'))
    age = whole(whois.get('age_days')) if not whois.get('error') else None
    login = page.get('has_login_form') is True or mapping(deep.get('page_content')).get('has_login_form') is True
    payment = page.get('has_payment_form') is True
    missing = [m for m in assessment.get('missing_checks') or [] if isinstance(m, str)]
    unresolved = SHORT_UNRESOLVED in missing
    copied = imitated(local, deep)
    tricks = {d.get('code'): d for d in assessment.get('address_details') or [] if isinstance(d, dict)}
    real_host = url_parts(url)['host']

    reasons = []
    rank = {'bad': 0, 'warn': 1, 'info': 2}
    for code, item in sorted(found.items(), key=lambda pair: (rank[REASONS[pair[0]][0]], -(pair[1].get('deduction') or 0))):
        kind, title, detail = REASONS[code]
        trick = tricks.get(code) or {}
        text = lambda key: trick.get(key) if isinstance(trick.get(key), str) and 0 < len(trick.get(key)) <= 80 else ''
        file = mapping(mapping(mapping(deep.get('page_content')).get('download')))
        name = file.get('filename') if isinstance(file.get('filename'), str) and 0 < len(file.get('filename')) <= 100 else ''
        signature = mapping(file.get('antivirus')).get('signature')
        if code == 'download_malware' and name and isinstance(signature, str) and 0 < len(signature) <= 120:
            detail = f'The link downloads “{name}”, and our antivirus found {signature} in it.'
        elif code == 'risky_download' and name:
            detail = f'The link downloads “{name}”. Fake apps sent by message can take over your phone. Install apps only from Google Play or the official site.'
        page_signature = mapping(mapping(deep.get('page_content')).get('antivirus')).get('signature')
        if code == 'page_malware' and isinstance(page_signature, str) and 0 < len(page_signature) <= 120:
            detail = f'Our antivirus found {page_signature} in this page.'
        destination = mapping(assessment.get('destination'))
        if code == 'destination' and isinstance(destination.get('url'), str) and url_parts(destination['url'])['host']:
            detail = f'The link opens {url_parts(destination["url"])["host"]}, a different site from the one in the link, and that site shows warning signs.'
        if code == 'userinfo_trick' and text('shown') and real_host:
            detail = f'The link shows “{text("shown")}”, but it really opens {real_host}. Browsers ignore everything before “@”.'
        elif code == 'encoded_ip' and text('shown') and text('real'):
            detail = f'“{text("shown")}” is a disguised way of writing the IP address {text("real")}. Real companies never write links like this.'
        elif code == 'homograph_name' and text('looks_like'):
            detail = f'It is made to look like {text("looks_like")}, but some letters come from another alphabet. It is a different site.'
        elif code == 'lookalike_name' and text('brand') and trick.get('tld_swap') is True and found[code].get('deduction', 0) >= 20:
            kind, title = 'bad', f'It imitates {display(text("brand"))}'
            detail = f'It uses the {display(text("brand"))} name with a different ending. It is not an official {display(text("brand"))} site.'
        elif code == 'lookalike_name' and text('brand'):
            kind = 'bad' if trick.get('strong') is True else 'warn'
            title = f'It imitates {display(text("brand"))}' if kind == 'bad' else f'The name is close to {display(text("brand"))}'
            detail = (f'The site name copies {display(text("brand"))} with swapped letters or numbers. It is not the real site.' if kind == 'bad'
                      else f'The site name is one letter away from {display(text("brand"))}. Check the spelling carefully.')
        elif code == 'brand_in_subdomain' and text('brand') and text('real'):
            detail = f'The link starts with {text("brand")} to look official, but the site it opens is {text("real")}.'
        elif code == 'brand_in_name' and text('brand'):
            title = f'It uses the {display(text("brand"))} name'
            detail = f'The address contains “{display(text("brand"))}”, but it isn’t an official {display(text("brand"))} site.'
        if code == 'brand_mismatch' and brand:
            title, detail = f'It pretends to be {brand}', f'The page shows the {brand} brand, but the address doesn’t belong to {brand}.'
        elif code == 'content_indicators' and (login or payment):
            title = 'It asks for your password' if login else 'It asks for payment details'
            detail = 'The page has a form that sends what you type to this site. Only enter it on sites you opened yourself.'
        elif code == 'typosquatting' and copied:
            title, detail = f'The name looks like {copied}', f'The address is very close to {copied} but isn’t it. Check the spelling carefully.'
        elif code == 'shortener' and unresolved:
            continue  # explained by the "couldn’t see where it leads" reason below
        elif code == 'new_domain' and age is not None:
            detail = f'The site was registered {age_text(age)} ago. Scam sites are usually new.'
        elif code == 'domain_history' and 'new_domain' in found:
            continue
        elif code == 'domain_history' and age is not None and age < 365:
            title, detail = 'A very new site', f'The site was registered {age_text(age)} ago. Scam sites are usually new.'
        reasons.append({'tone': kind, 'title': title, 'detail': detail})
    if verdict == 'harmless':
        good = []
        if assessed('reputation') and not LISTED & set(found):
            good.append({'tone': 'ok', 'title': 'Not on any threat list', 'detail': 'None of the malware and phishing lists we checked include this link.'})
        if assessed('transport') and not {'tls_invalid', 'no_https'} & set(found):
            good.append({'tone': 'ok', 'title': 'Secure connection', 'detail': 'The site uses HTTPS with a valid certificate, so what you send is encrypted.'})
        if age is not None and age >= 730:
            good.append({'tone': 'ok', 'title': 'A long-established site', 'detail': f'The address was registered {age_text(age)} ago.'})
        elif assessed('identity') and not (LOOK_ALIKE | ADDRESS) & set(found):
            good.append({'tone': 'ok', 'title': 'No look-alike tricks', 'detail': 'The address doesn’t imitate another site’s name.'})
        # A minor warning that didn't change the verdict is still shown, so every
        # warning in the checks list has a reason next to it.
        reasons = [r for r in reasons if r['tone'] == 'warn'] + good + [r for r in reasons if r['tone'] == 'info']
    warnings = [r for r in reasons if r['tone'] in ('bad', 'warn')]
    if tone in ('danger', 'caution') and not warnings:
        # Never a warning verdict without a visible reason (v10 invariant).
        warnings = [{'tone': 'warn', 'title': 'Several small warning signs', 'detail': 'None is serious alone, but together they lowered the score. The technical evidence lists each one.'}]
        reasons = warnings + reasons
    if len(warnings) >= 3:
        reasons = warnings  # minor notes stay in the technical evidence
    if verdict == 'unknown':
        if reputation_only:
            reasons.insert(0, {'tone': 'na', 'title': 'We didn’t open the page', 'detail': 'It uses an unusual port, so only its reputation was checked.'})
        elif unresolved:
            reasons.insert(0, {'tone': 'warn', 'title': 'We couldn’t see where it leads', 'detail': 'The short-link service showed its own page instead of sending us on, so the real destination wasn’t checked.'})
        elif missing:
            count = len(missing)
            reasons.insert(0, {'tone': 'na', 'title': 'Some checks couldn’t run', 'detail': f'{count} check' + (' was' if count == 1 else 's were') + ' unavailable, so we can’t call it safe.'})
    reasons = reasons[:4]

    codes = set(found)
    if tone == 'danger':
        if codes & MALWARE:
            summary = 'It is on a list of links that spread malware. Opening it could harm your device.'
            actions = ['Don’t open the link, and don’t run anything it downloaded.',
                       'Already opened a file from it? Disconnect from the internet and run a virus scan.']
        elif codes & SCAM:
            summary = 'It is a known scam page made to steal passwords or payment details.'
            actions = ['Don’t open the link or enter any information on it.',
                       'Already entered a password? Change it on the real site and turn on two-step login.']
        else:
            summary = 'We found several strong warning signs. Treat it as unsafe.'
            actions = ['Don’t open the link or enter any information on it.',
                       'Already entered a password? Change it on the real site and turn on two-step login.']
        actions.append('Tell the person who sent it. Their account may have been hacked.')
    elif tone == 'caution':
        summary = 'It isn’t on a threat list, but it shows signs that are common on scam pages.'
        actions = ['Don’t enter passwords or card details on this page.',
                   f'To reach {brand}, type its address yourself or use its official app.' if brand else 'Open important sites by typing the address yourself, not from links in messages.',
                   'Not sure? Ask the sender through another app or a phone call.']
    elif tone == 'unknown':
        summary = ('It uses an unusual port, so we only checked its reputation and didn’t open the page.' if reputation_only
                   else 'It’s a short link, and we couldn’t see the page it really leads to. Don’t trust it yet.' if unresolved
                   else 'Some checks couldn’t run, so we can’t say it’s safe. Nothing we did check looked dangerous.' if not warnings
                   else 'Some checks couldn’t run, and we found a few warning signs.')
        actions = ['Treat it with care until it can be checked fully.',
                   'Don’t enter passwords or payment details unless you opened the site yourself.',
                   'Try scanning it again in a few minutes.']
    else:
        if warnings:
            headline = 'No serious warning signs'
            summary = 'It isn’t on any threat list we checked. We noticed a minor sign, explained below.'
        else:
            summary = 'It isn’t on any threat list we checked, and we found no warning signs.'
        actions = ['Nothing we checked suggests it’s dangerous right now.',
                   'Only sign in or pay on pages you opened yourself, not from a link in a message.']

    def check(name, state, result):
        return {'name': name, 'state': state, 'result': result}
    not_opened = 'Not opened' if reputation_only else 'Not checked'
    reputation = mapping(components.get('reputation'))
    checks = [
        check('Threat lists', 'bad', 'Listed') if codes & LISTED else
        check('Threat lists', 'warn', 'Unconfirmed report') if 'unverified_report' in codes else
        check('Threat lists', 'ok', 'Not listed') if reputation.get('status') == 'assessed' else check('Threat lists', 'na', 'Not checked'),
        check('Secure connection', 'bad', 'Invalid certificate') if 'tls_invalid' in codes else
        check('Secure connection', 'warn', 'No HTTPS') if 'no_https' in codes else
        check('Secure connection', 'ok', 'Valid HTTPS') if assessed('transport') else check('Secure connection', 'na', 'Not checked'),
        check('Look-alike or fake brand', 'bad', 'Fake address') if codes & TRICKS - {'userinfo_trick', 'encoded_ip', 'encoded_host'} or mapping(tricks.get('lookalike_name')).get('strong') is True else
        check('Look-alike or fake brand', 'warn', brand if 'brand_mismatch' in codes and brand else copied if 'typosquatting' in codes and copied else 'Possible') if codes & LOOK_ALIKE else
        check('Look-alike or fake brand', 'ok', 'None') if assessed('identity') else check('Look-alike or fake brand', 'na', 'Not checked'),
        check('Suspicious address', 'bad', 'Hidden destination') if codes & {'userinfo_trick', 'encoded_ip', 'encoded_host'} else
        check('Suspicious address', 'warn', 'Short link' if codes & ADDRESS == {'shortener'} else 'Found') if codes & ADDRESS - {'shortener'} or unresolved else
        check('Suspicious address', 'info', 'Short link') if 'shortener' in codes else
        check('Suspicious address', 'ok', 'None') if assessed('identity') else check('Suspicious address', 'na', 'Not checked'),
        check('Site age', 'warn' if age < 90 else 'ok', age_text(age)) if age is not None else
        check('Site age', 'warn', 'Risk signs') if 'domain_history' in codes else check('Site age', 'na', 'Not available'),
        check('Page content', 'bad', 'Virus found') if codes & {'download_malware', 'page_malware'} else
        check('Page content', 'warn', 'Downloads a program') if 'risky_download' in codes else
        check('Page content', 'bad', 'Scam signs') if 'scam_content' in codes else
        check('Page content', 'warn', 'Hidden from us') if 'content_hidden' in codes else
        check('Page content', 'warn', 'Asks for password' if login else 'Warning signs') if codes & PAGE_WARNINGS else
        check('Page content', 'ok', 'Nothing unusual') if assessed('content') else check('Page content', 'na', not_opened),
        check('Redirects', 'bad', 'Hides from checks') if 'device_cloaking' in codes else
        check('Redirects', 'warn', 'To another site') if 'destination' in codes else
        check('Redirects', 'warn', 'Too many') if 'redirect_loop' in codes else
        check('Redirects', 'warn', 'Several') if 'redirect_behavior' in codes else
        check('Redirects', 'ok', 'Normal') if assessed('behavior') else check('Redirects', 'na', not_opened),
    ]

    share = (f'MyScanner checked this link and found no warning signs: {defang(url)}' if tone == 'safe'
             else f'Warning: MyScanner rates this link as {label.lower()}: {defang(url)}. Don’t open it.' if tone == 'danger'
             else f'Careful: MyScanner found warning signs on this link: {defang(url)}' if tone == 'caution'
             else f'MyScanner couldn’t fully check this link: {defang(url)}')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': url_parts(url), 'reasons': reasons, 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'reputation_only': reputation_only, 'not_visited': NOT_VISITED if reputation_only else None,
            'share_text': share.rstrip('.') + '. Check links free at https://myscanners.com'}
