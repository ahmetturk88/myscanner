"""Plain-language summary shown at the top of an email address report.

Like the URL and file summaries: every sentence maps to a recorded DNS,
blocklist, registration or probe result, and the verdict itself is never
changed. A well-configured domain says nothing about who is behind an address.
"""
from services.url_assessment import mapping
from services.url_report_view import age_text, tally, whole

VERDICTS = {
    'dangerous': ('danger', 'DANGEROUS', 'This address is likely used for scams'),
    'no_domain': ('danger', 'NOT A REAL ADDRESS', 'This address can’t receive email'),
    'review': ('caution', 'BE CAREFUL', 'Be careful with this address'),
    'unknown': ('unknown', 'NOT SURE', 'We couldn’t fully check this address'),
    'no_indicators': ('safe', 'NO WARNING SIGNS', 'No warning signs found'),
}


def plain_email_report(report):
    report = mapping(report)
    assessment, dns = mapping(report.get('assessment')), mapping(report.get('dns'))
    smtp, lists, domain_info = mapping(report.get('smtp')), mapping(report.get('blacklist')), mapping(report.get('domain_info'))
    verdict = assessment.get('verdict') if assessment.get('verdict') in VERDICTS else 'unknown'
    tone, label, headline = VERDICTS[verdict]
    email = report.get('email') if isinstance(report.get('email'), str) else ''
    domain = report.get('domain') if isinstance(report.get('domain'), str) else (email.rsplit('@', 1)[-1] if '@' in email else '')
    no_domain = verdict == 'no_domain'
    mx, spf, dmarc = mapping(dns.get('mx')), mapping(dns.get('spf')), mapping(dns.get('dmarc'))
    null_mx = any(isinstance(r, dict) and r.get('exchange') in ('', '.') for r in (mx.get('records') if isinstance(mx.get('records'), list) else []))
    private_mx = any(isinstance(h, dict) and h.get('unsafe_addresses') for h in (mx.get('infrastructure') if isinstance(mx.get('infrastructure'), list) else []))
    spf_missing, dmarc_missing = spf.get('status') == 'not_found', dmarc.get('status') == 'not_found'
    broken = [name for name, value in (('SPF', spf), ('DMARC', dmarc)) if mapping(value.get('audit')).get('configuration_valid') is False]
    monitoring = dmarc.get('status') == 'found' and dmarc.get('policy') == 'none'
    listed = lists.get('is_blacklisted') is True
    listed_on = ', '.join(s for s in lists.get('blacklisted_on') or [] if isinstance(s, str))[:120]
    lists_answered = lists.get('coverage_status') == 'completed' or bool(lists.get('clean_on')) or listed
    disposable, free = report.get('is_disposable') is True, report.get('is_free') is True
    age = whole(domain_info.get('age_days')) if not domain_info.get('error') else None
    rejected = smtp.get('coverage_status') == 'checked' and smtp.get('valid') is False
    accepted = smtp.get('coverage_status') == 'checked' and smtp.get('valid') is True
    missing = [m for m in assessment.get('missing_checks') or [] if isinstance(m, str)]
    names = [n for n in report.get('name_signals') or [] if isinstance(n, dict)]
    copied = next((n for n in names if n.get('code') in ('homograph_name', 'lookalike_name', 'brand_in_subdomain', 'scheme_in_name', 'brand_in_name')), None)
    brand = (copied or {}).get('brand_name') or ''
    copy_found = bool(copied) and assessment.get('copies_brand') is True
    web_risk = mapping(report.get('web_risk'))
    google_listed = web_risk.get('status') == 'matched'

    reasons = []
    def add(kind, title, detail):
        reasons.append({'tone': kind, 'title': title, 'detail': detail})
    if google_listed:
        add('bad', 'Google lists this domain as dangerous', 'Google Web Risk lists the website on this domain for phishing or malware.')
    if copy_found:
        code = copied.get('code')
        add('bad' if verdict == 'dangerous' else 'warn', 'It copies a well-known name',
            'The domain uses look-alike letters from another alphabet to copy a well-known name.' if code == 'homograph_name'
            else f'The domain copies {brand}’s name with swapped letters or numbers.' if code == 'lookalike_name' and copied.get('strong') and brand
            else f'The domain is one letter away from {brand}’s name.' if code == 'lookalike_name' and brand
            else f'The domain starts with {brand}’s address to look official, but it is a different domain.' if code == 'brand_in_subdomain' and brand
            else f'The domain uses {brand}’s name, but it isn’t one of {brand}’s known domains.' if brand
            else 'The domain is made to look like a well-known company’s.')
    if no_domain:
        add('bad', 'The domain doesn’t exist', f'{domain or "The domain"} isn’t registered, so this address can’t send or receive email. Check for a typo.')
    if null_mx:
        add('bad', 'This domain doesn’t accept email', 'Its owner has declared that it never receives mail.')
    elif mx.get('status') == 'not_found' and not no_domain:
        add('warn', 'No mail server listed', 'The domain has no mail (MX) record, so email to this address may not arrive.')
    if private_mx:
        add('warn', 'Its mail server points to a private address', 'A normal mail server is reachable on the internet. This setup is unusual.')
    if disposable:
        add('warn', 'A throwaway address', 'The domain hands out temporary inboxes that disappear after a while. Spammers and fake accounts use them.')
    if listed:
        add('warn', 'Its mail server is on a spam blocklist', (f'{listed_on} lists' if listed_on else 'A blocklist lists') + ' a server this domain uses. That is about the server, not proof this person is a scammer.')
    if spf_missing or dmarc_missing:
        which = 'SPF or DMARC' if spf_missing and dmarc_missing else 'SPF' if spf_missing else 'DMARC'
        add('warn', 'Email from this domain is easy to fake', f'The domain has no {which} protection, so anyone can send mail pretending to be from it.')
    if broken:
        add('warn', 'Its anti-spoofing setup has errors', f'The {" and ".join(broken)} record' + ('s are' if len(broken) > 1 else ' is') + ' misconfigured, so fake mail may not be stopped.')
    if age is not None and age < 30:
        add('warn', 'A brand-new domain', f'It was registered {age_text(age)} ago. Scam addresses often use new domains.')
    if rejected:
        add('warn', 'The mail server rejected this address', 'The mailbox probably doesn’t exist.')
    if verdict == 'no_indicators':
        if mx.get('status') == 'found' and not null_mx:
            add('ok', 'Set up to receive email', 'The domain has working mail servers.')
        if listed is False and lists_answered:
            add('ok', 'Not on spam blocklists', 'None of the blocklists that answered list its mail servers.')
        if age is not None and age >= 730:
            add('ok', 'An established domain', f'It was registered {age_text(age)} ago.')
    if free and not no_domain:
        add('info', 'A free email service', 'Anyone can create an address here, so the name alone doesn’t prove who it belongs to.')
    if monitoring and not dmarc_missing and verdict != 'no_domain':
        add('info', 'Fake-mail protection only monitors', 'Its DMARC policy reports fake mail but doesn’t block it. Common, even at large providers.')
    if verdict == 'unknown' and missing:
        reasons.insert(0, {'tone': 'na', 'title': 'Some checks couldn’t run',
                           'detail': f'{len(missing)} check' + (' was' if len(missing) == 1 else 's were') + ' unavailable, so we can’t say it’s fine.'})
    rank = {'na': 0, 'bad': 1, 'warn': 2, 'ok': 3, 'info': 4}
    reasons = sorted(reasons, key=lambda r: rank[r['tone']])[:4]

    spoofable = spf_missing or dmarc_missing or bool(broken)
    if no_domain:
        summary = 'The part after the @ isn’t a real domain, so no email can reach this address.'
        actions = ['Check the address for a typo.', 'If someone gave you this address, ask them for a working one.',
                   'Don’t trust a message that claims to come from it.']
    elif verdict == 'dangerous':
        summary = ('Google lists this domain as dangerous. Treat any message from it as a scam.' if google_listed
                   else f'The domain pretends to be {brand}’s. Treat any message from it as a scam.' if brand
                   else 'The domain is made to look like a well-known company’s. Treat any message from it as a scam.')
        actions = ['Don’t click links, open attachments or reply to messages from this address.',
                   f'To reach {brand}, use its official app or type its website yourself.' if brand else 'Contact the company through its official website or app.',
                   'Already shared a password or card details? Change the password and call your bank.']
    elif tone == 'caution':
        summary = ('It is a throwaway address, often used for spam and fake sign-ups.' if disposable
                   else 'Its mail server is on a spam blocklist.' if listed
                   else 'Email from this domain can be faked easily.' if spoofable and not (null_mx or rejected)
                   else 'We found warning signs about this address.')
        actions = ['Don’t send money, passwords or documents until you’ve confirmed who is behind it.',
                   'Got an unexpected request from this domain? Confirm it by phone or another app: it may be faked.' if spoofable
                   else 'Contact the person through a channel you already trust.',
                   'Never decide on payments based on an email address alone.']
    elif tone == 'unknown':
        summary = 'Some checks couldn’t run, so we can’t say it’s fine.'
        actions = ['Confirm who is behind it through a channel you already trust.', 'Try checking it again in a few minutes.']
    else:
        summary = 'The domain is set up properly and isn’t on a blocklist. This doesn’t prove who is behind the address.'
        actions = ['The address looks properly set up.',
                   'Unexpected request for money or data? Confirm it another way, even from a real address.']

    def check(name, state, result):
        return {'name': name, 'state': state, 'result': result}
    if no_domain:
        checks = [check('Domain exists', 'bad', 'No'), check('Receives email', 'bad', 'No')]
    else:
        checks = [
            check('Domain exists', 'ok', 'Yes'),
            check('Receives email', 'bad', 'No') if null_mx else check('Receives email', 'warn', 'No mail server') if mx.get('status') == 'not_found'
            else check('Receives email', 'ok', 'Yes') if mx.get('status') == 'found' else check('Receives email', 'na', 'Not checked'),
            check('Fake-mail protection', 'warn', 'Errors' if broken and not (spf_missing or dmarc_missing) else 'None' if spf_missing and dmarc_missing else 'No SPF' if spf_missing else 'No DMARC') if spoofable
            else check('Fake-mail protection', 'info', 'Monitoring only') if monitoring
            else check('Fake-mail protection', 'ok', 'SPF + DMARC') if spf.get('status') == 'found' and dmarc.get('status') == 'found'
            else check('Fake-mail protection', 'na', 'Not checked'),
            check('Spam blocklists', 'warn', 'Listed') if listed else check('Spam blocklists', 'ok', 'Not listed') if lists_answered else check('Spam blocklists', 'na', 'Not checked'),
            check('Throwaway address', 'warn', 'Yes') if disposable else check('Throwaway address', 'ok', 'No'),
            check('Copies a brand’s name', 'bad' if verdict == 'dangerous' else 'warn', 'Yes') if copy_found else check('Copies a brand’s name', 'ok', 'No'),
            *([check('Google Web Risk', 'bad', 'Listed')] if google_listed else [check('Google Web Risk', 'ok', 'Not listed')] if web_risk.get('status') == 'not_found' else []),
            check('Domain age', 'warn' if age < 30 else 'ok', age_text(age)) if age is not None else check('Domain age', 'na', 'Unknown'),
        ]
        if rejected or accepted:
            checks.append(check('Mailbox', 'warn', 'Rejected') if rejected else check('Mailbox', 'ok', 'Accepts mail'))
    local, _, host = email.partition('@')
    share = (f'MyScanner says the email address {email} can’t receive mail: its domain doesn’t exist.' if no_domain
             else f'Warning: MyScanner says the email address {email} is likely used for scams.' if verdict == 'dangerous'
             else f'Careful: MyScanner found warning signs for the email address {email}.' if tone == 'caution'
             else f'MyScanner found no warning signs for the email address {email}.' if tone == 'safe'
             else f'MyScanner couldn’t fully check the email address {email}.')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': local + '@' if host else '', 'host': host or email, 'rest': ''},
            'reasons': reasons, 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': share + ' Check addresses free at https://myscanners.com'}
