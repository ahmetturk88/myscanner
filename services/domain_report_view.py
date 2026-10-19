"""Plain-language summary shown at the top of a domain report.

The domain tool reads registration (RDAP) and DNS records only; it never opens
the website. The summary says so, points to the link scanner for the site
itself, and never turns missing data into a reassurance.
"""
from services.url_assessment import mapping
from services.url_report_view import age_text, tally, whole

HOLD = ('clienthold', 'serverhold')
DELETING = ('pendingdelete', 'redemptionperiod')


def plain_domain_report(result):
    result = mapping(result)
    domain = result.get('domain') if isinstance(result.get('domain'), str) else ''
    no_domain = result.get('verdict') == 'no_domain'
    coverage = mapping(result.get('coverage'))
    registered = coverage.get('whois') == 'assessed'
    age, expiry = whole(result.get('age_days')), result.get('days_until_expiry')
    expiry = expiry if isinstance(expiry, int) and not isinstance(expiry, bool) else None
    states = [s.lower().replace(' ', '') for s in result.get('status') or [] if isinstance(s, str)]
    on_hold = any(s in HOLD for s in states)
    deleting = any(s in DELETING for s in states)
    records = [r for r in result.get('dns') or [] if isinstance(r, dict)]
    kinds = {r.get('type') for r in records}
    has_site = bool(kinds & {'A', 'AAAA', 'CNAME'})
    has_mail = 'MX' in kinds
    multiple_spf = mapping(result.get('spf_observation')).get('status') == 'multiple_records'
    registrar = result.get('registrar') if isinstance(result.get('registrar'), str) else ''
    registrar = registrar[:60]

    reasons = []
    def add(kind, title, detail):
        reasons.append({'tone': kind, 'title': title, 'detail': detail})
    if no_domain:
        add('bad', 'The domain doesn’t exist', 'No DNS server knows this name, so no website or email can work on it. Check the spelling.')
    if on_hold:
        add('warn', 'The registry has suspended it', 'It is on hold, which often happens after abuse complaints or unpaid fees. It won’t load while on hold.')
    if deleting:
        add('warn', 'It is being deleted', 'The registration has expired and the domain is about to be released.')
    if age is not None and age < 30:
        add('warn', 'A brand-new domain', f'It was registered {age_text(age)} ago. Scam sites usually use new domains.')
    elif age is not None and age < 180:
        add('info', 'A young domain', f'It was registered {age_text(age)} ago.')
    if expiry is not None and 0 <= expiry < 30 and not deleting:
        add('info', 'It expires soon', f'The registration ends in {expiry} day' + ('' if expiry == 1 else 's') + '.')
    if multiple_spf:
        add('info', 'Its email setup has an error', 'It publishes more than one SPF record, so some email from it may be rejected.')
    if not no_domain and not registered:
        add('na', 'Registration data unavailable', 'The registry didn’t answer, so we can’t see when the domain was created.')
    warned = any(r['tone'] in ('bad', 'warn') for r in reasons)
    if not no_domain and not warned:
        if age is not None and age >= 730:
            add('ok', 'An established domain', f'It was registered {age_text(age)} ago' + (f' with {registrar}.' if registrar else '.'))
        if has_site or has_mail:
            add('ok', 'Active DNS setup', 'It has ' + ' and '.join(x for x in ('a website address' if has_site else '', 'mail servers' if has_mail else '') if x) + '.')
    rank = {'na': 0, 'bad': 1, 'warn': 2, 'ok': 3, 'info': 4}
    reasons = sorted(reasons, key=lambda r: rank[r['tone']])[:4]

    if no_domain:
        tone, label, headline = 'danger', 'NOT A REAL DOMAIN', 'This domain doesn’t exist'
        summary = 'Nothing is registered under this name, so no website or email can work on it.'
        actions = ['Check the spelling. Scammers count on look-alike names.',
                   'If a message used this address, don’t trust it.']
    elif warned:
        tone, label, headline = 'caution', 'BE CAREFUL', 'Be careful with this domain'
        summary = ('The registry has suspended it.' if on_hold else 'It is about to be deleted.' if deleting
                   else 'It is brand new. Most scam sites use domains that are only days old.')
        actions = ['Don’t enter passwords or payment details on a site using it until you trust it.',
                   'Check the website itself with the link scanner.']
    elif not registered:
        tone, label, headline = 'unknown', 'NOT SURE', 'We couldn’t fully check this domain'
        summary = 'Registration data wasn’t available, so we can’t tell how old it is.'
        actions = ['Try again in a few minutes.', 'Check the website itself with the link scanner.']
    else:
        tone, label, headline = 'safe', 'NO WARNING SIGNS', 'No warning signs found'
        summary = 'Its registration and DNS look normal. This lookup doesn’t open the website, so it isn’t a safety check of the site.'
        actions = ['To check the website itself, scan its link with the link scanner.',
                   'An old, normal domain can still host a hacked page.']

    def check(name, state, value):
        return {'name': name, 'state': state, 'result': value}
    if no_domain:
        checks = [check('Domain exists', 'bad', 'No')]
    else:
        checks = [
            check('Domain exists', 'ok', 'Yes'),
            check('Age', 'warn' if age < 30 else 'ok', age_text(age)) if age is not None else check('Age', 'na', 'Unknown'),
            check('Registration status', 'warn', 'On hold') if on_hold else check('Registration status', 'warn', 'Being deleted') if deleting
            else check('Registration status', 'ok', 'Active') if registered else check('Registration status', 'na', 'Not checked'),
            check('Expires', 'info' if expiry < 30 else 'ok', f'in {age_text(expiry)}') if expiry is not None and expiry >= 0 else check('Expires', 'na', 'Unknown'),
            check('Website address', 'info', 'Yes' if has_site else 'None'),
            check('Mail servers', 'info', 'Yes' if has_mail else 'None'),
        ]
        if registrar:
            checks.append(check('Registrar', 'info', registrar))
    share = (f'MyScanner says the domain {domain} doesn’t exist.' if no_domain
             else f'Careful: MyScanner found warning signs for the domain {domain}.' if tone == 'caution'
             else f'MyScanner found no warning signs in the registration of {domain}.' if tone == 'safe'
             else f'MyScanner couldn’t fully check the domain {domain}.')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': '', 'host': domain, 'rest': ''},
            'reasons': reasons, 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': (share.replace(domain, domain.replace('.', '[.]')) if domain else share) + ' Check domains free at https://myscanners.com'}
