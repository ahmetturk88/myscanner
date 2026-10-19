"""Plain-language summary shown at the top of an IP address report.

Built only from AbuseIPDB's community reports and the network metadata the
lookup returned; the verdict-free lookup gains no new conclusions here. An IP
is often shared, so reports describe the address, not one person.
"""
from services.url_assessment import mapping
from services.url_report_view import tally


def number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def text(value, limit=80):
    return value[:limit] if isinstance(value, str) and value.strip() else ''


def plain_ip_report(result):
    result = mapping(result)
    reputation = mapping(result.get('reputation'))
    status = reputation.get('status')
    checked = status in ('matched', 'not_found')
    score, reports = number(reputation.get('score')), number(reputation.get('reports'))
    reporters = number(reputation.get('distinct_reporters'))
    whitelisted = reputation.get('is_whitelisted') is True
    discounted = status == 'matched' and (whitelisted or score == 0)
    tor = reputation.get('is_tor') is True
    usage = text(reputation.get('usage_type'))
    owner = text(result.get('org')) or text(result.get('isp'))
    asn = number(result.get('asn'))
    country = text(result.get('country'), 60)
    ip = text(result.get('ip'), 64)
    hosting = 'hosting' in usage.lower() or 'data center' in usage.lower()

    if not checked:
        tone, label, headline = 'unknown', 'NOT SURE', 'We couldn’t check this address’s reputation'
    elif status == 'matched' and not discounted and score >= 50:
        tone, label, headline = 'danger', 'BAD REPUTATION', 'This address is often reported for abuse'
    elif (status == 'matched' and not discounted) or tor:
        tone, label, headline = 'caution', 'BE CAREFUL', 'Be careful with this address'
    else:
        tone, label, headline = 'safe', 'NO WARNING SIGNS', 'No warning signs found'

    reasons = []
    def add(kind, title, detail):
        reasons.append({'tone': kind, 'title': title, 'detail': detail})
    if not checked:
        add('na', 'Reputation couldn’t be checked', 'The abuse-report service didn’t answer, so we can’t say whether this address is trusted.')
    elif status == 'matched' and not discounted:
        add('bad' if score >= 50 else 'warn', f'Reported for abuse {reports} time' + ('' if reports == 1 else 's'),
            'AbuseIPDB users reported it in the last 90 days' + (f', from {reporters} different reporters' if reporters else '')
            + f'. Their confidence that it is abusive: {score}/100.')
    elif discounted:
        add('info', 'Reports, but discounted', f'It has {reports} report' + ('' if reports == 1 else 's') + ' in 90 days, but AbuseIPDB treats them as noise. '
            'That is typical for big shared services such as public DNS.')
    else:
        add('ok', 'No abuse reports', 'Nobody reported this address to AbuseIPDB in the last 90 days.')
    if tor:
        add('warn', 'Part of the Tor network', 'Tor hides who is really behind a connection. Many people use it for privacy, and attackers use it too.')
    if hosting:
        add('info', 'A server, not a home connection', 'It belongs to a hosting or data-center network. Websites, VPNs and bots use these.')
    if owner:
        add('info', f'Run by {owner}', (f'Network AS{asn}' if asn else 'Network owner') + (f' in {country}' if country else '') + '. The location is approximate and never points to a person.')
    rank = {'na': 0, 'bad': 1, 'warn': 2, 'ok': 3, 'info': 4}
    reasons = sorted(reasons, key=lambda r: rank[r['tone']])[:4]

    if tone == 'danger':
        summary = 'Many people reported it for attacks, spam or scams in the last 90 days.'
        actions = ['If it is contacting your server or accounts, block it.',
                   'Don’t trust logins, messages or payments coming from it.',
                   'Addresses can be shared or reassigned. Check your own logs before blaming one person.']
    elif tone == 'caution':
        summary = ('It belongs to the Tor network, which hides who is behind a connection.' if tor and not (status == 'matched' and not discounted)
                   else 'It has some abuse reports in the last 90 days.')
        actions = ['Watch activity from this address and block it if it misbehaves.',
                   'Don’t trust it with logins or payments without another check.']
    elif tone == 'unknown':
        summary = 'The reputation source didn’t answer, so we only have network details.'
        actions = ['Try checking it again in a few minutes.']
    else:
        summary = 'It has no abuse reports that count against it in the last 90 days.'
        actions = ['No action needed based on its reputation.',
                   'A clean record isn’t a guarantee: addresses change hands and can be shared.']

    def check(name, state, value):
        return {'name': name, 'state': state, 'result': value}
    checks = [
        check('Abuse reports', 'na', 'Not checked') if not checked else
        check('Abuse reports', 'ok', 'None') if status == 'not_found' else
        check('Abuse reports', 'info' if discounted else 'bad' if score >= 50 else 'warn', f'{reports} in 90 days'),
        check('Abuse confidence', 'na', 'Not checked') if not checked else
        check('Abuse confidence', 'ok' if discounted or score == 0 else 'bad' if score >= 50 else 'warn', f'{score}/100'),
        check('Tor network', 'warn', 'Yes') if tor else check('Tor network', 'ok', 'No') if reputation.get('is_tor') is False else check('Tor network', 'na', 'Unknown'),
    ]
    if usage:
        checks.append(check('Network type', 'info', usage))
    if owner:
        checks.append(check('Network owner', 'info', owner))
    if country:
        checks.append(check('Approximate location', 'info', country))
    share = (f'Warning: MyScanner shows that the IP address {ip} is often reported for abuse.' if tone == 'danger'
             else f'Careful: MyScanner found warning signs for the IP address {ip}.' if tone == 'caution'
             else f'MyScanner found no abuse reports against the IP address {ip}.' if tone == 'safe'
             else f'MyScanner couldn’t check the reputation of the IP address {ip}.')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': '', 'host': ip, 'rest': ' · IPv6' if result.get('ip_version') == 6 else ' · IPv4' if ip else ''},
            'reasons': reasons, 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': share + ' Check addresses free at https://myscanners.com'}
