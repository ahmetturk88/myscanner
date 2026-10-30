"""Plain-language summaries for the password, certificate (SSL) and website/QR checks.

Same rules as the other report summaries: every sentence maps to a recorded
observation and verdicts are never changed. The password summary never echoes
the password, and is never shareable.
"""
from urllib.parse import urlsplit

from services.url_assessment import mapping
from services.url_report_view import age_text, defang, tally, url_parts

PATTERNS = {
    'dictionary': ('It uses common words or names', 'Attackers try dictionary words and well-known passwords first.'),
    'spatial': ('It follows a keyboard path', 'Patterns like “qwerty” or “asdf” are among the first guesses.'),
    'repeat': ('It repeats characters', 'Repeated letters or blocks add length without making it harder to guess.'),
    'sequence': ('It contains a sequence', 'Runs like “abc” or “123” are easy to predict.'),
    'regex': ('It contains a familiar pattern', 'Things like a year are among the first guesses.'),
    'date': ('It contains a date', 'Birthdays and other dates are easy to guess.'),
}


def check(name, state, value):
    return {'name': name, 'state': state, 'result': value}


def reason(kind, title, detail):
    return {'tone': kind, 'title': title, 'detail': detail}


def ordered(reasons, limit=4):
    rank = {'na': 0, 'bad': 1, 'warn': 2, 'ok': 3, 'info': 4}
    return sorted(reasons, key=lambda r: rank[r['tone']])[:limit]


def plain_password_report(result):
    result = mapping(result)
    local, pwned = mapping(result.get('local_strength')), mapping(result.get('pwned'))
    length = result.get('password_length') if isinstance(result.get('password_length'), int) else None
    rank = local.get('estimator_rank') if isinstance(local.get('estimator_rank'), int) else None
    estimated = local.get('status') == 'completed' and rank is not None
    exposed, count = pwned.get('status') == 'found', pwned.get('count') if isinstance(pwned.get('count'), int) else None
    leak_checked = pwned.get('status') in ('found', 'not_found')
    patterns = [f.get('code') for f in local.get('findings') or [] if isinstance(f, dict) and f.get('code') in PATTERNS]

    reasons = []
    if exposed:
        reasons.append(reason('bad', 'Found in data leaks', (f'It appears {count:,} times' if count else 'It appears') + ' in passwords stolen from hacked websites. Attackers try these first.'))
    if estimated and rank < 3:
        reasons.append(reason('warn', 'Easy to guess', f'A password-cracking model rates it {local.get("strength", "weak").lower()}.'))
    for code in patterns:
        reasons.append(reason('warn' if rank is not None and rank < 3 else 'info', *PATTERNS[code]))
    if estimated and rank >= 3:
        reasons.append(reason('ok', 'Hard to guess', f'A password-cracking model rates it {local.get("strength", "strong").lower()}.'))
    if pwned.get('status') == 'not_found':
        reasons.append(reason('ok', 'Not found in known leaks', 'It isn’t in the Have I Been Pwned list of leaked passwords.'))
    elif not leak_checked:
        reasons.append(reason('na', 'Leaks weren’t checked', 'Turn on the leak check to see whether it was stolen in a data breach.'))
    if not estimated:
        reasons.insert(0, reason('na', 'Strength couldn’t be measured', 'The strength estimator wasn’t available.'))

    if exposed:
        tone, label, headline = 'danger', 'LEAKED', 'Stop using this password'
        summary = 'It has been stolen in data breaches, so attackers already know it.'
        actions = ['Change it on every account where you use it, starting with email and banking.',
                   'Don’t just add a character: pick a completely new password.',
                   'Turn on two-step login wherever you can.']
    elif estimated and rank < 3:
        tone, label, headline = 'caution', 'WEAK', 'This password is easy to guess'
        summary = 'Attackers’ tools would likely guess it quickly.'
        actions = ['Use a password manager to create a long random password.',
                   'Or use four or more random words, not a phrase you know.',
                   'Use a different password for every account.']
    elif estimated:
        tone, label, headline = 'safe', 'STRONG', 'This password is hard to guess'
        summary = ('It isn’t in known leaks and would be hard to guess.' if pwned.get('status') == 'not_found'
                   else 'It would be hard to guess. We didn’t check whether it has leaked.')
        actions = ['Use it for one account only.', 'Turn on two-step login for extra protection.']
    else:
        tone, label, headline = 'unknown', 'NOT SURE', 'We couldn’t measure this password'
        summary = 'The strength check wasn’t available.'
        actions = ['Try again in a few minutes.']

    checks = [
        check('Strength', 'na', 'Not measured') if not estimated else check('Strength', 'warn' if rank < 3 else 'ok', str(local.get('strength'))),
        check('Data leaks', 'bad', f'Found {count:,} times' if count else 'Found') if exposed else
        check('Data leaks', 'ok', 'Not found') if pwned.get('status') == 'not_found' else check('Data leaks', 'na', 'Not checked'),
        check('Predictable patterns', 'warn' if rank is not None and rank < 3 else 'info', str(len(patterns))) if patterns else check('Predictable patterns', 'ok', 'None'),
    ]
    if length is not None:
        checks.append(check('Length', 'warn' if length < 12 else 'ok', f'{length} characters'))
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': '', 'host': 'Your password', 'rest': f' · {length} characters' if length else ''},
            'reasons': ordered(reasons), 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': ''}


# Each verification failure gets its own plain explanation (keys are the analyzer's reason codes).
SSL_FAILURES = {
    'expired': ('Certificate has expired', 'Browsers block the page with a warning until the owner renews it.'),
    'not_yet_valid': ('Certificate isn’t valid yet', 'Its start date is in the future, often a wrong server clock. Browsers will warn.'),
    'self_signed': ('Self-signed certificate', 'The site vouched for itself instead of a trusted authority, so anyone could have made it.'),
    'self_signed_chain': ('Signed by an authority browsers don’t trust', 'The chain ends at a private authority that isn’t in browsers’ trusted list.'),
    'untrusted_issuer': ('Signed by an unknown authority', 'The certificate’s issuer couldn’t be found or isn’t trusted by browsers.'),
    'incomplete_chain': ('The certificate chain is incomplete', 'The server didn’t send the in-between certificates, so many browsers and apps can’t verify it.'),
    'revoked': ('Certificate was cancelled', 'Its issuer revoked it, usually because it was compromised or issued by mistake.'),
    'hostname_mismatch': ('Certificate is for another site', 'It was issued for a different name, which is what a redirect or interception looks like.'),
}


def plain_ssl_report(result):
    result = mapping(result)
    host = result.get('domain') if isinstance(result.get('domain'), str) else ''
    valid = result.get('valid')
    states = {c.get('name'): c.get('status') for c in result.get('checks') or [] if isinstance(c, dict)}
    days = result.get('days_remaining') if isinstance(result.get('days_remaining'), int) else None
    version = result.get('tls_version') if isinstance(result.get('tls_version'), str) else ''
    issuer = result.get('issuer') if isinstance(result.get('issuer'), str) else ''
    code = result.get('reason_code')
    failures = [f for f in result.get('findings') or [] if isinstance(f, dict) and f.get('severity') == 'danger']

    reasons = []
    if valid is False:
        title, detail = SSL_FAILURES.get(code, (failures[0].get('title') if failures and isinstance(failures[0].get('title'), str) else 'Certificate verification failed',
                                                'Browsers will show a security warning. Someone could read or change what you send.'))
        if code == 'expired' and days is not None and days < 0:
            detail = f'It ran out {age_text(-days)} ago. ' + detail
        reasons.append(reason('bad', title, detail))
    elif valid is True:
        reasons.append(reason('ok', 'Valid certificate', f'Issued by {issuer[:60]} for this exact name.' if issuer and issuer != 'Not provided' else 'Issued by a trusted authority for this exact name.'))
        if days is not None and days < 14:
            reasons.append(reason('info', 'It expires soon', f'In {days} day' + ('' if days == 1 else 's') + '. It may renew automatically.'))
        if version and version not in ('TLSv1.2', 'TLSv1.3'):
            reasons.append(reason('warn', 'An old encryption version', f'The connection used {version}. Modern sites use TLS 1.2 or 1.3.'))
        elif version:
            reasons.append(reason('ok', 'Modern encryption', f'The connection used {version.replace("TLSv", "TLS ")}.'))
    else:
        reasons.append(reason('na', 'Couldn’t connect securely', 'The site didn’t answer on HTTPS, so we couldn’t see its certificate.'
                              if code != 'dns_unavailable' else 'The name doesn’t resolve, so there was nothing to connect to.'))
    if valid is True:
        reasons.append(reason('info', 'This checks the connection only', 'A valid certificate means the connection is private. It doesn’t mean the site is honest: scam sites have them too.'))

    if valid is False:
        # Browsers block the page behind a full-screen warning, so this is red (v10).
        tone, label, headline = 'danger', 'NOT SECURE', 'This site’s connection isn’t secure'
        summary = 'Its certificate failed verification, so browsers will warn visitors or block the page.'
        actions = ['Don’t enter passwords or payment details while the browser shows a warning.',
                   'If it is your site, renew or reinstall the certificate.']
    elif valid is True and version and version not in ('TLSv1.2', 'TLSv1.3'):
        tone, label, headline = 'caution', 'OUTDATED', 'The connection uses old encryption'
        summary = 'The certificate is valid, but the connection used an outdated protocol.'
        actions = ['If it is your site, turn on TLS 1.2 and 1.3 and turn off older versions.']
    elif valid is True:
        tone, label, headline = 'safe', 'SECURE CONNECTION', 'The connection is private'
        summary = 'The certificate is valid. This says nothing about whether the site itself is honest.'
        actions = ['To check whether the site is a scam, scan its link with the link scanner.']
    else:
        tone, label, headline = 'unknown', 'NOT SURE', 'We couldn’t check the certificate'
        summary = 'We couldn’t make a secure connection to see the certificate.'
        actions = ['Check the address and try again in a few minutes.']

    def state(name, ok, bad='Failed'):
        status = states.get(name)
        # After a failed verification, an unanswered check was cut short, not skipped.
        missing = check(ok[0], 'na', 'Couldn’t confirm' if valid is False else 'Not checked')
        return check(ok[0], 'ok', ok[1]) if status == 'completed' else check(ok[0], 'bad', bad) if status == 'invalid' else missing
    checks = [state('Chain trust', ('Trusted issuer', 'Yes'), 'No'),
              state('Hostname identity', ('Matches the name', 'Yes'), 'No')]
    # One row for the validity period: the date says more than a separate "in date" yes/no.
    if days is not None and valid is not None:
        checks.append(check('Valid until', 'bad' if days < 0 else 'info' if days < 14 else 'ok',
                            f'Expired {age_text(-days)} ago' if days < 0 else f'{days} day' + ('' if days == 1 else 's') + ' left' if days < 60 else f'{age_text(days)} left'))
    else:
        checks.append(state('Validity period', ('Valid until', 'In date'), 'Expired or not yet valid'))
    if version:
        checks.append(check('Encryption', 'ok' if version in ('TLSv1.2', 'TLSv1.3') else 'warn', version.replace('TLSv', 'TLS ')))
    share = (f'Careful: MyScanner says the connection to {defang(host)} isn’t secure.' if tone in ('caution', 'danger')
             else f'MyScanner verified the certificate of {defang(host)}.' if tone == 'safe'
             else f'MyScanner couldn’t check the certificate of {defang(host)}.')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': 'https://', 'host': host, 'rest': ''},
            'reasons': ordered(reasons), 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': share + ' Check sites free at https://myscanners.com'}


WEB_FINDINGS = {
    'external_password_form': ('warn', 'It sends your password to another site', 'The login form posts to a different address than the page you are on.'),
    'password_http': ('warn', 'It asks for a password without encryption', 'The login form isn’t protected by HTTPS, so others could read it.'),
    'https_downgrade': ('warn', 'It drops the secure connection', 'It redirects from HTTPS to plain HTTP.'),
    'invalid_certificate': ('warn', 'Its certificate is invalid', 'Browsers will show a security warning on this site.'),
    'tls_http_failure': ('warn', 'The secure connection failed', 'We couldn’t verify its HTTPS connection.'),
    'unencrypted_entry': ('warn', 'The link isn’t encrypted', 'It starts with http://, so the first request isn’t private.'),
    'shortener': ('info', 'A short link', 'Short links hide where they lead; we followed it.'),
    'host_change': ('info', 'It lands on a different site', 'The link redirects to another address.'),
    'redirect_parameter': ('info', 'It carries another address inside', 'The link contains a destination address, a trick some scams use.'),
    'idn': ('info', 'Unusual characters in the name', 'International characters can imitate real site names.'),
    'unverified_phishing_report': ('info', 'An unconfirmed scam report', 'Someone reported it as phishing; reviewers haven’t confirmed it.'),
    # site-trust-v1: the URL scanner's evidence, for websites and QR links
    'web_risk_listed': ('bad', 'Google lists it as dangerous', 'Google Web Risk reports this address for phishing or malware.'),
    'gambling_site': ('warn', 'An online gambling site', 'Casino or betting content. We didn’t verify a licence; unlicensed betting is illegal in Turkey and deposits are often never paid out.'),
    'prize_offer': ('warn', 'It promises a prize or a gift', 'Prize and free-gift pages are a common way to collect card details.'),
    'fake_comments': ('warn', 'It shows fake comments', 'The page imitates social media comments to look trustworthy.'),
    'collects_card': ('warn', 'It asks for a card or phone number', 'A new or copied site asking for these details is a common scam.'),
}
# site-posture-v1 findings carry their own sentences (software versions, cookie and host names); see i18n_tr.
POSTURE_FINDINGS = {'script_lookalike', 'old_software', 'mixed_content', 'cookie_flags', 'mail_spoofable'}
# Findings whose sentence names the brand or the age, so it comes from the evidence, not from this table.
WEB_TRUST_FINDINGS = {'lookalike_brand', 'new_domain'}


def plain_web_report(result, source='link'):
    """For the website check and for links read from QR codes (source='qr')."""
    result = mapping(result)
    url = result.get('url') if isinstance(result.get('url'), str) else ''
    verdict = result.get('verdict')
    provider = mapping(result.get('provider'))
    tls = mapping(result.get('tls'))
    http = mapping(result.get('http'))
    findings = [f for f in result.get('findings') or [] if isinstance(f, dict) and f.get('code') in WEB_FINDINGS]
    every = [f for f in result.get('findings') or [] if isinstance(f, dict)]
    codes = {f.get('code') for f in every}
    trust = mapping(result.get('trust'))
    risk = mapping(trust.get('web_risk'))
    brand = trust.get('brand') if isinstance(trust.get('brand'), str) else ''
    age = mapping(trust.get('domain_age'))
    age_days = age.get('age_days') if isinstance(age.get('age_days'), int) and not isinstance(age.get('age_days'), bool) else None
    new_finding = next((f for f in every if f.get('code') == 'new_domain'), None)
    hops = len(http.get('chain')) - 1 if isinstance(http.get('chain'), list) and http.get('chain') else None
    final = http.get('final_url') if isinstance(http.get('final_url'), str) else ''
    host = (urlsplit(url).hostname or '') if url else ''
    final_host = (urlsplit(final).hostname or '') if final else ''

    reasons = []
    if verdict == 'malicious' and 'web_risk_listed' not in codes:
        reasons.append(reason('bad', 'Listed as a threat', 'A threat-intelligence source reports this link as malicious.'))
    if brand and 'lookalike_brand' in codes:
        reasons.append(reason('warn', f'The address copies {brand}', f'It uses the name {brand}, but it isn’t one of {brand}’s sites.'))
    if new_finding and age_days is not None:
        reasons.append(reason('warn' if new_finding.get('severity') == 'warning' else 'info', 'The site is brand new',
                              f'Its domain was registered {age_days} days ago. Scam shops and fake login pages rarely live longer than a few weeks.'))
    crawl = mapping(result.get('crawl'))
    pages_read = crawl.get('pages_read') if isinstance(crawl.get('pages_read'), int) and not isinstance(crawl.get('pages_read'), bool) else 0
    for item in every:
        # site-crawl-v1 findings carry their own sentences (with counts and names); see i18n_tr.
        code = str(item.get('code', ''))
        if code.startswith(('crawl_', 'fake_shop')) or code in POSTURE_FINDINGS:
            if not (isinstance(item.get('title'), str) and isinstance(item.get('detail'), str)):
                continue
            kind = 'bad' if code in ('crawl_page_listed', 'crawl_malware_download') else 'warn' if item.get('severity') == 'warning' else 'info'
            reasons.append(reason(kind, item['title'], item['detail']))
    for item in findings:
        kind, title, detail = WEB_FINDINGS[item['code']]
        reasons.append(reason(kind, title, detail + (f' It ends at {final_host}.' if item['code'] == 'host_change' and final_host else '')))
    if verdict == 'clean':
        reasons.append(reason('ok', 'No warning signs found', 'The connection, redirects and page form checks found nothing suspicious.'))
    if verdict == 'unknown' and result.get('assessment_status') != 'completed':
        reasons.insert(0, reason('na', 'Some checks couldn’t run', 'Not every check finished, so we can’t call it safe.'))

    opening = 'this QR code’s link' if source == 'qr' else 'this website' if source == 'site' else 'this link'
    if verdict == 'malicious':
        tone, label, headline = 'danger', 'DANGEROUS', 'Don’t open this link' if source != 'site' else 'Don’t use this website'
        summary = 'Google lists it as a phishing or malware site.' if risk.get('status') == 'matched' else 'A threat source reports it as malicious.'
        actions = ['Don’t open it or enter any information on it.',
                   'If it is a QR code in a public place, tell the business: stickers over real codes are a common scam.' if source == 'qr'
                   else 'Tell the person who sent it.']
    elif verdict == 'suspicious':
        tone, label, headline = 'caution', 'BE CAREFUL', f'Be careful with {opening}'
        summary = (f'It copies {brand}’s name but isn’t its site.' if brand and 'lookalike_brand' in codes
                   else 'We found warning signs on the page or its connection.')
        actions = ['Don’t enter passwords or payment details on it.',
                   'For payments, type the company’s address yourself instead of using the QR code.' if source == 'qr'
                   else 'Open important sites by typing the address yourself.']
    elif verdict == 'clean':
        tone, label, headline = 'safe', 'NO WARNING SIGNS', 'No warning signs found'
        summary = (f'We read {pages_read} of its pages and checked the sites they link to; nothing looked suspicious. This isn’t a guarantee.'
                   if pages_read > 1 else 'Its connection and page looked normal. This isn’t a guarantee.')
        actions = ['Check that the address shown is the one you expected before signing in or paying.']
    else:
        tone, label, headline = 'unknown', 'NOT SURE', f'We couldn’t fully check {opening}'
        summary = 'Not every check finished, so we can’t say it is safe.'
        actions = ['Check the address carefully before entering anything.', 'Try again in a few minutes.']

    tls_status = tls.get('status')
    checks = [
        check('Threat lists', 'bad', 'Listed') if verdict == 'malicious' else
        check('Threat lists', 'info', 'Unconfirmed report') if 'unverified_phishing_report' in codes else
        check('Threat lists', 'ok', 'Not listed') if provider.get('status') in ('completed', 'partial') or risk.get('status') == 'not_found' else
        check('Threat lists', 'na', 'Not checked') if risk.get('status') == 'unavailable' else
        check('Threat lists', 'na', 'Not requested') if provider.get('status') == 'not_requested' else check('Threat lists', 'na', 'Not checked'),
        check('Secure connection', 'ok', 'Valid HTTPS') if tls_status == 'completed' and not codes & {'https_downgrade', 'unencrypted_entry'} else
        check('Secure connection', 'warn', 'Not secure') if tls_status == 'invalid' or codes & {'https_downgrade', 'unencrypted_entry', 'invalid_certificate', 'tls_http_failure'} else
        check('Secure connection', 'na', 'Not checked'),
        check('Password forms', 'warn', 'Unsafe') if codes & {'external_password_form', 'password_http'} else check('Password forms', 'ok', 'Nothing unsafe'),
        check('Redirects', 'info', f'{hops}') if hops else check('Redirects', 'ok', 'None') if hops == 0 else check('Redirects', 'na', 'Not checked'),
    ]
    if crawl.get('policy') == 'site-crawl-v1' and crawl.get('status') != 'not_performed':
        downloads = [d for d in crawl.get('downloads') or [] if isinstance(d, dict)]
        shop = mapping(crawl.get('shop'))
        found = crawl.get('downloads_found') if isinstance(crawl.get('downloads_found'), int) else len(downloads)
        checks += [
            check('Pages read', 'ok' if pages_read else 'na', f'{pages_read}' if pages_read else 'Not checked'),
            check('Links to other sites', 'bad', 'Dangerous') if crawl.get('listed_links') else
            check('Links to other sites', 'warn', 'Look-alike') if crawl.get('lookalike_links') else
            check('Links to other sites', 'info', 'Betting') if crawl.get('betting_links') else
            check('Links to other sites', 'ok', f'{crawl.get("external_sites", 0)} sites') if crawl.get('external_sites') else
            check('Links to other sites', 'ok', 'None'),
            check('Downloads', 'bad', 'Malware') if 'crawl_malware_download' in codes else
            check('Downloads', 'info', f'{found} files') if found else check('Downloads', 'ok', 'None'),
        ]
        if shop.get('not_judged'):
            checks.append(check('Online shop', 'na', 'Foreign version'))
        elif shop:
            have = 5 - len(shop.get('missing') or [])
            checks.append(check('Online shop', 'warn', 'Fake shop signs') if shop.get('fake_signs') else
                          check('Online shop', 'ok' if have >= 3 else 'info', f'{have} of 5 details'))
    posture = mapping(result.get('posture'))
    if posture.get('policy') == 'site-posture-v1' and posture.get('status') != 'not_performed':
        place, mail = mapping(posture.get('hosting')), mapping(posture.get('mail'))
        where = ', '.join(str(v) for v in (place.get('country'), place.get('network')) if isinstance(v, str) and v)
        software = [t for t in posture.get('technology') or [] if isinstance(t, dict) and t.get('source') != 'Server']
        outside = posture.get('outside_scripts') if isinstance(posture.get('outside_scripts'), list) else []
        checks += [
            check('Hosted in', 'info', where[:60]) if place.get('status') == 'completed' and where else check('Hosted in', 'na', 'Not checked'),
            check('Email in its name', 'ok', 'Protected') if mail.get('protected') is True else
            check('Email in its name', 'info', 'Not protected') if mail.get('status') == 'completed' else check('Email in its name', 'na', 'Not checked'),
            check('Software', 'info', 'Old version') if posture.get('old_software') else
            check('Software', 'ok', str(software[0].get('name'))[:40]) if software else check('Software', 'na', 'Not shown'),
            check('Scripts from other sites', 'warn', 'Copied address') if posture.get('copied_scripts') else
            check('Scripts from other sites', 'ok', f'{len(outside)} sites') if outside else check('Scripts from other sites', 'ok', 'None'),
        ]
        if 'crawl' in result and mapping(result.get('crawl')).get('pages_read'):
            checks.append(check('Privacy notice', 'ok', 'Found') if mapping(result.get('crawl')).get('privacy_notice') else check('Privacy notice', 'info', 'Not found'))
    if trust:
        scam = codes & {'gambling_site', 'prize_offer', 'fake_comments', 'collects_card'}
        checks += [
            check('Copies a brand’s name', 'warn', brand) if brand else check('Copies a brand’s name', 'ok', 'No'),
            check('Domain age', 'warn' if new_finding and new_finding.get('severity') == 'warning' else 'info' if new_finding else 'ok',
                  f'{age_days} days') if age_days is not None and age_days < 365 else
            check('Domain age', 'ok', f'{age_days // 365} years' if age_days >= 730 else '1 year') if age_days is not None else
            check('Domain age', 'na', 'Not published'),
            check('Page content', 'warn', 'Scam signs') if scam else
            check('Page content', 'ok', 'Nothing suspicious') if mapping(result.get('content')).get('status') == 'completed' else
            check('Page content', 'na', 'Not checked'),
        ]
    share = (f'Warning: MyScanner rates this link as dangerous: {defang(url)}. Don’t open it.' if tone == 'danger'
             else f'Careful: MyScanner found warning signs on this link: {defang(url)}.' if tone == 'caution'
             else f'MyScanner found no warning signs on this link: {defang(url)}.' if tone == 'safe'
             else f'MyScanner couldn’t fully check this link: {defang(url)}.')
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': url_parts(url) if url else {'prefix': '', 'host': host, 'rest': ''},
            'reasons': ordered(reasons), 'actions': actions, 'checks': checks, 'tally': tally(checks),
            'share_text': share + ' Check links free at https://myscanners.com'}


def plain_subdomain_report(result):
    """Discovery lists hostnames; it is not a safety verdict, so the tone is informational."""
    result = mapping(result)
    domain = result.get('domain') if isinstance(result.get('domain'), str) else ''
    count = lambda key: result.get(key) if isinstance(result.get(key), int) and not isinstance(result.get(key), bool) else 0
    found, active, redirects = count('total_found'), count('active_count'), count('redirect_count')
    errors, checked = count('dns_error_count'), count('total_checked')
    groups = mapping(result.get('subdomains'))
    dns_only = len(groups.get('dns_only') or []) if isinstance(groups.get('dns_only'), list) else 0
    http_errors = len(groups.get('http_error') or []) if isinstance(groups.get('http_error'), list) else 0
    wildcard = mapping(result.get('wildcard')).get('detected') is True
    sources = [s for s in result.get('sources') or [] if isinstance(s, dict)]
    ct = next((s for s in sources if 'Certificate' in str(s.get('name'))), {})
    partial = result.get('assessment_status') != 'completed'

    reasons = []
    if found:
        reasons.append(reason('info', f'{found} subdomain' + ('' if found == 1 else 's') + ' found',
                              f'{active} answer as websites' + (f', {redirects} redirect elsewhere' if redirects else '') + '.'))
    else:
        reasons.append(reason('info', 'No subdomains found', f'None of the {checked} names we tried exist.'))
    if wildcard:
        reasons.append(reason('warn', 'Every name seems to exist', 'The domain answers for any made-up name (a wildcard), so some results may not be real separate sites.'))
    if http_errors:
        reasons.append(reason('info', f'{http_errors} show' + ('s' if http_errors == 1 else '') + ' an error page', 'Error pages can mean forgotten or broken services.'))
    if partial:
        reasons.insert(0, reason('na', 'This is a sample', 'We check a limited set of likely names, so there may be more subdomains.'))

    actions = ['Check any subdomain you don’t recognise with the “Inspect URL” button.',
               'If this is your domain, remove subdomains you no longer use: forgotten ones are a common way in for attackers.']
    if wildcard:
        actions.insert(0, 'Treat the list with care: the wildcard makes made-up names look real.')
    checks = [check('Subdomains found', 'info', str(found)), check('Answer as websites', 'info', str(active))]
    if redirects:
        checks.append(check('Redirect elsewhere', 'info', str(redirects)))
    if dns_only:
        checks.append(check('Name only, no website', 'info', str(dns_only)))
    checks.append(check('Wildcard', 'warn', 'Yes') if wildcard else check('Wildcard', 'ok', 'No'))
    checks.append(check('Certificate history', 'ok', 'Used') if ct.get('status') == 'completed'
                  else check('Certificate history', 'na', 'Not requested' if ct.get('status') == 'not_requested' else 'Not available'))
    if errors:
        checks.append(check('Lookups that failed', 'na', str(errors)))
    return {'tone': 'info', 'label': 'DISCOVERY', 'headline': f'{found} subdomain' + ('' if found == 1 else 's') + ' found',
            'summary': 'This lists names under the domain. It is not a safety check of each one; inspect the ones you don’t recognise.',
            'url': {'prefix': '', 'host': domain, 'rest': ''},
            'why_title': 'What we found',
            'reasons': ordered(reasons), 'actions': actions, 'checks': checks, 'tally': f'{checked} names checked' if checked else '',
            'share_text': ''}
