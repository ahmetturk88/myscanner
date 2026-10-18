"""Plain-language summary shown at the top of a file report.

Like services/url_report_view.py: every sentence maps to an observation the
analyzers recorded, and the verdict itself is never changed. Files have no
"clean" verdict: no warning signs is still not proof, because nothing is run.
"""
from datetime import datetime

from services.url_assessment import mapping

VERDICTS = {
    'malicious': ('danger', 'DANGEROUS', 'Don’t open this file'),
    'high_risk': ('danger', 'HIGH RISK', 'Don’t open this file'),
    'suspicious': ('caution', 'BE CAREFUL', 'Be careful with this file'),
    'unknown': ('unknown', 'NOT SURE', 'We couldn’t fully check this file'),
    'not_found': ('safe', 'NO WARNING SIGNS', 'No warning signs found'),
}
HIDDEN_CODE = (('has_macros', 'Macros'), ('has_javascript', 'Script'), ('has_actions', 'Auto-run actions'))


def size_text(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return ''
    for unit, step in (('MB', 1024 * 1024), ('KB', 1024)):
        if value >= step:
            return f'{value / step:.1f} {unit}'
    return f'{int(value)} bytes'


def checked_at(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
    except ValueError:
        return ''


def plain_file_report(report):
    report = mapping(report)
    verdict = report.get('verdict') if report.get('verdict') in VERDICTS else 'unknown'
    tone, label, headline = VERDICTS[verdict]
    meta, kind = mapping(report.get('metadata')), mapping(report.get('file_type'))
    patterns, iocs = mapping(report.get('yara')), mapping(report.get('iocs'))
    provider = mapping(report.get('malwarebazaar') or mapping(report.get('hash_reputation')).get('provider'))
    name = report.get('filename') if isinstance(report.get('filename'), str) else ''
    name = name[:120]
    benign = report.get('is_likely_benign') is True
    eicar = report.get('eicar') is True
    disguise = report.get('disguised_name') if isinstance(report.get('disguised_name'), str) else ''
    matched = provider.get('status') == 'matched' and provider.get('is_malicious') is True
    signature = provider.get('signature') if isinstance(provider.get('signature'), str) and len(provider.get('signature')) <= 60 else ''
    actual = kind.get('actual_type') if isinstance(kind.get('actual_type'), str) and kind.get('actual_type') not in ('', 'unknown') else ''
    extension = name.rsplit('.', 1)[-1].lower()[:10] if '.' in name else ''
    rules = patterns.get('matched_rules') if isinstance(patterns.get('matched_rules'), list) else None
    suspicious = [s for s in meta.get('suspicious') or [] if isinstance(s, str)]
    remote = any('External Office relationship:' in s for s in suspicious)
    encrypted = meta.get('encrypted') is True or bool(meta.get('encrypted_members'))
    links = len(iocs.get('urls') or []) if isinstance(iocs.get('urls'), list) else 0
    darkweb = bool(iocs.get('onion_addresses') or iocs.get('bitcoin_addresses'))
    metadata_failed = bool(meta.get('error') or meta.get('metadata_error'))
    missing = [m for m in report.get('missing_checks') or [] if isinstance(m, str)]

    reasons = []
    def add(kind_, title, detail):
        reasons.append({'tone': kind_, 'title': title, 'detail': detail})
    if eicar:
        tone, label, headline = 'caution', 'TEST FILE', 'This is an antivirus test file'
        add('info', 'The EICAR test file', 'It is harmless by design. Security tools report it as malware on purpose, so people can check that they work.')
    if matched:
        add('bad', 'Known malware', 'MalwareBazaar, a public malware library, has this exact file' + (f', named {signature}.' if signature else '.'))
    if disguise:
        hidden = 'right-to-left' in disguise
        add('bad', 'The name hides a program' if not hidden else 'The name is reversed on purpose',
            f'It looks like a document, but it is really a program (.{extension}). This trick makes people run malware.' if not hidden
            else 'A hidden character flips how the end of the name is shown, so a program can look like a document.')
    elif kind.get('is_spoofed') is True:
        add('warn', 'The name doesn’t match the content', f'It is named .{extension} but is really a {actual.upper() or "different"} file.')
    if meta.get('has_macros') is True and not benign:
        add('warn', 'It contains macros', 'Macros are small programs inside Office files. Scams use them to install malware.')
    if meta.get('has_javascript') is True:
        add('warn', 'The PDF contains code', 'Some forms use it, but malicious PDFs use it to run code or open websites.')
    if meta.get('has_actions') is True and not benign:
        add('warn', 'It does something when opened', 'The file is set to run an action automatically as soon as it is opened.')
    if remote:
        add('warn', 'It loads content from the internet', 'The document pulls in content from an outside address when it is opened.')
    if meta.get('has_path_traversal') is True:
        add('warn', 'The archive tries to escape its folder', 'Some names inside try to write files elsewhere on your device, a known attack trick.')
    if rules and not benign:
        add('warn', 'Suspicious patterns inside', f'We found {len(rules)} pattern' + ('s' if len(rules) != 1 else '') + ' often seen in malicious files.')
    if darkweb and not benign:
        add('warn', 'Dark-web or crypto addresses inside', 'The file contains .onion or Bitcoin addresses, which are common in ransomware notes.')
    if encrypted:
        add('info', 'Password-protected contents', 'We couldn’t look inside the locked parts. Scammers lock files to hide malware from scanners.')
    if verdict == 'not_found' and not reasons:
        if provider.get('status') == 'not_found':
            add('ok', 'Not in the malware library', 'MalwareBazaar doesn’t know this exact file as malware.')
        if not metadata_failed and not any(meta.get(key) is True for key, _ in HIDDEN_CODE):
            add('ok', 'No hidden code found', 'We found no macros, scripts or automatic actions.')
        if actual and kind.get('is_spoofed') is not True:
            add('ok', 'The name matches the content', f'It really is a {actual.upper()} file.')
    if verdict == 'unknown' and missing:
        reasons.insert(0, {'tone': 'na', 'title': 'Some checks couldn’t run',
                           'detail': f'{len(missing)} check' + (' was' if len(missing) == 1 else 's were') + ' unavailable, so we can’t call it safe.'})
    if eicar:
        reasons = [r for r in reasons if r['title'] == 'The EICAR test file']  # its odd name and format are part of the test
    rank = {'na': 0, 'bad': 1, 'warn': 2, 'info': 3, 'ok': 4}
    reasons = sorted(reasons, key=lambda r: rank[r['tone']])[:4]

    if eicar:
        summary = 'It is the standard file used to test antivirus programs. It can’t harm your device.'
        actions = ['Nothing to worry about if you were testing a security tool.',
                   'Didn’t expect this file? Delete it and ask the sender why they sent it.']
    elif tone == 'danger':
        summary = ('It is a known piece of malware. Opening it could infect your device.' if matched
                   else 'It is a program disguised as a document, a common way to spread malware.' if disguise
                   else 'We found strong warning signs. Treat it as dangerous.')
        actions = ['Don’t open or run this file. Delete it.',
                   'Already opened it? Disconnect from the internet and run a full virus scan.',
                   'Tell the person who sent it. Their device or account may be infected.']
    elif tone == 'caution':
        summary = ('It is a program disguised as a document, a common way to spread malware.' if disguise
                   else 'It isn’t known malware, but it has features that malicious files often use.')
        actions = ['Don’t open it unless you expected it from someone you trust.',
                   'If you open it, don’t click “Enable content”, “Enable macros” or allow scripts.' if any(meta.get(k) is True for k, _ in HIDDEN_CODE)
                   else 'Don’t run it if it turns out to be a program.',
                   'Not sure? Ask the sender through another app or a phone call.']
        if disguise:
            actions = ['Don’t open it: it is a program pretending to be a document. Delete it.',
                       'Already opened it? Disconnect from the internet and run a full virus scan.',
                       'Tell the person who sent it. Their device or account may be infected.']
    elif tone == 'unknown':
        summary = 'Some checks couldn’t run, so we can’t say it’s safe.'
        actions = ['Only open it if you expected it from someone you trust.',
                   'Try scanning it again in a few minutes.']
    else:
        summary = 'It isn’t known malware and has no hidden code we could find. We didn’t run it, so this isn’t a guarantee.'
        actions = ['You can open it if you expected it from someone you trust.',
                   'If a document asks you to enable macros or content, don’t.']

    def check(name_, state, result):
        return {'name': name_, 'state': state, 'result': result}
    code = [labels for key, labels in HIDDEN_CODE if meta.get(key) is True and (key == 'has_javascript' or not benign)]
    checks = [
        check('Malware library', 'bad', signature or 'Known malware') if matched else
        check('Malware library', 'ok', 'Not listed') if provider.get('status') == 'not_found' else check('Malware library', 'na', 'Not checked'),
        check('Real file type', 'bad', 'Program in disguise') if disguise else
        check('Real file type', 'ok', 'Antivirus test file') if eicar else
        check('Real file type', 'warn', 'Doesn’t match name') if kind.get('is_spoofed') is True else
        check('Real file type', 'ok', actual.upper()) if actual else check('Real file type', 'na', 'Unknown'),
        check('Hidden code', 'warn', ', '.join(code)) if code else
        check('Hidden code', 'na', 'Not checked') if metadata_failed else check('Hidden code', 'ok', 'None found'),
    ]
    if rules is not None and patterns.get('status') != 'not_checked':
        checks.append(check('Suspicious patterns', 'warn', f'{len(rules)} found') if rules and not benign else check('Suspicious patterns', 'ok', 'None'))
    if meta.get('is_archive') is True or kind.get('is_archive') is True:
        payload = mapping(meta.get('payload_inspection'))
        inspected = payload.get('inspected_members')
        checks.append(check('Archive contents', 'warn', 'Password-locked') if encrypted else
                      check('Archive contents', 'warn', 'Unsafe names') if meta.get('has_path_traversal') is True else
                      check('Archive contents', 'ok', f'{inspected} files checked') if payload.get('status') in ('assessed', 'partial') and isinstance(inspected, int)
                      else check('Archive contents', 'na', 'Not inspected'))
    checks.append(check('Links inside', 'warn', 'Dark-web / crypto') if darkweb else
                  check('Links inside', 'info', f'{links} link' + ('s' if links != 1 else '')) if links else check('Links inside', 'ok', 'None'))
    counts = {state: sum(c['state'] == state for c in checks) for state in ('bad', 'warn', 'ok', 'na')}
    tally = ' · '.join(text for text in (f"{counts['bad']} bad" if counts['bad'] else '',
                                         f"{counts['warn']} warning" + ('s' if counts['warn'] != 1 else '') if counts['warn'] else '',
                                         f"{counts['ok']} fine" if counts['ok'] else '',
                                         f"{counts['na']} not checked" if counts['na'] else '') if text)
    shown = name or 'this file'
    share = (f'Warning: MyScanner rates the file “{shown}” as dangerous. Don’t open it.' if tone == 'danger'
             else f'MyScanner says “{shown}” is the EICAR antivirus test file. It is harmless.' if eicar
             else f'Careful: MyScanner found warning signs in the file “{shown}”.' if tone == 'caution'
             else f'MyScanner found no warning signs in the file “{shown}”.' if tone == 'safe'
             else f'MyScanner couldn’t fully check the file “{shown}”.')
    size = size_text(report.get('file_size_bytes') if report.get('file_size_bytes') is not None else report.get('file_size'))
    when = checked_at(report.get('scanned_at') or report.get('analyzed_at'))
    return {'tone': tone, 'label': label, 'headline': headline, 'summary': summary,
            'url': {'prefix': '', 'host': name or 'Unnamed file', 'rest': f' · {size}' if size else ''},
            'reasons': reasons, 'actions': actions, 'checks': checks, 'tally': tally,
            'checked': f'Checked {when} UTC' if when else '',
            'share_text': share + ' Check files free at https://myscanners.com'}
