"""Benchmark every non-URL tool against inputs whose answer is known in advance.

Calls the same services the website and app use; saves nothing and uses no quota.
Run it inside the worker container, which has the scanners' network access:
    dc exec worker python scripts/tools_check.py
    dc exec worker python scripts/tools_check.py --only ssl,email
    dc exec worker python scripts/tools_check.py --live    # also IPs attacking servers right now
"""
import argparse
import concurrent.futures
import logging
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NO_DOMAIN = 'myscanner-nonexistent-7f3a9c.com'
# The EICAR antivirus test string, assembled so this file is not itself flagged.
EICAR = ''.join(['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*']).encode()
def pdf_with_javascript():
    """A valid one-page PDF that runs JavaScript when opened."""
    import io
    from pypdf import PdfWriter
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        writer.add_js("app.alert('MyScanner test');")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def run(tool, value):
    """The service call behind each tool's endpoint or worker task."""
    if tool == 'email':
        from services.email_checker import AdvancedEmailChecker
        return AdvancedEmailChecker(None).check_all(value)
    if tool == 'password':
        from services.password_analyzer import PasswordAnalyzer
        analyzer = PasswordAnalyzer()
        try:
            return analyzer.comprehensive_analysis(value, check_breaches=True)
        finally:
            analyzer.close()
    if tool == 'ip':
        from services.ip_analyzer import IPAnalyzer
        from services.provider_credentials import abuseipdb_key
        return IPAnalyzer().analyze_ip(value, abuseipdb_key())
    if tool == 'domain':
        from services.domain_analyzer import DomainAnalyzer
        return DomainAnalyzer().analyze_domain(value)
    if tool == 'ssl':
        from services.ssl_analyzer import SSLAnalyzer
        return SSLAnalyzer().analyze_certificate(value)
    if tool == 'subdomain':
        from services.subdomain_finder import SubdomainFinder
        return SubdomainFinder().find_subdomains(value, include_ct=True)
    if tool == 'site':
        from services.site_analyzer import SiteAnalyzer
        return SiteAnalyzer().comprehensive_analysis(value, include_provider=True)
    if tool == 'file':
        from services.file_deep_analyzer import FileDeepAnalyzer
        name, content = value
        return FileDeepAnalyzer(use_exiftool=True).comprehensive_analysis(content, name)
    raise ValueError(tool)


def one_of(field, ok, warn=()):
    """PASS when result[field] is in ok, WARN when in warn, otherwise FAIL."""
    def check(result):
        value = result.get(field)
        return ('PASS' if value in ok else 'WARN' if value in warn else 'FAIL'), f'{field}={value}'
    return check


def refused(result):
    return ('PASS' if result.get('error') or result.get('valid') is False else 'FAIL'), \
        f"error={bool(result.get('error'))} valid={result.get('valid')}"


def password_exposed(result):
    breach = (result.get('pwned') or {}).get('status')
    grade = 'PASS' if result.get('verdict') == 'exposed' else 'WARN' if breach == 'unavailable' else 'FAIL'
    return grade, f"verdict={result.get('verdict')} breach={breach}"


def password_strong(result):
    local = result.get('local_strength') or {}
    breach = (result.get('pwned') or {}).get('status')
    ok = result.get('verdict') == 'review' and local.get('strength') in ('Strong', 'Very strong') and breach == 'not_found'
    return ('PASS' if ok else 'WARN' if breach == 'unavailable' else 'FAIL'), \
        f"verdict={result.get('verdict')} strength={local.get('strength')} breach={breach}"


def ip_clean(result):
    score, status = result.get('abuse_score'), result.get('reputation_status')
    if status in ('not_configured', 'unavailable'):
        return 'WARN', f'reputation={status}'
    return ('PASS' if isinstance(score, (int, float)) and score < 25 else 'FAIL'), f'abuse_score={score} verdict={result.get("verdict")}'


def ip_attacker(result):
    score, status = result.get('abuse_score'), result.get('reputation_status')
    if status in ('not_configured', 'unavailable'):
        return 'WARN', f'reputation={status}'
    return ('PASS' if result.get('verdict') == 'reported' and (score or 0) >= 25 else 'WARN' if result.get('verdict') == 'reported'
            else 'FAIL'), f'abuse_score={score} verdict={result.get("verdict")}'


def domain_found(result):
    found = result.get('domain_status') == 'found'
    registrar = result.get('registrar') or (result.get('whois') or {}).get('registrar')
    return ('PASS' if found and registrar else 'WARN' if found else 'FAIL'), \
        f"domain_status={result.get('domain_status')} registrar={registrar}"


def tls_failed(reason=None):
    def check(result):
        ok = result.get('verdict') == 'verification_failed' and (reason is None or result.get('reason_code') == reason)
        return ('PASS' if ok else 'WARN' if result.get('verdict') == 'verification_failed' else 'FAIL'), \
            f"verdict={result.get('verdict')} reason={result.get('reason_code')}"
    return check


def finds_www(result):
    names = {row.get('full_domain') for row in result.get('results') or [] if isinstance(row, dict)}
    return ('PASS' if 'www.example.com' in names else 'WARN' if names else 'FAIL'), \
        f"found={len(names)} status={result.get('assessment_status')}"


def file_verdict(ok, warn=()):
    def check(result):
        verdict = result.get('verdict')
        return ('PASS' if verdict in ok else 'WARN' if verdict in warn else 'FAIL'), \
            f"verdict={verdict} score={result.get('security_score')} hash={(result.get('hash_reputation') or {}).get('status')}"
    return check


CASES = [
    ('email', 'Real mailbox domain', 'test@gmail.com', one_of('verdict', ('no_indicators',), ('unknown',))),
    ('email', 'Domain that does not exist', f'someone@{NO_DOMAIN}', one_of('verdict', ('no_domain',))),
    ('email', 'Domain with a null MX (accepts no mail)', 'info@example.com', one_of('verdict', ('review',))),
    ('email', 'Not an email address', 'not-an-email', refused),
    ('password', 'Famous leaked password', 'password123', password_exposed),
    ('password', 'Leaked and predictable', 'Summer2024!', password_exposed),
    ('password', 'Fresh random password', secrets.token_urlsafe(24), password_strong),
    ('ip', 'Google DNS', '8.8.8.8', ip_clean),
    ('ip', 'Cloudflare DNS', '1.1.1.1', ip_clean),
    ('ip', 'Private address', '192.168.1.1', refused),
    ('domain', 'Large registered domain', 'google.com', domain_found),
    ('domain', 'Encyclopedia domain', 'wikipedia.org', domain_found),
    ('domain', 'Domain that does not exist', NO_DOMAIN, one_of('verdict', ('no_domain',))),
    ('ssl', 'Valid certificate', 'google.com', one_of('verdict', ('verified_connection',))),
    ('ssl', 'Expired certificate', 'expired.badssl.com', tls_failed('expired')),
    ('ssl', 'Self-signed certificate', 'self-signed.badssl.com', tls_failed('self_signed')),
    ('ssl', 'Untrusted root', 'untrusted-root.badssl.com', tls_failed()),
    ('ssl', 'Certificate for another host', 'wrong.host.badssl.com', tls_failed()),
    ('subdomain', 'Known www host', 'example.com', finds_www),
    ('site', 'Simple clean site', 'example.com', one_of('verdict', ('clean',), ('unknown',))),
    ('site', 'Large clean site', 'wikipedia.org', one_of('verdict', ('clean',), ('unknown',))),
    ('site', 'Expired certificate', 'expired.badssl.com', one_of('verdict', ('suspicious', 'malicious'), ('unknown',))),
    ('file', 'Plain text file', ('notes.txt', b'Meeting notes: buy milk.\n'), file_verdict(('not_found',), ('unknown',))),
    ('file', 'EICAR antivirus test file', ('eicar.com', EICAR), file_verdict(('malicious',), ('suspicious',))),
    ('file', 'PDF that runs JavaScript on open', ('invoice.pdf', pdf_with_javascript()), file_verdict(('suspicious', 'malicious'), ('unknown',))),
    ('file', 'Executable disguised as a PDF', ('invoice.pdf.exe', b'MZ' + b'\x00' * 62 + b'This program cannot be run in DOS mode'),
     file_verdict(('suspicious', 'malicious'), ('unknown',))),
]


def live_cases(count=3):
    """IPs reported for SSH attacks in the last 48 hours (blocklist.de)."""
    from services.url_analyzer import URLDeepAnalyzer
    try:
        lines = URLDeepAnalyzer().session.get('https://lists.blocklist.de/lists/ssh.txt', timeout=20).text.split()
    except Exception as error:
        print(f'! blocklist.de unavailable: {type(error).__name__}')
        return []
    return [('ip', 'Reported SSH attacker (blocklist.de)', ip, ip_attacker) for ip in lines[:count]]


def explain(result):
    """Findings and missing checks, so every WARN or FAIL says why."""
    assessment = result.get('assessment') if isinstance(result.get('assessment'), dict) else {}
    findings = [f.get('message') for f in assessment.get('findings') or [] if isinstance(f, dict) and f.get('message')]
    missing = result.get('missing_checks') or assessment.get('missing_checks') or []
    lines = [f'\n       finding: {f}' for f in findings[:4]] + [f'\n       missing: {m}' for m in missing[:4] if isinstance(m, str)]
    return ''.join(lines)


def run_case(case):
    tool, label, value, check = case
    shown = value[0] if isinstance(value, tuple) else ('(random)' if label.startswith('Fresh') else value)
    started = time.monotonic()
    try:
        result = run(tool, value)
        result = result if isinstance(result, dict) else {}
        grade, detail = check(result)
        if grade != 'PASS':
            detail += explain(result)
    except Exception as error:
        grade, detail = 'FAIL', f'{type(error).__name__}: {str(error)[:120]}'
    return {'tool': tool, 'label': label, 'input': shown, 'grade': grade, 'detail': detail,
            'seconds': round(time.monotonic() - started)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--only', help='comma-separated tools: email,password,ip,domain,ssl,subdomain,site,file')
    parser.add_argument('--live', action='store_true', help='add IPs reported for attacks right now')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args(argv)
    logging.disable(logging.ERROR)  # service error logs would interleave with the table
    try:
        tools = set(args.only.split(',')) if args.only else None
        cases = CASES + (live_cases() if args.live else [])
        cases = [c for c in cases if not tools or c[0] in tools]
        print(f'Checking {len(cases)} inputs across {len({c[0] for c in cases})} tools. This takes a few minutes.\n')
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for row in pool.map(run_case, cases):
                results.append(row)
                mark = {'PASS': 'OK  ', 'WARN': 'WARN', 'FAIL': 'FAIL'}[row['grade']]
                print(f"{mark} {row['tool']:<9} {row['label']:<40} {str(row['input'])[:32]:<32} {row['detail']}")
        counts = {g: sum(r['grade'] == g for r in results) for g in ('PASS', 'WARN', 'FAIL')}
        print(f"\nPASS {counts['PASS']}  WARN {counts['WARN']}  FAIL {counts['FAIL']}  of {len(results)}")
        return 1 if counts['FAIL'] else 0
    finally:
        logging.disable(logging.NOTSET)


if __name__ == '__main__':
    sys.exit(main())
