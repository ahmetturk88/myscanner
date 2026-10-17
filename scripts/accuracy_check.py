"""Benchmark URL verdicts against links whose answer is known in advance.

Runs the same analyzer and scoring as a real URL scan (services.url_analyzer +
services.url_assessment) but saves nothing and uses no account or quota.

Run it inside the worker container, which has the scanner's network access:
    dc exec worker python scripts/accuracy_check.py
    dc exec worker python scripts/accuracy_check.py --live 5     # also 5 current URLhaus + 5 OpenPhish URLs
    dc exec worker python scripts/accuracy_check.py --only clean # one group: clean, flag or threat
"""
import argparse
import concurrent.futures
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# expect: clean  = an ordinary, legitimate site; any threat verdict is a false positive.
#         flag   = should not look clean (broken TLS, look-alike names); not necessarily malware.
#         threat = a known-bad or official test-threat URL; it should be flagged.
CASES = [
    ('clean', 'https://www.google.com/', 'Major search engine'),
    ('clean', 'https://www.wikipedia.org/', 'Encyclopedia'),
    ('clean', 'https://github.com/', 'Code hosting'),
    ('clean', 'https://www.apple.com/', 'Large brand'),
    ('clean', 'https://www.microsoft.com/', 'Large brand'),
    ('clean', 'https://www.bbc.com/', 'News site'),
    ('clean', 'https://example.com/', 'IANA reserved example domain'),
    ('clean', 'http://github.com/', 'Plain HTTP that upgrades to HTTPS'),
    ('flag', 'https://expired.badssl.com/', 'Expired certificate'),
    ('flag', 'https://self-signed.badssl.com/', 'Self-signed certificate'),
    ('flag', 'https://wrong.host.badssl.com/', 'Certificate for another host name'),
    ('flag', 'https://untrusted-root.badssl.com/', 'Certificate from an untrusted root'),
    ('flag', 'http://http.badssl.com/', 'No HTTPS at all'),
    ('flag', 'https://xn--80ak6aa92e.com/', 'Punycode look-alike of apple.com'),
    ('threat', 'https://testsafebrowsing.appspot.com/s/phishing.html', 'Google Safe Browsing phishing test page'),
    ('threat', 'https://testsafebrowsing.appspot.com/s/malware.html', 'Google Safe Browsing malware test page'),
    ('threat', 'http://malware.wicar.org/data/eicar.com', 'WICAR malware test file'),
]

THREAT = ('malicious', 'high_risk')
FLAGGED = ('malicious', 'high_risk', 'suspicious')


def grade(expect, verdict):
    """PASS, WARN (partial or a coverage gap) or FAIL for one verdict."""
    if verdict in (None, 'error'):
        return 'FAIL'
    if expect == 'clean':
        return 'PASS' if verdict == 'harmless' else 'WARN' if verdict == 'unknown' else 'FAIL'
    if expect == 'flag':
        return 'PASS' if verdict in FLAGGED else 'WARN' if verdict == 'unknown' else 'FAIL'
    return 'PASS' if verdict in THREAT else 'WARN' if verdict == 'suspicious' else 'FAIL'


def scan(url):
    from services.url_analyzer import URLDeepAnalyzer
    from services.url_assessment import assess_url
    analyzer = URLDeepAnalyzer()
    started = time.monotonic()
    try:
        local = analyzer.comprehensive_analysis(url)
        deep = analyzer.comprehensive_deep_analysis(url)
        result = assess_url(local, deep)
        result['seconds'] = round(time.monotonic() - started)
        result['provider_verdict'] = (local.get('urlvet') or {}).get('verdict')
        result['urlhaus'] = (deep.get('osint') or {}).get('urlhaus_status')
        return result
    finally:
        try:
            analyzer.session.close()
        except Exception:
            pass


def standard_port(url):
    try:
        return urlsplit(url).port in (None, 80, 443)
    except ValueError:
        return False


def live_cases(count):
    """Current entries from URLhaus (malware) and OpenPhish (phishing)."""
    from services.url_analyzer import URLDeepAnalyzer
    session = URLDeepAnalyzer().session
    cases = []
    key = os.environ.get('URLHAUS_AUTH_KEY', '').strip()
    if os.environ.get('URLHAUS_AUTH_KEY_FILE'):
        try:
            with open(os.environ['URLHAUS_AUTH_KEY_FILE'], encoding='utf-8') as secret:
                key = secret.read(4096).strip()
        except OSError:
            key = ''
    try:
        response = session.get(f'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{count * 4}/',
                               headers={'Auth-Key': key}, timeout=20)
        online = [u['url'] for u in response.json().get('urls', []) if u.get('url_status') == 'online']
        # The scanner only visits ports 80/443; most URLhaus links use other ports.
        testable = [url for url in online if standard_port(url)]
        print(f'URLhaus: {len(online)} online, {len(testable)} on ports 80/443')
        cases += [('threat', url, 'URLhaus: listed now') for url in testable[:count]]
        if len(testable) < count:
            cases += [('threat', url, 'URLhaus: listed now, non-standard port') for url in
                      [u for u in online if not standard_port(u)][:count - len(testable)]]
    except Exception as error:
        print(f'! URLhaus list unavailable: {type(error).__name__}')
    try:
        feed = session.get('https://openphish.com/feed.txt', timeout=20).text.split()
        cases += [('threat', url, 'OpenPhish: listed now') for url in feed[:count] if url.startswith('http')]
    except Exception as error:
        print(f'! OpenPhish feed unavailable: {type(error).__name__}')
    return cases


def run_case(case):
    expect, url, note = case
    try:
        result = scan(url)
    except Exception as error:
        name = type(error).__name__
        reason = 'blocked: the scanner only visits public ports 80/443' if name == 'UnsafeTargetError' else name
        return {'expect': expect, 'url': url, 'note': note, 'verdict': 'error', 'grade': 'FAIL', 'error': reason}
    return {'expect': expect, 'url': url, 'note': note, 'verdict': result['verdict'], 'score': result['score'],
            'grade': grade(expect, result['verdict']), 'seconds': result['seconds'],
            'reasons': [r['code'] for r in result['reasons']], 'missing': result['missing_checks'],
            'provider_verdict': result['provider_verdict'], 'urlhaus': result['urlhaus']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--live', type=int, default=0, metavar='N', help='add N current URLhaus and N OpenPhish URLs')
    parser.add_argument('--only', choices=('clean', 'flag', 'threat'), help='run one group')
    parser.add_argument('--workers', type=int, default=3, help='scans in parallel (default 3)')
    args = parser.parse_args(argv)
    logging.disable(logging.ERROR)  # analyzer error logs would interleave with the table
    try:
        return benchmark(args)
    finally:
        logging.disable(logging.NOTSET)


def benchmark(args):
    cases = [c for c in CASES if not args.only or c[0] == args.only]
    if args.live:
        cases += [c for c in live_cases(args.live) if not args.only or c[0] == args.only]
    print(f'Scanning {len(cases)} URLs, {args.workers} at a time. This takes a few minutes.\n')

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for row in pool.map(run_case, cases):
            results.append(row)
            mark = {'PASS': 'OK  ', 'WARN': 'WARN', 'FAIL': 'FAIL'}[row['grade']]
            score = row.get('score')
            print(f"{mark} {row['expect']:<6} {row['verdict']:<10} {'-' if score is None else score:>3}  {row['url'][:70]}")
            if row['grade'] != 'PASS':
                detail = row.get('error') or f"reasons={','.join(row.get('reasons') or []) or '-'}; " \
                    f"provider={row.get('provider_verdict')}; urlhaus={row.get('urlhaus')}"
                print(f'     {row["note"]}: {detail}')
                for item in (row.get('missing') or [])[:6]:
                    print(f'       missing: {item}')

    counts = {g: sum(r['grade'] == g for r in results) for g in ('PASS', 'WARN', 'FAIL')}
    print(f"\nPASS {counts['PASS']}  WARN {counts['WARN']}  FAIL {counts['FAIL']}  of {len(results)}")
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    path = f'/tmp/accuracy-{stamp}.json'
    try:
        with open(path, 'w', encoding='utf-8') as out:
            json.dump(results, out, indent=1)
        print(f'Full details: {path}')
    except OSError:
        print('Full details could not be saved; the table above has the summary.')
    return 1 if counts['FAIL'] else 0


if __name__ == '__main__':
    sys.exit(main())
