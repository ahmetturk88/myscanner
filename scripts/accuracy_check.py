"""Benchmark URL verdicts against links whose answer is known in advance.

Runs the same analyzer and scoring as a real URL scan (services.url_analyzer +
services.url_assessment) but saves nothing and uses no account or quota.

Run it inside the worker container, which has the scanner's network access:
    dc exec worker python scripts/accuracy_check.py
    dc exec worker python scripts/accuracy_check.py --live 5     # also 5 current URLhaus + 5 OpenPhish URLs
    dc exec worker python scripts/accuracy_check.py --only clean # one group: clean, flag or threat
    dc exec worker python scripts/accuracy_check.py --live 15 --blind
        # threat lists (URLhaus, Web Risk) turned off: does the rest of the scan still catch them?
    dc exec worker python scripts/accuracy_check.py --url https://example.com/ --expect clean
    dc exec worker python scripts/accuracy_check.py --evasion
        # tricks that hide a link's real destination (an @ sign, coded IPs and names,
        # look-alike letters, decoy addresses, redirects, downloads), and real sites
        # that must not be flagged by them
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

# --evasion: each technique once, plus real sites that look like the tricks but are fine.
EVASION_CASES = [
    ('threat', 'https://www.google.com@example.com/', 'Name before @ hides the real site (example.com)'),
    ('threat', 'http://3627732462/', 'IP address written as one number'),
    ('threat', 'http://0xd8.0x3a.0xd4.0x4e/', 'IP address written in hex'),
    ('threat', 'http://0330.072.0324.0116/', 'IP address written in octal'),
    ('threat', 'https://%65xample.com/', 'Site name written in %-code'),
    ('threat', 'https://xn--pple-43d.com/', 'Cyrillic letter in "apple" (homograph)'),
    ('threat', 'https://paypal.com.example.com/', 'Real brand address used as a decoy subdomain'),
    ('threat', 'https://garanti.com.tr.example.net/', 'Turkish bank address used as a decoy subdomain'),
    ('threat', 'https://paypa1.com/', 'Digit swapped into a brand name'),
    ('threat', 'https://secure.eicar.org/eicar.com', 'EICAR antivirus test file (download)'),
    ('threat', 'https://secure.eicar.org/eicar.com.txt', 'EICAR antivirus test file (text page)'),
    ('flag', 'https://httpbingo.org/redirect/12', 'More redirects than a browser follows'),
    ('clean', 'https://apple.stackexchange.com/', 'Brand name on an established site it belongs with'),
    ('clean', 'https://medium.com/@google', '@ in the path, not before the site name'),
    ('clean', 'https://httpbingo.org/redirect-to?url=https%3A%2F%2Fwww.wikipedia.org%2F', 'Redirect to a normal site'),
    ('clean', 'https://play.google.com/store/apps/details?id=com.whatsapp', 'App store page'),
    ('clean', 'https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.1/Git-2.47.0-64-bit.exe',
     'Program download from an established site'),
]


def evasion_cases():
    """EVASION_CASES plus redirects built now: an open redirect to a listed malware URL, and a short link."""
    from urllib.parse import quote
    from services.url_analyzer import URLDeepAnalyzer
    cases = list(EVASION_CASES)
    # Any port: the scanner stops at a redirect to another port and checks that address by reputation.
    listed = [url for expect, url, note in live_cases(2) if note.startswith('URLhaus: listed now')]
    if listed:
        cases.append(('threat', 'https://httpbingo.org/redirect-to?url=' + quote(listed[0], safe=''), 'Redirect to a URLhaus-listed URL'))
    else:
        print('! No URLhaus URL for the redirect case')
    try:
        short = URLDeepAnalyzer().session.get('https://is.gd/create.php', params={'format': 'simple', 'url': 'https://www.wikipedia.org/'}, timeout=15).text.strip()
        if short.startswith('https://is.gd/'):
            cases.append(('clean', short, 'Short link to a normal site'))
    except Exception as error:
        print(f'! Short link could not be created: {type(error).__name__}')
    return cases


THREAT = ('malicious', 'high_risk')
FLAGGED = ('malicious', 'high_risk', 'suspicious')


BLIND = False  # --blind: a threat counts as caught when it is flagged at all


def grade(expect, verdict):
    """PASS, WARN (partial or a coverage gap) or FAIL for one verdict."""
    if verdict in (None, 'error'):
        return 'FAIL'
    if BLIND and expect == 'threat':
        return 'PASS' if verdict in FLAGGED else 'WARN' if verdict == 'unknown' else 'FAIL'
    if expect == 'clean':
        return 'PASS' if verdict == 'harmless' else 'WARN' if verdict == 'unknown' else 'FAIL'
    if expect == 'flag':
        return 'PASS' if verdict in FLAGGED else 'WARN' if verdict == 'unknown' else 'FAIL'
    return 'PASS' if verdict in THREAT else 'WARN' if verdict == 'suspicious' else 'FAIL'


def scan(url):
    from services.url_analyzer import URLDeepAnalyzer
    from services.url_assessment import assess_url
    from services.url_tricks import unmask
    url, tricks = unmask(url)  # the same clean-up a real scan request gets
    analyzer = URLDeepAnalyzer()
    started = time.monotonic()
    try:
        from services.safe_http import needs_reputation_only
        if needs_reputation_only(url):
            local, deep = analyzer.reputation_only_analysis(url)  # same path as a real scan
        else:
            local = analyzer.comprehensive_analysis(url)
            deep = analyzer.comprehensive_deep_analysis(url)
        if tricks:
            local['address_tricks'] = tricks
        result = assess_url(local, deep)
        result['seconds'] = round(time.monotonic() - started)
        result['provider_verdict'] = (local.get('urlvet') or {}).get('verdict')
        result['urlhaus'] = (deep.get('osint') or {}).get('urlhaus_status')
        result['final_url'] = (deep.get('behavior') or {}).get('final_url')
        web_risk = (deep.get('osint') or {}).get('web_risk') or {}
        result['web_risk'] = web_risk.get('status') if web_risk.get('status') != 'unavailable' else f"unavailable ({web_risk.get('reason')}, {web_risk.get('google_reason')})"
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
        # Links on ports 80/443 get the full scan; others the reputation-only check. Test both.
        visited = [url for url in online if standard_port(url)][:(count + 1) // 2]
        reputation = [url for url in online if not standard_port(url)][:count - len(visited)]
        cases += [('threat', url, 'URLhaus: listed now') for url in visited]
        cases += [('threat', url, 'URLhaus: listed now, other port (reputation only)') for url in reputation]
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
        reason = 'blocked: the scanner only visits public ports 80/443' if name == 'UnsafeTargetError' else f'{name}: {str(error)[:120]}'
        return {'expect': expect, 'url': url, 'note': note, 'verdict': 'error', 'grade': 'FAIL', 'error': reason}
    return {'expect': expect, 'url': url, 'note': note, 'verdict': result['verdict'], 'score': result['score'],
            'grade': grade(expect, result['verdict']), 'seconds': result['seconds'],
            'reasons': [r['code'] for r in result['reasons']], 'missing': result['missing_checks'],
            'provider_verdict': result['provider_verdict'], 'urlhaus': result['urlhaus'], 'web_risk': result.get('web_risk'),
            'final_url': result.get('final_url'), 'destination': result.get('destination')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--live', type=int, default=0, metavar='N', help='add N current URLhaus and N OpenPhish URLs')
    parser.add_argument('--only', choices=('clean', 'flag', 'threat'), help='run one group')
    parser.add_argument('--workers', type=int, default=3, help='scans in parallel (default 3)')
    parser.add_argument('--blind', action='store_true',
                        help='turn off the URLhaus and Web Risk threat lists to measure detection of new, unlisted scams')
    parser.add_argument('--url', action='append', default=[], help='scan this URL instead of the built-in cases (repeatable)')
    parser.add_argument('--evasion', action='store_true', help='run the evasion-technique cases instead of the built-in ones')
    parser.add_argument('--expect', choices=('clean', 'flag', 'threat'), default='flag', help='expected answer for --url (default flag)')
    args = parser.parse_args(argv)
    if args.blind:
        global BLIND
        BLIND = True
        os.environ['MYSCANNER_DISABLED_SOURCES'] = ','.join(filter(None, [os.environ.get('MYSCANNER_DISABLED_SOURCES', ''), 'urlhaus', 'web_risk']))
    logging.disable(logging.ERROR)  # analyzer error logs would interleave with the table
    try:
        return benchmark(args)
    finally:
        logging.disable(logging.NOTSET)


def benchmark(args):
    if args.url:
        cases = [(args.expect, url, 'given on the command line') for url in args.url]
    elif args.evasion:
        cases = [c for c in evasion_cases() if not args.only or c[0] == args.only]
    else:
        cases = [c for c in CASES if not args.only or c[0] == args.only]
    if args.live:
        cases += [c for c in live_cases(args.live) if not args.only or c[0] == args.only]
    print(f'Scanning {len(cases)} URLs, {args.workers} at a time. This takes a few minutes.'
          + (' Blind mode: URLhaus and Web Risk are off.' if BLIND else '') + '\n')

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for row in pool.map(run_case, cases):
            results.append(row)
            mark = {'PASS': 'OK  ', 'WARN': 'WARN', 'FAIL': 'FAIL'}[row['grade']]
            score = row.get('score')
            print(f"{mark} {row['expect']:<6} {row['verdict']:<10} {'-' if score is None else score:>3}  {row['url'][:70]}")
            if row['grade'] != 'PASS':
                detail = row.get('error') or f"reasons={','.join(row.get('reasons') or []) or '-'}; " \
                    f"provider={row.get('provider_verdict')}; urlhaus={row.get('urlhaus')}; web_risk={row.get('web_risk')}"
                print(f'     {row["note"]}: {detail}')
                if row.get('final_url') and row['final_url'] != row['url']:
                    print(f"       ends at: {row['final_url'][:120]}" + (f" ({row['destination']['verdict']})" if row.get('destination') else ''))
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
