"""Load test: N people using the site and the app's tools at the same time (default 20).

Run on the server (or any machine) from the repository root:

    python3 scripts/load_test.py                     # 20 users against https://myscanners.com
    python3 scripts/load_test.py --users 5 --no-url-scan

It signs in once through the app API with an account you choose; the password
is asked with a hidden prompt and never printed or stored. Use an admin
account: admins have no daily limits, so the test doesn't use up anyone's
allowance. Every virtual user then, at the same moment:

  1. opens the home, scam-guide and Pro pages,
  2. runs the SSL, domain, IP and email checks on our own domain,
  3. starts a full URL scan of our own site and waits for its report.

Only our own domain and a public DNS address are checked. At the end the app
token is signed out and a summary is printed: requests, failures by status,
and response times (median, 95th percentile, slowest). Standard library only.
"""
import argparse
import getpass
import json
import math
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

AGENT = 'MyScanner-loadtest/1.0 (bot)'  # "bot" keeps these visits out of the Pro page counts
PAGES = ['/', '/scams', '/pro']


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.times, self.failures = {}, {}

    def add(self, step, seconds, failure=None):
        with self.lock:
            self.times.setdefault(step, []).append(seconds)
            if failure:
                bucket = self.failures.setdefault(step, {})
                bucket[failure] = bucket.get(failure, 0) + 1


def percentile(values, percent):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * percent / 100) - 1)]


def request(base, path, token=None, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    headers = {'User-Agent': AGENT, 'Accept': 'application/json, text/html'}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, data=data, headers=headers, method='POST' if data is not None else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        payload, status = error.read(), error.code
    try:
        parsed = json.loads(payload) if payload[:1] in (b'{', b'[') else None
    except ValueError:
        parsed = None
    return status, parsed


def timed(recorder, step, call, ok=lambda status, data: status == 200):
    start = time.monotonic()
    try:
        status, data = call()
    except Exception as error:  # timeouts and dropped connections count as failures
        recorder.add(step, time.monotonic() - start, type(error).__name__)
        return None, None
    message = data.get('error') if isinstance(data, dict) and isinstance(data.get('error'), str) else ''
    recorder.add(step, time.monotonic() - start, None if ok(status, data) else f'HTTP {status}' + (f' "{message[:60]}"' if message else ''))
    return status, data


def url_scan(base, token, domain, recorder, deadline, target=None):
    start = time.monotonic()
    status, data = timed(recorder, 'url scan: queue', lambda: request(base, '/api/mobile/v1/tools/url', token, {'url': target or f'https://{domain}/'}),
                         ok=lambda s, d: s == 202 and isinstance(d, dict) and 'scan_id' in d)
    if status != 202:
        return
    scan_id = data['scan_id']
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            poll_status, state = request(base, f'/api/mobile/v1/scans/{scan_id}/status', token, timeout=30)
        except Exception:
            continue
        if poll_status != 200 or not isinstance(state, dict):
            recorder.add('url scan: status', 0, f'HTTP {poll_status}')
            continue
        current = state.get('status')
        if isinstance(current, str) and current not in ('pending', 'queued', 'running'):
            # 'partial' is a finished report with a check missing: counted, not failed.
            seconds = time.monotonic() - start
            recorder.add('url scan: full report', seconds, None if current in ('completed', 'partial') else f'scan {current}')
            if current in ('completed', 'partial'):
                timed(recorder, 'url scan: result', lambda: request(base, f'/api/mobile/v1/scans/{scan_id}/analysis', token),
                      ok=lambda s, d: s == 200 and isinstance(d, dict) and isinstance(d.get('plain'), dict))
            if current not in ('completed', 'error', 'failed'):
                recorder.add(f'  of which {current}', seconds)
            return
    recorder.add('url scan: full report', time.monotonic() - start, 'not finished in time')


def user(base, token, domain, recorder, scan_url, deadline, start_gate, target=None):
    start_gate.wait()
    for path in PAGES:
        timed(recorder, 'page ' + path, lambda: request(base, path))
    tools = [('ssl', {'domain': domain}), ('domain', {'domain': domain}), ('ip', {'ip': '1.1.1.1'}),
             ('email', {'email': f'info@{domain}'})]
    for name, body in tools:
        timed(recorder, 'tool ' + name, lambda: request(base, f'/api/mobile/v1/tools/{name}', token, body))
    if scan_url:
        url_scan(base, token, domain, recorder, deadline, target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--base', default='https://myscanners.com')
    parser.add_argument('--users', type=int, default=20)
    parser.add_argument('--domain', help='domain the tools check (default: the host of --base)')
    parser.add_argument('--no-url-scan', action='store_true', help='skip the full URL scans (the heaviest step)')
    parser.add_argument('--timeout', type=int, default=600, help='seconds to wait for every URL scan to finish')
    parser.add_argument('--target', action='append', default=[], help='repeat for distinct authorized URL fixtures; full scans only')
    parser.add_argument('--ack-authorized-targets', action='store_true', help='confirm permission for target/domain fixtures outside --base')
    args = parser.parse_args(argv)
    if not 1 <= args.users <= 30:
        parser.error('--users must be between 1 and 30')
    base = args.base.rstrip('/')
    domain = args.domain or urlsplit(base).hostname

    targets = args.target or [f'https://{domain}/']
    for target in targets:
        parts = urlsplit(target)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            parser.error('--target must be an HTTP(S) URL without credentials')
    if not args.ack_authorized_targets and (domain != urlsplit(base).hostname or any(urlsplit(t).hostname != urlsplit(base).hostname for t in targets)):
        parser.error('External fixture targets require --ack-authorized-targets')
    print(f'Workload: {len(set(targets))} distinct URL targets; caches are NOT bypassed. Cold/warm runs must be recorded separately.')

    email = input('Account email (an admin account has no daily limits): ').strip()
    password = getpass.getpass('Password (hidden): ')
    status, data = request(base, '/api/mobile/v1/auth/login', body={'email': email, 'password': password, 'device': 'load test'})
    del password
    if status != 200 or not isinstance(data, dict) or 'token' not in data:
        print(f'Sign-in failed (HTTP {status}): {(data or {}).get("error", "no details")}')
        return 1
    token = data['token']
    if (data.get('user') or {}).get('role') != 'admin':
        print('Note: this is not an admin account, so the test uses its daily allowance and may stop at the limit.')

    recorder = Recorder()
    gate = threading.Barrier(args.users)
    print(f'Starting {args.users} users at once against {base} ...')
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=args.users) as pool:
            futures = [pool.submit(user, base, token, domain, recorder, not args.no_url_scan, started + args.timeout, gate, targets[i % len(targets)]) for i in range(args.users)]
            for future in futures:
                try:
                    future.result()
                except Exception as error:
                    recorder.add('virtual user', time.monotonic() - started, type(error).__name__)
    finally:
        request(base, '/api/mobile/v1/auth/logout', token, body={})
    elapsed = time.monotonic() - started

    print(f'\nFinished in {elapsed:.0f} s\n')
    print(f'{"step":<26}{"requests":>9}{"failed":>8}{"median":>9}{"p95":>9}{"slowest":>9}')
    failed_total = 0
    for step, values in recorder.times.items():
        failed = sum(recorder.failures.get(step, {}).values())
        failed_total += failed
        print(f'{step:<26}{len(values):>9}{failed:>8}{percentile(values, 50):>8.1f}s{percentile(values, 95):>8.1f}s{max(values):>8.1f}s')
    for step, reasons in recorder.failures.items():
        for reason, count in reasons.items():
            print(f'  {step}: {reason} ×{count}')
    print('\nResult: ' + ('PASS, no failed requests.' if not failed_total else f'{failed_total} failed requests; see above.'))
    return 0 if not failed_total else 2


if __name__ == '__main__':
    sys.exit(main())
