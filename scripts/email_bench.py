"""Measure the email checker on real company addresses and on scam domains.

Legitimate addresses of banks, cargo companies, shops and mail providers must never
raise review/dangerous false alarms. Unknown is inconclusive, never a pass. Domains taken from a list of phishing links (one per line, the
same file accuracy_check.py reads) stand in for scam sender domains: each becomes
info@<host> and should be flagged (dangerous or review) while dead or invalid domains remain inconclusive.
A list may also hold sender addresses (one per line, such as the ones --senders prints
from real phishing emails); each is checked as it is, one per domain.
Makes live provider lookups, which may consume provider quota; it saves no credentials. Run it in the web container, which holds the email
checker's Web Risk key:
    dc exec -T web python scripts/email_bench.py
    dc exec -T web python scripts/email_bench.py - < ~/phish.txt
    python3 scripts/email_bench.py --senders ~/phishing_pot/email > ~/senders.txt   # on the host, stdlib only
    dc exec -T web python scripts/email_bench.py - < ~/senders.txt
"""
import concurrent.futures
import logging
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LEGIT = [
    'info@garantibbva.com.tr', 'iletisim@akbank.com', 'bilgi@isbank.com.tr', 'info@ziraatbank.com.tr', 'info@vakifbank.com.tr',
    'info@yapikredi.com.tr', 'info@denizbank.com', 'destek@papara.com', 'musteri@turkcell.com.tr', 'info@vodafone.com.tr',
    'info@turktelekom.com.tr', 'destek@trendyol.com', 'info@hepsiburada.com', 'info@n11.com', 'destek@sahibinden.com',
    'info@migros.com.tr', 'info@amazon.com.tr', 'noreply@turkiye.gov.tr', 'info@ptt.gov.tr', 'info@yurticikargo.com',
    'info@araskargo.com.tr', 'info@mngkargo.com.tr', 'info@suratkargo.com.tr', 'service@paypal.com', 'no-reply@accounts.google.com',
    'info@thy.com', 'info@getir.com', 'info@yemeksepeti.com', 'info@lcwaikiki.com', 'info@teknosa.com', 'info@a101.com.tr',
    'info@kizilay.org.tr', 'iletisim@btk.gov.tr', 'info@itu.edu.tr', 'info@koton.com', 'info@garantiemeklilik.com.tr',
    'someone@gmail.com', 'someone@hotmail.com', 'someone@outlook.com.tr', 'someone@yandex.com.tr', 'someone@icloud.com',
]
LEGIT_OK = {'no_indicators'}
SCAM_OK = {'dangerous', 'review'}  # Dead/invalid addresses are not detected threats.


def scam_addresses(path):
    """info@<host> for each distinct host in a list of links, or the sender addresses themselves;
    one per domain, IP addresses skipped."""
    from scripts.accuracy_check import read_links
    hosts, addresses = [], []
    for link in read_links(path):
        if '@' in link and '://' not in link and ' ' not in link:
            domain = link.rsplit('@', 1)[1].lower()
            if domain not in hosts:
                hosts.append(domain)
                addresses.append(link.lower())
            continue
        try:
            host = (urlsplit(link if '://' in link else 'http://' + link).hostname or '').lower()
        except ValueError:
            continue
        if host and host not in hosts and not host.replace('.', '').isdigit():
            hosts.append(host)
            addresses.append('info@' + host)
    return addresses


def senders(directory):
    """One sender address per domain from the .eml files in a folder, newest sample last.
    The messages are only parsed, never opened in a mail program: they are real phishing."""
    import email
    import email.policy
    import email.utils
    import re
    names = sorted((n for n in os.listdir(directory) if n.endswith('.eml')),
                   key=lambda n: int(re.sub(r'\D', '', n) or 0))
    seen, out = set(), []
    for name in names:
        try:
            with open(os.path.join(directory, name), 'rb') as handle:
                message = email.message_from_binary_file(handle, policy=email.policy.default)
            address = email.utils.parseaddr(str(message.get('From') or ''))[1].strip().lower()
            local, _, domain = address.rpartition('@')
            domain = domain.encode('idna').decode('ascii')
        except Exception:  # broken headers are common in phishing mail
            continue
        if local and re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', domain) and domain not in seen:
            seen.add(domain)
            out.append(local + '@' + domain)
    return out


def check(email):
    from services.email_checker import AdvancedEmailChecker
    try:
        result = AdvancedEmailChecker(None).check_all(email)
        return email, result.get('verdict') or 'invalid', (result.get('web_risk') or {}).get('status', '-')
    except Exception as error:  # one broken lookup must not stop the run
        return email, 'error', type(error).__name__


def bench(title, emails, good):
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        rows = list(pool.map(check, emails))
    counts = {}
    for _, verdict, _ in rows:
        counts[verdict] = counts.get(verdict, 0) + 1
    from scripts.benchmark_metrics import classification_metrics
    metrics = classification_metrics([('clean' if good == LEGIT_OK else 'threat', verdict) for _, verdict, _ in rows])
    import json
    print(json.dumps(metrics, sort_keys=True))
    passed = sum(verdict in good for _, verdict, _ in rows)
    print(f'\n== {title}: {passed} of {len(rows)} as expected ==  ' + '  '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    for email, verdict, web_risk in rows:
        if verdict not in good:
            print(f'   {verdict:<14} web_risk={web_risk:<14} {email}')
    return bool(rows) and passed == len(rows)


def labeled_dataset(path):
    """JSONL holdout: id, email, label clean|threat, provenance, observed_at.

    Supply independent, consented examples, separate from regression fixtures and
    threshold tuning. Labels concern the address/domain evidence, not a message
    body; a forged From header is not proof that the mailbox is malicious.
    """
    import json
    from datetime import date
    rows, seen = [], set()
    with open(path, encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or item.get('label') not in ('clean', 'threat'):
                raise ValueError(f'Invalid label on line {number}')
            if not all(isinstance(item.get(k), str) and item[k].strip() for k in ('id', 'email', 'provenance', 'observed_at')):
                raise ValueError(f'Missing dataset metadata on line {number}')
            date.fromisoformat(item['observed_at'])
            identity = item['email'].strip().lower()
            if item['id'] in seen or identity in seen or '@' not in identity:
                raise ValueError(f'Duplicate/invalid sample on line {number}')
            seen.update((item['id'], identity))
            rows.append(item)
    if {r['label'] for r in rows} != {'clean', 'threat'}:
        raise ValueError('Both independent clean and threat samples are required')
    return rows


def benchmark_dataset(path):
    import json
    from scripts.benchmark_metrics import classification_metrics
    samples = labeled_dataset(path)
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)  # Provider/checker logs can contain supplied addresses.
    try:
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            observations = list(pool.map(check, [s['email'] for s in samples]))
    finally:
        logging.disable(previous_logging)
    metrics = classification_metrics([(s['label'], observation[1]) for s, observation in zip(samples, observations)])
    # Aggregates only: do not print personal addresses from a supplied holdout.
    print(json.dumps({'mode': 'independently-labeled-email-holdout', 'metrics': metrics}, indent=2))
    return 1 if metrics['false_positive'] or metrics['false_negative'] else 2 if metrics['inconclusive'] else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--dataset'] and len(argv) == 2:
        return benchmark_dataset(argv[1])
    if argv[:1] == ['--senders'] and len(argv) == 2:
        print('\n'.join(senders(argv[1])))
        return 0
    logging.disable(logging.ERROR)
    clean = bench('Known-domain controls (review counts as a false alarm)', LEGIT, LEGIT_OK)
    if argv:
        threats = bench('Phishing-domain proxies (not labeled sender ground truth)', scam_addresses(argv[0]), SCAM_OK)
        clean = clean and threats
    return 0 if clean else 1


if __name__ == '__main__':
    sys.exit(main())
