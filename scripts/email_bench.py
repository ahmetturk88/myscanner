"""Measure the email checker on real company addresses and on scam domains.

Legitimate addresses of banks, cargo companies, shops and mail providers must never
come out dangerous. Domains taken from a list of phishing links (one per line, the
same file accuracy_check.py reads) stand in for scam sender domains: each becomes
info@<host> and should be flagged (dangerous or review) or have no domain at all.
A list may also hold sender addresses (one per line, such as the ones --senders prints
from real phishing emails); each is checked as it is, one per domain.
Saves nothing and uses no quota. Run it in the web container, which holds the email
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
LEGIT_OK = {'no_indicators', 'unknown', 'review'}
SCAM_OK = {'dangerous', 'review', 'no_domain'}


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
    passed = sum(verdict in good for _, verdict, _ in rows)
    print(f'\n== {title}: {passed} of {len(rows)} as expected ==  ' + '  '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    for email, verdict, web_risk in rows:
        if verdict not in good:
            print(f'   {verdict:<14} web_risk={web_risk:<14} {email}')
    return passed == len(rows)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--senders'] and len(argv) == 2:
        print('\n'.join(senders(argv[1])))
        return 0
    logging.disable(logging.ERROR)
    clean = bench('Real addresses (must not be dangerous)', LEGIT, LEGIT_OK)
    if argv:
        bench('Phishing-site domains (should be flagged)', scam_addresses(argv[0]), SCAM_OK)
    return 0 if clean else 1


if __name__ == '__main__':
    sys.exit(main())
