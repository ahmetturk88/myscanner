"""MyScanner Business monitoring: the daily checks of a verified domain, its score, and what changed.

Each check returns a state (ok, warn, bad, na) and plain facts. A check that cannot
run is "na", never "ok": an outage is not good news. Every run is kept as a
snapshot; comparing it with the previous one produces events (a new problem, a
fix, a renewed certificate, changed DNS…). Events hold a code and parameters
only; the page and the alerts render them in the reader's language.

Sources are the site's own checks: the TLS handshake (ssl_analyzer), the registry
(RDAP via domain_analyzer), DNS, SPF/DMARC (site_posture), the DNS blocklists of
the email check, Google Web Risk and URLhaus.
"""
import json
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver

from extensions import db

CHECKS = ('ownership', 'tls', 'registration', 'dns', 'mail', 'blocklist', 'reputation')
DAILY = timedelta(hours=23, minutes=30)
PROOF_GRACE = 3  # daily runs in a row without the TXT record before monitoring pauses
DEDUCTIONS = {('tls', 'bad'): 30, ('tls', 'warn'): 10, ('registration', 'bad'): 25, ('registration', 'warn'): 10,
              ('dns', 'bad'): 30, ('mail', 'bad'): 20, ('mail', 'warn'): 10, ('blocklist', 'bad'): 30,
              ('reputation', 'bad'): 50}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def result(state, **facts):
    return {'state': state, **facts}


# ------------------------------------------------------------------ probes (network; replaced in tests)

def probe_ownership(domain_row):
    from services import business
    try:
        values = business.lookup_txt(business.record_name(domain_row))
    except dns.resolver.NXDOMAIN:
        values = []
    expected = business.record_value(domain_row)
    return any(isinstance(v, str) and v.strip() == expected for v in values)


def probe_tls(domain):
    from services.ssl_analyzer import SSLAnalyzer
    return SSLAnalyzer().analyze_certificate(domain)


def probe_registration(domain):
    from services.domain_analyzer import DomainAnalyzer
    analyzer = DomainAnalyzer()
    try:
        return analyzer._get_whois_info(domain)
    finally:
        analyzer.session.close()


def probe_dns(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    records = {}
    for kind in ('A', 'AAAA', 'MX', 'NS'):
        try:
            answer = resolver.resolve(domain + '.', kind, search=False, lifetime=4)
            records[kind] = sorted({str(r).rstrip('.').lower() for r in answer})[:16]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records[kind] = []
    return records


def probe_mail(domain):
    from services.site_posture import mail_security
    return mail_security(domain)


def probe_blocklist(domain, ip):
    from services.email_checker import AdvancedEmailChecker
    return AdvancedEmailChecker().check_blacklists(domain, ip=ip)


def probe_reputation(domain):
    import requests
    from services.url_analyzer import URLDeepAnalyzer
    from services.web_risk import check_web_risk
    url = f'https://{domain}/'
    with requests.Session() as session:
        google = check_web_risk(url, session)
    analyzer = URLDeepAnalyzer()
    try:
        urlhaus = analyzer.check_urlhaus(url)
    finally:
        analyzer.session.close()
    return {'web_risk': google, 'urlhaus': urlhaus}


PROBES = {'ownership': probe_ownership, 'tls': probe_tls, 'registration': probe_registration, 'dns': probe_dns,
          'mail': probe_mail, 'blocklist': probe_blocklist, 'reputation': probe_reputation}


# ------------------------------------------------------------------ reading each probe into a state

def read_tls(report):
    if not isinstance(report, dict) or report.get('valid') is None:
        return result('na')
    days = report.get('days_remaining') if isinstance(report.get('days_remaining'), int) else None
    facts = {'days': days, 'issuer': report.get('issuer'), 'expires': report.get('expiry_date'),
             'fingerprint': report.get('certificate_sha256'), 'version': report.get('tls_version')}
    if report['valid'] is False:
        return result('bad', reason=report.get('reason_code') or 'invalid', **facts)
    if days is not None and days < 7:
        return result('bad', **facts)
    return result('warn' if days is not None and days < 14 else 'ok', **facts)


def read_registration(info):
    if not isinstance(info, dict) or info.get('_whois_status') != 'assessed':
        return result('na')
    days = info.get('days_until_expiry') if isinstance(info.get('days_until_expiry'), int) else None
    facts = {'days': days, 'registrar': info.get('registrar'), 'expires': (info.get('expires') or '')[:10] or None}
    if days is None:
        return result('na', **facts)
    return result('bad' if days < 7 else 'warn' if days < 30 else 'ok', **facts)


def read_dns(records):
    if not isinstance(records, dict):
        return result('na')
    has_address = bool(records.get('A') or records.get('AAAA'))
    return result('ok' if has_address else 'bad', records={k: records.get(k, []) for k in ('A', 'AAAA', 'MX', 'NS')})


def read_mail(mail):
    if not isinstance(mail, dict) or mail.get('status') != 'completed':
        return result('na')
    facts = {'spf': mail.get('spf') or '', 'dmarc': mail.get('dmarc_policy'), 'protected': mail.get('protected') is True}
    if facts['protected']:
        return result('ok', **facts)
    return result('bad' if not facts['spf'] and facts['dmarc'] == 'missing' else 'warn', **facts)


def read_blocklist(report):
    if not isinstance(report, dict) or not report.get('queried_ips'):
        return result('na')
    listed = [s for s in report.get('blacklisted_on') or [] if isinstance(s, str)]
    if listed:
        return result('bad', lists=listed, ip=report['queried_ips'][0])
    if report.get('coverage_status') == 'completed':
        return result('ok', ip=report['queried_ips'][0])
    return result('na', ip=report['queried_ips'][0])


def read_reputation(report):
    if not isinstance(report, dict):
        return result('na')
    google = report.get('web_risk') or {}
    urlhaus = report.get('urlhaus') or {}
    listed = []
    if google.get('status') == 'matched':
        listed.append('Google Web Risk')
    if urlhaus.get('coverage_status') == 'matched':
        listed.append('URLhaus')
    if listed:
        return result('bad', lists=listed)
    if google.get('status') == 'not_found' or urlhaus.get('coverage_status') == 'not_found':
        return result('ok')
    return result('na')


# ------------------------------------------------------------------ score and changes

def score(results):
    """100 minus what the problems cost; None when too little could be checked."""
    checked = [k for k in CHECKS if k != 'ownership' and results.get(k, {}).get('state') in ('ok', 'warn', 'bad')]
    if len(checked) < 3:
        return None
    return max(0, 100 - sum(DEDUCTIONS.get((k, results[k]['state']), 0) for k in checked))


def changes(previous, current):
    """[(code, severity, params)] between two runs; on the first run, the problems found and a start note."""
    events = []
    if previous is None:
        events.append(('monitoring_started', 'info', {}))
        for key in CHECKS[1:]:
            state = current.get(key, {}).get('state')
            if state in ('warn', 'bad'):
                events.append((f'{key}_{state}', state, _params(key, current[key])))
        return events
    for key in CHECKS[1:]:
        before, after = previous.get(key, {}), current.get(key, {})
        old, new = before.get('state'), after.get('state')
        if new in ('warn', 'bad') and old != new and not (old == 'bad' and new == 'warn' and key == 'tls'):
            events.append((f'{key}_{new}', new, _params(key, after)))
        elif new == 'ok' and old in ('warn', 'bad'):
            events.append((f'{key}_fixed', 'good', _params(key, after)))
    tls_old, tls_new = previous.get('tls', {}), current.get('tls', {})
    if (tls_new.get('state') == 'ok' and tls_old.get('fingerprint') and tls_new.get('fingerprint')
            and tls_old['fingerprint'] != tls_new['fingerprint'] and tls_old.get('state') == 'ok'):
        events.append(('tls_renewed', 'info', {'expires': tls_new.get('expires'), 'issuer': tls_new.get('issuer')}))
    dns_old = previous.get('dns', {}).get('records') or {}
    dns_new = current.get('dns', {}).get('records') or {}
    if dns_old and dns_new:
        for kind in ('A', 'AAAA', 'MX', 'NS'):
            if dns_old.get(kind) and dns_new.get(kind) is not None and dns_old.get(kind) != dns_new.get(kind):
                events.append(('dns_changed', 'warn', {'kind': kind, 'before': ', '.join(dns_old[kind])[:200],
                                                       'after': ', '.join(dns_new[kind])[:200] or '—'}))
    mail_old, mail_new = previous.get('mail', {}), current.get('mail', {})
    if (mail_old.get('state') in ('ok', 'warn', 'bad') and mail_new.get('state') in ('ok', 'warn', 'bad')
            and (mail_old.get('spf'), mail_old.get('dmarc')) != (mail_new.get('spf'), mail_new.get('dmarc'))
            and mail_old.get('state') == mail_new.get('state')):
        events.append(('mail_changed', 'warn', {'dmarc': mail_new.get('dmarc') or '—', 'spf': (mail_new.get('spf') or '—')[:120]}))
    reg_old, reg_new = previous.get('registration', {}), current.get('registration', {})
    if reg_old.get('registrar') and reg_new.get('registrar') and reg_old['registrar'] != reg_new['registrar']:
        events.append(('registrar_changed', 'warn', {'before': reg_old['registrar'], 'after': reg_new['registrar']}))
    return events


def _params(key, value):
    keep = {'tls': ('days', 'expires', 'reason'), 'registration': ('days', 'expires'), 'mail': ('dmarc',),
            'blocklist': ('lists', 'ip'), 'reputation': ('lists',), 'dns': ()}[key]
    params = {k: value.get(k) for k in keep if value.get(k) is not None}
    if isinstance(params.get('lists'), list):
        params['lists'] = ', '.join(params['lists'])
    return params


# ------------------------------------------------------------------ one run

def latest_snapshot(domain_id, kind='daily'):
    from models import BusinessSnapshot
    return (BusinessSnapshot.query.filter_by(domain_id=domain_id, kind=kind)
            .order_by(BusinessSnapshot.created_at.desc(), BusinessSnapshot.id.desc()).first())


def run_domain(domain_row, probes=None, now=None):
    """Run every daily check for one verified domain; store the snapshot and its events. Returns the snapshot."""
    from models import BusinessEvent, BusinessSnapshot
    probes = {**PROBES, **(probes or {})}
    now = now or _now()
    if domain_row.verified_at is None:
        return None
    name = domain_row.domain
    current = {}

    def attempt(key, reader, *args):
        try:
            current[key] = reader(probes[key](*args))
        except Exception:
            current[key] = result('na')

    try:
        present = probes['ownership'](domain_row)
        current['ownership'] = result('ok' if present else 'warn')
    except Exception:
        current['ownership'] = result('na')
    attempt('tls', read_tls, name)
    attempt('registration', read_registration, name)
    attempt('dns', read_dns, name)
    attempt('mail', read_mail, name)
    address = next(iter((current['dns'].get('records') or {}).get('A') or []), None)
    if address:
        attempt('blocklist', read_blocklist, name, address)
    else:
        current['blocklist'] = result('na')
    attempt('reputation', read_reputation, name)

    previous_row = latest_snapshot(domain_row.id)
    previous = json.loads(previous_row.results) if previous_row else None
    snapshot = BusinessSnapshot(domain_id=domain_row.id, kind='daily', created_at=now, score=score(current),
                                results=json.dumps(current, ensure_ascii=False, sort_keys=True))
    db.session.add(snapshot)
    db.session.flush()
    found = changes(previous, current)
    ownership = current['ownership']['state']
    if ownership == 'warn':
        domain_row.proof_misses = (domain_row.proof_misses or 0) + 1
        if domain_row.proof_misses >= PROOF_GRACE:
            domain_row.verified_at = None  # proof gone: stop watching until it is proven again
            found.append(('proof_lost', 'bad', {}))
        else:
            found.append(('proof_missing', 'warn', {'left': PROOF_GRACE - domain_row.proof_misses}))
    elif ownership == 'ok':
        domain_row.proof_misses = 0
    for code, severity, params in found:
        db.session.add(BusinessEvent(domain_id=domain_row.id, snapshot_id=snapshot.id, created_at=now, code=code,
                                     severity=severity, params=json.dumps(params, ensure_ascii=False, sort_keys=True)))
    domain_row.monitored_at = now
    db.session.commit()
    return snapshot


def due_domains(now=None, limit=25):
    """Verified domains whose last daily run is older than DAILY (never-run ones first)."""
    from models import BusinessDomain
    now = now or _now()
    query = BusinessDomain.query.filter(BusinessDomain.verified_at.isnot(None)).filter(
        (BusinessDomain.monitored_at.is_(None)) | (BusinessDomain.monitored_at <= now - DAILY))
    rows = query.all()
    rows.sort(key=lambda d: d.monitored_at or datetime.min)
    return rows[:limit]


def recent_events(domain_id, limit=12):
    from models import BusinessEvent
    rows = (BusinessEvent.query.filter_by(domain_id=domain_id)
            .order_by(BusinessEvent.created_at.desc(), BusinessEvent.id.desc()).limit(limit).all())
    return [{'code': e.code, 'severity': e.severity, 'params': json.loads(e.params or '{}'), 'at': e.created_at} for e in rows]


# ------------------------------------------------------------------ what the workspace shows

class _Keep(dict):
    def __missing__(self, key):
        return '—'


def check_rows(results, text):
    """[(check name, state, plain value)] in the reader's language."""
    values = text['check_values']
    rows = []
    for key in CHECKS:
        item = results.get(key) or {}
        state = item.get('state', 'na')
        facts = _Keep({k: v for k, v in item.items() if v is not None})
        if state == 'na':
            value = values['na']
        elif key == 'tls':
            value = values['tls_bad'] if state == 'bad' and item.get('reason') else values[f'tls_{state}' if state != 'bad' else 'tls_bad_days']
        elif key == 'registration':
            value = values['registration']
        elif key == 'dns':
            records = item.get('records') or {}
            facts['count'] = len(records.get('A') or []) + len(records.get('AAAA') or [])
            value = values[f'dns_{state}']
        elif key in ('blocklist', 'reputation') and isinstance(item.get('lists'), list):
            facts['lists'] = ', '.join(item['lists'])
            value = values[f'{key}_{state}']
        else:
            value = values.get(f'{key}_{state}', values['na'])
        rows.append((text['checks'][key], state, value.format_map(facts)))
    return rows


def event_line(event, text):
    template = text['events'].get(event['code'])
    if template is None:
        return None
    params = {k: v for k, v in (event.get('params') or {}).items() if v is not None}
    if isinstance(params.get('title'), str) and text.get('lang') == 'tr':
        from services.report_i18n import translate  # site findings are stored in English, as the site check writes them
        params['title'] = translate(params['title'], 'tr')
    return template.format_map(_Keep(params))


def domain_view(domain_row, text):
    """Everything the workspace shows for one verified domain."""
    snapshot = latest_snapshot(domain_row.id)
    results = json.loads(snapshot.results) if snapshot else {}
    events = [dict(e, text=event_line(e, text)) for e in recent_events(domain_row.id)]
    return {'score': snapshot.score if snapshot else None, 'last_run': snapshot.created_at if snapshot else None,
            'rows': check_rows(results, text) if snapshot else [], 'events': [e for e in events if e['text']]}


# ------------------------------------------------------------------ weekly full site inspection

WEEKLY = timedelta(days=7)


def probe_site(domain):
    """The public website check (passive: no attack traffic), as on /site-scanner."""
    from services.simple_report_view import plain_web_report
    from services.site_analyzer import SiteAnalyzer
    report = SiteAnalyzer().comprehensive_analysis(domain, include_provider=False, include_discovery=False)
    if report.get('error'):
        raise ValueError('site check failed')
    return plain_web_report(report, source='site')


def read_site(plain):
    """The plain report's warning reasons, by title (English, as stored by the site check)."""
    if not isinstance(plain, dict) or not plain.get('tone'):
        return result('na')
    issues = sorted({r['title'] for r in plain.get('reasons') or []
                     if isinstance(r, dict) and r.get('tone') in ('bad', 'warn') and isinstance(r.get('title'), str)})[:20]
    state = 'bad' if plain.get('tone') == 'danger' else 'warn' if issues else 'ok'
    return result(state, verdict=plain.get('tone'), issues=issues)


def run_weekly(domain_row, probe=None, now=None):
    """The weekly site inspection; new and resolved issues become events. Returns the snapshot or None."""
    from models import BusinessEvent, BusinessSnapshot
    now = now or _now()
    if domain_row.verified_at is None:
        return None
    try:
        current = read_site((probe or probe_site)(domain_row.domain))
    except Exception:
        current = result('na')
    previous_row = latest_snapshot(domain_row.id, kind='weekly')
    previous = json.loads(previous_row.results).get('site') if previous_row else None
    snapshot = BusinessSnapshot(domain_id=domain_row.id, kind='weekly', created_at=now, score=None,
                                results=json.dumps({'site': current}, ensure_ascii=False, sort_keys=True))
    db.session.add(snapshot)
    db.session.flush()
    found = []
    if current['state'] != 'na':
        before = set((previous or {}).get('issues') or []) if previous and previous.get('state') != 'na' else set()
        after = set(current.get('issues') or [])
        for title in sorted(after - before):
            found.append(('site_issue', 'bad' if current['state'] == 'bad' else 'warn', {'title': title}))
        if previous and previous.get('state') != 'na':
            for title in sorted(before - after):
                found.append(('site_issue_fixed', 'good', {'title': title}))
    for code, severity, params in found:
        db.session.add(BusinessEvent(domain_id=domain_row.id, snapshot_id=snapshot.id, created_at=now, code=code,
                                     severity=severity, params=json.dumps(params, ensure_ascii=False, sort_keys=True)))
    domain_row.weekly_at = now
    db.session.commit()
    return snapshot


def weekly_due(now=None, limit=3):
    from models import BusinessDomain
    now = now or _now()
    rows = BusinessDomain.query.filter(BusinessDomain.verified_at.isnot(None), BusinessDomain.monitored_at.isnot(None)).filter(
        (BusinessDomain.weekly_at.is_(None)) | (BusinessDomain.weekly_at <= now - WEEKLY)).all()
    rows.sort(key=lambda d: d.weekly_at or datetime.min)
    return rows[:limit]
