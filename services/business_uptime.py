"""MyScanner Business: is the site up? Checked every few minutes, alerts on outages and recoveries.

Each run fetches the home page of every verified domain once (HTTPS, falling back
to HTTP only when HTTPS cannot connect; public-network session, at most 64 KB
read, nothing submitted). A site is "down" after two failed checks in a row, so
a single slow answer never alerts. A failure is a timeout, a refused or broken
connection, or a server error (5xx); any other HTTP answer, including 4xx from a
firewall, means the site responds.

Before checking, the run asks a well-known control address. If even that fails,
the problem is our own network and the run concludes nothing.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from extensions import db

EVERY = timedelta(minutes=5)
FAIL_THRESHOLD = 2
READ_LIMIT = 64 * 1024
CONTROL_URLS = ('https://www.google.com/generate_204', 'https://www.cloudflare.com/cdn-cgi/trace')


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ------------------------------------------------------------------ probes (network; replaced in tests)

def _fetch(url):
    from services.safe_http import PublicHTTPSession
    with PublicHTTPSession(response_limit=READ_LIMIT) as session:
        started = time.monotonic()
        response = session.get(url, timeout=(5, 10), allow_redirects=True, stream=True,
                               headers={'User-Agent': 'MyScanner-Uptime/1.0 (+https://myscanners.com/isletme)'})
        try:
            next(response.iter_content(4096), b'')
            return response.status_code, int((time.monotonic() - started) * 1000)
        finally:
            response.close()


def probe_site(domain):
    """{'ok': bool, 'status': int | None, 'ms': int | None, 'reason': None | timeout | connection | tls | server_error}."""
    import requests
    for scheme in ('https', 'http'):
        try:
            status, ms = _fetch(f'{scheme}://{domain}/')
        except requests.exceptions.SSLError:
            reason = 'tls'
        except requests.exceptions.Timeout:
            return {'ok': False, 'status': None, 'ms': None, 'reason': 'timeout'}
        except Exception:
            reason = 'connection'
        else:
            if status >= 500:
                return {'ok': False, 'status': status, 'ms': ms, 'reason': 'server_error'}
            return {'ok': True, 'status': status, 'ms': ms, 'reason': None}
        # only a site that cannot be reached over HTTPS at all is tried over plain HTTP
    return {'ok': False, 'status': None, 'ms': None, 'reason': reason}


def probe_control():
    for url in CONTROL_URLS:
        try:
            status, _ = _fetch(url)
            if status < 500:
                return True
        except Exception:
            continue
    return False


PROBES = {'site': probe_site, 'control': probe_control}


# ------------------------------------------------------------------ one run

def due_domains(now=None):
    from models import BusinessDomain
    now = now or _now()
    # A little slack so a run that starts a few seconds early still covers every domain.
    cutoff = now - EVERY + timedelta(seconds=30)
    return (BusinessDomain.query.filter(BusinessDomain.verified_at.isnot(None))
            .filter((BusinessDomain.up_checked_at.is_(None)) | (BusinessDomain.up_checked_at <= cutoff)).all())


def run_uptime(domains, probes=None, now=None):
    """Check each domain once; record the day's counts and outage/recovery events. Returns {domain_id: [events]}."""
    from models import BusinessEvent
    probes = {**PROBES, **(probes or {})}
    now = now or _now()
    if not domains:
        return {}
    if not probes['control']():
        return {}  # our own network is down: no conclusion about anyone's site
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = dict(zip([d.id for d in domains], pool.map(lambda d: _safe(probes['site'], d.domain), domains)))
    found = {}
    for domain in domains:
        answer = answers.get(domain.id)
        if not isinstance(answer, dict):
            continue  # the probe itself failed: no conclusion
        _count(domain.id, now, answer)
        events = _transition(domain, answer, now)
        for code, severity, params in events:
            db.session.add(BusinessEvent(domain_id=domain.id, created_at=now, code=code, severity=severity,
                                         params=_json(params)))
        if events:
            found[domain.id] = events
    db.session.commit()
    return found


def _transition(domain, answer, now):
    domain.up_checked_at = now
    if answer.get('ok'):
        domain.up_ms = answer.get('ms')
        events = []
        if domain.up_state == 'down' and domain.down_since:
            minutes = max(1, int((now - domain.down_since).total_seconds() // 60))
            events.append(('site_up', 'good', {'minutes': minutes}))
        domain.up_state, domain.up_fails, domain.down_since = 'up', 0, None
        return events
    domain.up_fails = (domain.up_fails or 0) + 1
    if domain.up_fails == 1:
        domain.down_since = now
    if domain.up_fails >= FAIL_THRESHOLD and domain.up_state != 'down':
        domain.up_state = 'down'
        params = {'reason': answer.get('reason') or 'connection'}
        if answer.get('status'):
            params['status'] = answer['status']
        return [('site_down', 'bad', params)]
    return []


def _count(domain_id, now, answer):
    from models import BusinessUptimeDay
    row = BusinessUptimeDay.query.filter_by(domain_id=domain_id, day=now.date()).first()
    if row is None:
        row = BusinessUptimeDay(domain_id=domain_id, day=now.date(), checks=0, ups=0, total_ms=0)
        db.session.add(row)
    row.checks += 1
    if answer.get('ok'):
        row.ups += 1
        row.total_ms += int(answer.get('ms') or 0)


def summary(domain_id, days=30, now=None):
    """{'percent': float | None, 'avg_ms': int | None, 'checks': int} over the last `days` days."""
    from models import BusinessUptimeDay
    now = now or _now()
    rows = BusinessUptimeDay.query.filter(BusinessUptimeDay.domain_id == domain_id,
                                          BusinessUptimeDay.day > (now - timedelta(days=days)).date()).all()
    checks, ups, total = sum(r.checks for r in rows), sum(r.ups for r in rows), sum(r.total_ms for r in rows)
    return {'percent': round(100 * ups / checks, 2) if checks else None,
            'avg_ms': round(total / ups) if ups else None, 'checks': checks}


def view(domain_row, text, now=None):
    """What the workspace shows: state, since when, last-30-day percentage and response time (in the reader's style)."""
    stats = summary(domain_row.id, now=now)
    percent = stats['percent']
    shown = None
    if percent is not None:
        shown = f'{percent:.2f}'.rstrip('0').rstrip('.')
        if text.get('lang') == 'tr':
            shown = shown.replace('.', ',')
    return {'state': domain_row.up_state, 'since': domain_row.down_since if domain_row.up_state == 'down' else None,
            'percent': shown, 'avg_ms': stats['avg_ms']}


def _json(params):
    import json
    return json.dumps(params, ensure_ascii=False, sort_keys=True)


def _safe(function, *args):
    try:
        return function(*args)
    except Exception:
        return None
