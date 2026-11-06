"""MyScanner Business: files that should never be public (exposed .env, .git, backups, admin pages).

Weekly, and only for domains the customer proved are theirs, we ask the site for
a short fixed list of well-known paths over HTTPS (about 17 GET requests, nothing
else is sent). Redirects are not followed, at most 4 KB of an answer is read, and
a path only counts when its content proves it (a .env has KEY=value lines, a
.git/config has [core], an SQL dump has CREATE TABLE…), so a site that answers
"200" for every address never raises an alarm. A random address is asked first
as a baseline for the same reason. The content itself is never stored: only
which path answered.

This stays on ports 443/80 (the worker's egress firewall is unchanged) and is
not a penetration test: no login is tried and nothing is written.
"""
import json
import re
import secrets
from datetime import datetime, timezone

from extensions import db

READ_LIMIT = 4096
ENV_LINE = re.compile(rb'^[A-Z][A-Z0-9_]{1,40}=', re.M)
SQL = re.compile(rb'CREATE TABLE|INSERT INTO|-- MySQL dump|-- PostgreSQL database dump|-- phpMyAdmin SQL Dump', re.I)
HTML = re.compile(rb'<\s*(!doctype|html|head|body)\b', re.I)


def _env(body):
    return not HTML.search(body) and len(ENV_LINE.findall(body)) >= 2


def _git_config(body):
    return b'[core]' in body and not HTML.search(body)


def _git_head(body):
    head = body.strip()
    return head.startswith(b'ref: refs/') or bool(re.fullmatch(rb'[0-9a-f]{40}', head))


def _sql(body):
    return bool(SQL.search(body)) and not HTML.search(body[:512])


def _zip(body):
    return body.startswith(b'PK\x03\x04')


def _wp_config(body):
    return b'DB_PASSWORD' in body and b'define(' in body


def _phpinfo(body):
    return b'phpinfo()' in body and b'PHP Version' in body


def _server_status(body):
    return b'Apache Server Status' in body


def _phpmyadmin(body):
    return bool(re.search(rb'<title>[^<]*phpMyAdmin', body, re.I)) or b'pma_username' in body


def _ds_store(body):
    return body[4:8] == b'Bud1'


# (finding key, path, proof). Several paths can prove the same finding; it is reported once.
CHECKS = (
    ('env', '/.env', _env),
    ('git', '/.git/config', _git_config),
    ('git', '/.git/HEAD', _git_head),
    ('database_dump', '/backup.sql', _sql),
    ('database_dump', '/db.sql', _sql),
    ('database_dump', '/dump.sql', _sql),
    ('database_dump', '/database.sql', _sql),
    ('archive', '/backup.zip', _zip),
    ('archive', '/site.zip', _zip),
    ('archive', '/www.zip', _zip),
    ('wp_config', '/wp-config.php.bak', _wp_config),
    ('wp_config', '/wp-config.php~', _wp_config),
    ('phpinfo', '/phpinfo.php', _phpinfo),
    ('phpinfo', '/info.php', _phpinfo),
    ('server_status', '/server-status', _server_status),
    ('phpmyadmin', '/phpmyadmin/', _phpmyadmin),
    ('ds_store', '/.DS_Store', _ds_store),
)
SEVERE = {'env', 'git', 'database_dump', 'archive', 'wp_config'}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def severity(key):
    return 'bad' if key in SEVERE else 'warn'


# ------------------------------------------------------------------ the fetch (network; replaced in tests)

def make_fetch(domain):
    """A fetch(path) -> (status, first bytes) for https://<domain>, or None if the site cannot be reached at all."""
    from services.safe_http import PublicHTTPSession
    session = PublicHTTPSession(response_limit=READ_LIMIT)
    session.headers['User-Agent'] = 'MyScanner/1.0 (owner-authorised exposure check; +https://myscanners.com/isletme)'

    def fetch(path):
        response = session.get(f'https://{domain}{path}', timeout=(4, 8), allow_redirects=False, stream=True)
        try:
            body = b''
            if response.status_code == 200:
                for chunk in response.iter_content(1024):
                    body += chunk
                    if len(body) >= READ_LIMIT:
                        break
            return response.status_code, body[:READ_LIMIT]
        finally:
            response.close()
    return fetch, session


def scan(fetch):
    """{'found': [{'key', 'path'}], 'checked': n} or None when the site did not answer the baseline."""
    try:
        baseline_status, baseline = fetch(f'/myscanner-{secrets.token_hex(6)}.env')
    except Exception:
        return None
    soft = baseline[:256] if baseline_status == 200 else None
    found, keys, checked = [], set(), 0
    for key, path, proof in CHECKS:
        if key in keys:
            continue
        try:
            status, body = fetch(path)
        except Exception:
            continue
        checked += 1
        if status != 200 or not body or (soft and body[:256] == soft):
            continue
        if proof(body):
            keys.add(key)
            found.append({'key': key, 'path': path})
    return {'found': found, 'checked': checked}


# ------------------------------------------------------------------ one run

def run_exposure(domain_row, probe=None, now=None):
    """Check the paths once; new findings and fixed ones become events. Returns the snapshot or None."""
    from models import BusinessEvent, BusinessSnapshot
    from services.business_monitor import latest_snapshot
    now = now or _now()
    if domain_row.verified_at is None:
        return None
    if probe is None:
        fetch, session = make_fetch(domain_row.domain)
        try:
            current = scan(fetch)
        finally:
            session.close()
    else:
        current = probe(domain_row.domain)
    if current is None:
        return None  # the site did not answer: no conclusion
    previous_row = latest_snapshot(domain_row.id, kind='exposure')
    before = {f['key'] for f in json.loads(previous_row.results).get('found', [])} if previous_row else set()
    after = {f['key']: f['path'] for f in current['found']}
    snapshot = BusinessSnapshot(domain_id=domain_row.id, kind='exposure', created_at=now, score=None,
                                results=json.dumps(current, sort_keys=True))
    db.session.add(snapshot)
    db.session.flush()
    for key in sorted(set(after) - before):  # alarms even on the first run: these are urgent
        db.session.add(BusinessEvent(domain_id=domain_row.id, snapshot_id=snapshot.id, created_at=now, code='exposure_found',
                                     severity=severity(key), params=json.dumps({'key': key, 'path': after[key]})))
    for key in sorted(before - set(after)):
        db.session.add(BusinessEvent(domain_id=domain_row.id, snapshot_id=snapshot.id, created_at=now, code='exposure_fixed',
                                     severity='good', params=json.dumps({'key': key})))
    db.session.commit()
    return snapshot


def view(domain_id, text):
    """What the workspace and the report show, or None before the first check."""
    from services.business_monitor import latest_snapshot
    row = latest_snapshot(domain_id, kind='exposure')
    if row is None:
        return None
    data = json.loads(row.results)
    items = [{'key': f['key'], 'path': f['path'], 'state': severity(f['key']), 'name': text['exposure_names'].get(f['key'], f['key']),
              'fix': text['exposure_fix'].get(f['key'], '')} for f in data.get('found', [])]
    return {'items': items, 'checked': data.get('checked', 0), 'when': row.created_at}
