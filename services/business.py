"""MyScanner Business (İşletme): pilot access, workspaces, domain ownership proof and pre-registrations.

Nothing is sold here. During the pilot only invited accounts (BUSINESS_PILOT_EMAILS)
and administrators open a workspace; everyone else can pre-register on the public
page. A domain is monitored only after its owner proves control with a DNS TXT
record, so nobody can watch a company's domain without its consent.
"""
import os
import re
import secrets
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from extensions import db
from services.target_verification import TargetProofError, normalize_origin

RECORD_PREFIX = '_myscanner.'
VALUE_PREFIX = 'myscanner-business='
DOMAINS_PER_WORKSPACE = 3  # pilot limit
SECTORS = ('eshop', 'agency', 'accounting', 'health', 'education', 'other')
EMAIL = re.compile(r'[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,24}')


class BusinessError(ValueError):
    """A problem the user can fix. The message is a code; the page shows its text (business_page.CONTENT[lang]['errors'])."""


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def pilot_emails(environ=None):
    env = os.environ if environ is None else environ
    return {item.strip().lower() for item in env.get('BUSINESS_PILOT_EMAILS', '').split(',') if item.strip()}


def pilot_allowed(user, environ=None):
    """Administrators and invited, email-verified accounts may open a workspace during the pilot."""
    if not getattr(user, 'is_authenticated', False):
        return False
    if getattr(user, 'is_admin', False) or getattr(user, 'role', None) == 'admin':
        return True
    email = (getattr(user, 'email', '') or '').strip().lower()
    return bool(email) and getattr(user, 'is_verified', False) is True and email in pilot_emails(environ)


def workspace_for(user, create=False):
    from models import BusinessWorkspace
    workspace = BusinessWorkspace.query.filter_by(owner_id=user.id).first()
    if workspace is None and create:
        name = (getattr(user, 'username', '') or 'MyScanner')[:80]
        workspace = BusinessWorkspace(owner_id=user.id, name=name, status='pilot')
        db.session.add(workspace)
        db.session.commit()
    return workspace


def normalize_domain(value):
    """A public site name from what a person types: 'https://www.Shop.com/' -> 'shop.com'."""
    if isinstance(value, str):
        value = value.strip()
        value = re.sub(r'^https?://', '', value, flags=re.I).split('/')[0].split('?')[0].split('#')[0]
    try:
        _, hostname = normalize_origin(value)
    except TargetProofError:
        raise BusinessError('bad_domain') from None
    return hostname[4:] if hostname.startswith('www.') and hostname.count('.') >= 2 else hostname


def record_name(domain):
    return RECORD_PREFIX + domain.domain


def record_value(domain):
    return VALUE_PREFIX + domain.token


def add_domain(workspace, value):
    from models import BusinessDomain
    name = normalize_domain(value)
    existing = BusinessDomain.query.filter_by(workspace_id=workspace.id, domain=name).first()
    if existing is not None:
        return existing
    if BusinessDomain.query.filter_by(workspace_id=workspace.id).count() >= DOMAINS_PER_WORKSPACE:
        raise BusinessError('limit')
    domain = BusinessDomain(workspace_id=workspace.id, domain=name, token=secrets.token_hex(16))
    db.session.add(domain)
    db.session.commit()
    return domain


def owned_domain(workspace, domain_id):
    from models import BusinessDomain
    if workspace is None:
        return None
    return BusinessDomain.query.filter_by(id=domain_id, workspace_id=workspace.id).first()


def lookup_txt(name):
    """TXT values at one exact name, bounded in time and size."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    values = []
    for answer in resolver.resolve(name + '.', 'TXT', search=False, lifetime=4):
        raw = b''.join(answer.strings)
        if len(raw) <= 256:
            try:
                values.append(raw.decode('ascii'))
            except UnicodeDecodeError:
                continue
        if len(values) >= 32:
            break
    return values


def verify_domain(domain, lookup=None):
    """Mark the domain verified when its TXT record holds our value; DNS errors never verify."""
    expected = record_value(domain)
    try:
        values = (lookup or lookup_txt)(record_name(domain))
    except dns.resolver.NXDOMAIN:
        values = []
    except (dns.exception.DNSException, OSError):
        raise BusinessError('dns_unavailable') from None
    domain.last_checked_at = _now()
    if not any(isinstance(v, str) and secrets.compare_digest(v.strip(), expected) for v in values):
        db.session.commit()
        raise BusinessError('not_found_yet')
    domain.verified_at = domain.last_checked_at
    db.session.commit()
    return domain


def remove_domain(domain):
    db.session.delete(domain)
    db.session.commit()


def serialize(domain):
    return {'id': domain.id, 'domain': domain.domain, 'verified': domain.verified_at is not None,
            'record_name': record_name(domain), 'record_value': record_value(domain),
            'verified_at': domain.verified_at, 'last_checked_at': domain.last_checked_at}


# ------------------------------------------------------------------ pre-registration (public page)

def normalize_email(value):
    value = (value or '').strip().lower()
    return value if len(value) <= 254 and EMAIL.fullmatch(value) else None


def normalize_website(value):
    value = (value or '').strip()
    if not value:
        return None
    try:
        return normalize_domain(value)
    except BusinessError:
        return None


def pre_register(email, website, sector, source, lang, user_id=None):
    """Add a pre-registration once. Returns 'added' or 'already'."""
    from models import BusinessLead
    if BusinessLead.query.filter_by(email=email).first():
        return 'already'
    db.session.add(BusinessLead(email=email, website=website, sector=sector if sector in SECTORS else 'other',
                                source=source, lang=lang, user_id=user_id))
    db.session.commit()
    return 'added'


def lead_stats():
    from sqlalchemy import func
    from models import BusinessLead
    rows = db.session.query(BusinessLead.sector, func.count()).group_by(BusinessLead.sector).all()
    latest = BusinessLead.query.order_by(BusinessLead.created_at.desc()).limit(50).all()
    return {'total': sum(count for _, count in rows), 'by_sector': sorted(rows, key=lambda row: -row[1]), 'latest': latest}
