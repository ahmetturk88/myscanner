"""DNS proof bound to account and exact origin, with bounded lookups."""
import ipaddress
import re
import secrets
import time
import uuid
from urllib.parse import urlsplit
import dns.exception
import dns.resolver
from sqlalchemy import update
from extensions import db
from models.verified_target import VerifiedTarget

CHALLENGE_TTL = 86400
PROOF_TTL = 86400

class TargetProofError(ValueError):
    pass

def normalize_origin(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise TargetProofError('Enter a domain or an HTTP/HTTPS origin.')
    if '\\' in value or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise TargetProofError('Spaces, control characters and backslashes are not allowed.')
    try:
        parsed = urlsplit(value if '://' in value else 'https://' + value)
        if parsed.scheme not in {'http', 'https'} or parsed.username is not None or parsed.password is not None:
            raise ValueError()
        if parsed.path not in {'', '/'} or parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError()
        hostname = parsed.hostname.removesuffix('.').encode('idna').decode('ascii').lower()
        if len('_myscanner-verification.' + hostname) > 253 or len(hostname.split('.')) < 2 or hostname.split('.')[-1].isdigit():
            raise ValueError()
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in hostname.split('.')):
            raise ValueError()
        if hostname.endswith(('.localhost', '.local', '.internal', '.invalid', '.test', '.example')):
            raise ValueError()
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError()
        default_port = 443 if parsed.scheme == 'https' else 80
        if parsed.port not in {None, default_port}:
            raise ValueError()
        return parsed.scheme + '://' + hostname, hostname
    except (ValueError, UnicodeError):
        raise TargetProofError('Use a public domain with HTTP port 80 or HTTPS port 443, without paths or credentials.') from None

def challenge_value(target):
    return 'myscanner-v1=' + target.id + ':' + target.token

def serialize_target(target, now=None):
    now = time.time() if now is None else now
    state = 'revoked' if target.revoked else ('verified' if target.verified_until and target.verified_until > now else ('expired' if target.challenge_expires_at <= now else 'pending'))
    return {'id': target.id, 'origin': target.origin, 'hostname': target.hostname,
            'status': state, 'record_name': '_myscanner-verification.' + target.hostname,
            'record_value': challenge_value(target),
            'challenge_expires_at': target.challenge_expires_at,
            'verified_until': target.verified_until}

def issue_challenge(user_id, value, now=None):
    origin, hostname = normalize_origin(value)
    now = time.time() if now is None else now
    target = VerifiedTarget.query.filter_by(user_id=user_id, origin=origin).first()
    if target is None:
        if VerifiedTarget.query.filter_by(user_id=user_id).count() >= 50:
            raise TargetProofError('The account target limit has been reached.')
        target = VerifiedTarget(id=str(uuid.uuid4()), user_id=user_id, origin=origin, hostname=hostname)
        db.session.add(target)
    # Rotating a challenge invalidates every earlier proof for this origin.
    target.token = secrets.token_hex(32)
    target.challenge_expires_at = now + CHALLENGE_TTL
    target.verified_until = None
    target.revoked = False
    db.session.commit()
    return target

def lookup_txt(hostname):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    answers = resolver.resolve('_myscanner-verification.' + hostname + '.', 'TXT', search=False, lifetime=4)
    values = []
    for answer in answers:
        raw = b''.join(answer.strings)
        if len(raw) <= 256:
            try:
                values.append(raw.decode('ascii'))
            except UnicodeDecodeError:
                continue
        if len(values) >= 32:
            break
    return values

def verify_challenge(target, user_id, lookup=None, now=None):
    started = time.time() if now is None else now
    if target.user_id != user_id or target.revoked or target.challenge_expires_at <= started:
        raise TargetProofError('This challenge is unavailable or expired. Generate a new challenge.')
    token, target_id = target.token, target.id
    expected = challenge_value(target)
    try:
        values = (lookup or lookup_txt)(target.hostname)
    except (dns.exception.DNSException, OSError):
        raise TargetProofError('DNS verification could not complete. Check the TXT record and try again later.') from None
    if not any(isinstance(value, str) and value.isascii() and len(value) <= 256 and secrets.compare_digest(expected, value) for value in values):
        raise TargetProofError('The matching TXT record was not found. DNS propagation may take time.')
    completed = time.time() if now is None else now
    # A concurrent revoke, rotation or expiry must not be undone by a slow DNS query.
    statement = update(VerifiedTarget).where(VerifiedTarget.id == target_id,
        VerifiedTarget.user_id == user_id, VerifiedTarget.token == token,
        VerifiedTarget.revoked.is_(False), VerifiedTarget.challenge_expires_at > completed).values(verified_until=completed + PROOF_TTL)
    changed = db.session.execute(statement).rowcount
    if changed != 1:
        db.session.rollback()
        raise TargetProofError('The challenge changed during verification. Refresh and try again.')
    db.session.commit()
    db.session.refresh(target)
    return target

def has_verified_origin(user_id, value, now=None):
    try:
        origin, _ = normalize_origin(value)
    except TargetProofError:
        return False
    now = time.time() if now is None else now
    return VerifiedTarget.query.filter(VerifiedTarget.user_id == user_id,
        VerifiedTarget.origin == origin, VerifiedTarget.revoked.is_(False),
        VerifiedTarget.verified_until > now).first() is not None
