"""Account-bound HTTP scope for future scanner integration; no dispatch switch."""
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
import time
from sqlalchemy import select
from extensions import db
from models import User, VerifiedTarget
from services.target_verification import normalize_origin, TargetProofError
from services.safe_http import (normalize_url, UnsafeTargetError, PublicHTTPAdapter,
                                PublicHTTPSession, validate_public_url)

class TargetScopeError(UnsafeTargetError):
    """No current account proof or request outside its exact origin."""

@dataclass(frozen=True)
class VerifiedTargetScope:
    user_id: int
    origin: str

    @classmethod
    def for_target(cls, user_id, origin):
        try:
            canonical, _ = normalize_origin(origin)
        except TargetProofError:
            raise TargetScopeError('A verified HTTP/HTTPS domain origin is required.') from None
        scope = cls(user_id, canonical)
        scope.validate_url(canonical)
        return scope

    def validate_url(self, value):
        if not isinstance(value, str) or len(value) > 2048:
            raise TargetScopeError('The request URL is invalid.')
        # Require absolute URLs here; the caller must resolve relative crawl links.
        parts = urlsplit(value)
        if parts.scheme not in {'http', 'https'} or not parts.netloc:
            raise TargetScopeError('An absolute HTTP/HTTPS URL is required.')
        normalized = normalize_url(value)
        parts = urlsplit(normalized)
        try:
            request_origin, host = normalize_origin(urlunsplit((parts.scheme, parts.netloc, '', '', '')))
            configured_origin, _ = normalize_origin(self.origin)
        except TargetProofError:
            raise TargetScopeError('The request origin is not supported.') from None
        if request_origin != configured_origin:
            raise TargetScopeError('The request is outside the verified origin.')
        # Read scalar columns afresh: a cached ORM object must not hide revocation.
        granted = db.session.execute(select(VerifiedTarget.id).join(User, User.id == VerifiedTarget.user_id).where(
            VerifiedTarget.user_id == self.user_id, VerifiedTarget.origin == configured_origin,
            VerifiedTarget.revoked.is_(False), VerifiedTarget.verified_until > time.time(),
            User.is_verified.is_(True)).limit(1)).scalar_one_or_none()
        if granted is None:
            raise TargetScopeError('Current domain verification is required for this account.')
        return urlunsplit((parts.scheme, host, parts.path or '/', parts.query, ''))

    def authorize_url(self, value):
        """Preflight only: connections must still use the pinned scoped adapter."""
        return validate_public_url(self.validate_url(value))

class ScopedHTTPAdapter(PublicHTTPAdapter):
    def __init__(self, scope):
        self.scope = scope
        super().__init__()

    def send(self, request, **kwargs):
        # Requests routes redirects through this adapter too, before DNS/connect.
        request.url = self.scope.validate_url(request.url)
        return super().send(request, **kwargs)

class VerifiedTargetSession(PublicHTTPSession):
    """Scoped public HTTP transport, not a wrapper for ZAP/OpenVAS/browser traffic."""
    def __init__(self, scope):
        super().__init__()
        for adapter in set(self.adapters.values()):
            adapter.close()
        self.mount('http://', ScopedHTTPAdapter(scope))
        self.mount('https://', ScopedHTTPAdapter(scope))
