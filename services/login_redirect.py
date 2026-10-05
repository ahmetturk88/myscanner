"""Accept only root-relative destinations after authentication."""
from urllib.parse import unquote, urlsplit


def safe_login_redirect(destination, fallback):
    if not isinstance(destination, str) or not destination:
        return fallback
    candidate = destination
    # Inspect nested encoding as well; never normalize an unsafe input into a URL.
    for _ in range(5):
        if (not candidate.startswith('/') or candidate.startswith('//')
                or '\\' in candidate or any(ord(char) < 32 or ord(char) == 127 for char in candidate)):
            return fallback
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return fallback
        if parsed.scheme or parsed.netloc:
            return fallback
        decoded = unquote(candidate)
        if decoded == candidate:
            return destination
        candidate = decoded
    return fallback
