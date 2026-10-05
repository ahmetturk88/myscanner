"""Explicit production settings, with a safe local-development fallback."""
import os
import secrets

PLACEHOLDERS = {'change-this-secret-key', 'your-secret-key-here-change-it'}
VALID_ENVIRONMENTS = {'development', 'production', 'testing'}


def security_settings(environ=None):
    env = os.environ if environ is None else environ
    mode = env.get('APP_ENV', 'production' if env.get('RENDER', '').lower() == 'true' else 'development').lower()
    if mode not in VALID_ENVIRONMENTS:
        raise RuntimeError('APP_ENV must be development, testing, or production.')
    production = mode == 'production'
    key = env.get('SECRET_KEY', '')
    invalid = not key.strip() or key.strip() in PLACEHOLDERS
    if production and (invalid or len(key) < 32):
        raise RuntimeError('Production requires a private SECRET_KEY of at least 32 characters.')
    if invalid:
        key = secrets.token_urlsafe(48)
    debug = not production and env.get('FLASK_DEBUG', '').lower() in {'1', 'true'}
    return {
        'SECRET_KEY': key, 'DEBUG': debug,
        'SESSION_COOKIE_SECURE': production, 'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'REMEMBER_COOKIE_SECURE': production, 'REMEMBER_COOKIE_HTTPONLY': True,
        'REMEMBER_COOKIE_SAMESITE': 'Lax',
    }
