"""Website language: English pages translated after rendering.

Templates stay in English. When a visitor picks Turkish (?lang=tr, kept in a
cookie, or a Turkish browser), finished HTML has every text node and a few
attributes (placeholder, aria-label, title, alt, meta content) swapped for the
catalog translation when one exists. Anything without a translation stays
English, so a missing entry never breaks a page. Report summaries returned by
the website's JSON endpoints are translated with the report catalog.
"""
import html
import json
import re

from flask import g, request

from services.report_i18n import CATALOGS as REPORT_CATALOGS, preferred_language, translate_plain

LANGUAGES = ('en', 'tr')
COOKIE = 'lang'
COOKIE_DAYS = 365


def _catalogs():
    from services.i18n_site_tr import SITE_TR
    return {'tr': SITE_TR}


def _patterns(lang):
    if lang != 'tr':
        return [], {}
    from services.i18n_site_tr import MONTHS, SITE_TR_PATTERNS
    if not hasattr(_patterns, 'compiled'):
        _patterns.compiled = [(re.compile(p), r) for p, r in SITE_TR_PATTERNS]
    return _patterns.compiled, MONTHS


def current_language():
    """The page language for this request: ?lang=, then the cookie, then the browser."""
    cached = getattr(g, 'site_language', None)
    if cached:
        return cached
    asked = (request.args.get('lang') or '').lower()
    if asked in LANGUAGES:
        g.site_language_chosen = asked
        lang = asked
    else:
        cookie = (request.cookies.get(COOKIE) or '').lower()
        lang = cookie if cookie in LANGUAGES else ('tr' if preferred_language(request.headers.get('Accept-Language')) == 'tr' else 'en')
    g.site_language = lang
    return lang


_SPACE = re.compile(r'\s+')
_PARTS = re.compile(r'(<!--.*?-->|<script\b.*?</script>|<style\b.*?</style>|<textarea\b.*?</textarea>|<[^>]+>)', re.S | re.I)
_ATTRIBUTE = re.compile(r'\b(placeholder|aria-label|title|alt|content|data-label)="([^"]*)"')
_TITLE_LIKE = ('<meta ',)


_MONTH_WORD = re.compile(r'\b(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b')


def _lookup(text, catalog, lang):
    key = _SPACE.sub(' ', html.unescape(text)).strip()
    if not key:
        return None
    found = catalog.get(key)
    if found is not None or not key[:1].isalnum():
        return found
    patterns, months = _patterns(lang)
    for pattern, replacement in patterns:
        if pattern.match(key):
            return _MONTH_WORD.sub(lambda m: months.get(m.group(1), m.group(1)), pattern.sub(replacement, key))
    return None


def _translate_text(segment, catalog, lang):
    found = _lookup(segment, catalog, lang)
    if found is None:
        return segment
    lead = segment[:len(segment) - len(segment.lstrip())]
    trail = segment[len(segment.rstrip()):]
    return lead + html.escape(found, quote=False) + trail


def _translate_tag(tag, catalog, lang):
    if tag.startswith(('</', '<!')):
        return tag
    if tag[:6].lower() == '<meta ' and not re.search(r'\b(name|property)="(description|og:title|og:description|twitter:title|twitter:description)"', tag):
        return tag

    def swap(match):
        found = _lookup(match.group(2), catalog, lang)
        return match.group(0) if found is None else f'{match.group(1)}="{html.escape(found, quote=True)}"'
    return _ATTRIBUTE.sub(swap, tag)


def translate_html(page, lang):
    catalog = _catalogs().get(lang)
    if not catalog:
        return page
    out = []
    for part in _PARTS.split(page):
        if not part:
            continue
        if part.startswith('<'):
            low = part[:9].lower()
            if low.startswith(('<script', '<style', '<textarea', '<!--')):
                out.append(part)
            else:
                out.append(_translate_tag(part, catalog, lang))
        else:
            out.append(_translate_text(part, catalog, lang))
    result = ''.join(out)
    return re.sub(r'<html lang="en"', f'<html lang="{lang}"', result, count=1)


def _localise_plain(value, lang):
    if isinstance(value, dict):
        return {key: translate_plain(item, lang) if key == 'plain' and isinstance(item, dict) and 'headline' in item
                else _localise_plain(item, lang) for key, item in value.items()}
    if isinstance(value, list):
        return [_localise_plain(item, lang) for item in value]
    return value


def localise_response(response):
    """after_request: translate pages and report summaries, and remember an explicit choice."""
    if request.path.startswith(('/static/', '/api/mobile/')):
        return response
    lang = current_language()
    chosen = getattr(g, 'site_language_chosen', None)
    if chosen:
        response.set_cookie(COOKIE, chosen, max_age=COOKIE_DAYS * 86400, samesite='Lax', secure=request.is_secure)
    vary = response.headers.get('Vary', '')
    for header in ('Cookie', 'Accept-Language'):
        if header.lower() not in vary.lower():
            vary = f'{vary}, {header}' if vary else header
    response.headers['Vary'] = vary
    if lang == 'en' or response.status_code != 200 or response.is_streamed or response.direct_passthrough:
        return response
    if response.mimetype == 'text/html':
        response.set_data(translate_html(response.get_data(as_text=True), lang))
    elif response.mimetype == 'application/json' and lang in REPORT_CATALOGS:
        data = json.loads(response.get_data(as_text=True))
        localised = _localise_plain(data, lang)
        if localised != data:
            response.set_data(json.dumps(localised, ensure_ascii=False))
    return response
