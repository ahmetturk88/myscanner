"""Translate the plain-language report summaries ("plain" objects) for the app.

The English builders (services/*_report_view.py) stay the single source of
what a report says; this module only maps their finished sentences onto the
catalog in services/i18n_tr.py. Codes (tone, state) and the scanned address
(url.prefix/host/rest) are never translated, and text with no catalog entry is
returned unchanged, so a missing entry shows English rather than nothing.
"""
import copy
import re

from services.i18n_tr import TR

CATALOGS = {'tr': TR}
TEXT_FIELDS = ('label', 'headline', 'summary', 'why_title', 'checked', 'share_text', 'not_visited', 'no_preview')
TALLY_SEPARATOR = ' · '

# Placeholders that hold scanned data (addresses, names, versions): kept as they are.
VERBATIM = {'url', 'host', 'brand', 'email', 'ip', 'domain', 'issuer', 'owner', 'registrar', 'signature',
            'country', 'version', 'ext', 'type', 'listed', 'asn', 'when', 'name'}
# What each placeholder may match; anything not listed matches any text (shortest first).
PLACEHOLDER_PATTERNS = {
    'n': r'\d[\d,.]*', 'm': r'\d[\d,.]*', 'r': r'\d[\d,.]*', 'score': r'\d+', 'asn': r'\d+',
    'age': r'\d+ (?:day|days|months|years)',
}
_PLACEHOLDER = re.compile(r'\{([a-z_]+)\}')


def _compile(template):
    """An anchored regex for one catalog template, and how many literal characters it has."""
    parts, seen, last = [], set(), 0
    for match in _PLACEHOLDER.finditer(template):
        parts.append(re.escape(template[last:match.start()]))
        name = match.group(1)
        parts.append(f'(?P={name})' if name in seen else f'(?P<{name}>{PLACEHOLDER_PATTERNS.get(name, ".*?")})')
        seen.add(name)
        last = match.end()
    parts.append(re.escape(template[last:]))
    return re.compile(''.join(parts), re.DOTALL), len(_PLACEHOLDER.sub('', template))


def _templates(catalog):
    compiled = [(*_compile(english), turkish) for english, turkish in catalog.items() if _PLACEHOLDER.search(english)]
    # Most specific first: the template with the most literal text wins.
    return sorted(compiled, key=lambda item: -item[1])


TEMPLATES = {lang: _templates(catalog) for lang, catalog in CATALOGS.items()}


def _value(name, text, lang, depth):
    if name in VERBATIM:
        return text
    return translate(text, lang, depth + 1)


def translate(text, lang, _depth=0):
    """The catalog translation of one finished English sentence, or the sentence unchanged."""
    catalog = CATALOGS.get(lang)
    if not catalog or not isinstance(text, str) or not text or _depth > 3:
        return text
    if text in catalog:
        return catalog[text]
    for pattern, _, target in TEMPLATES[lang]:
        match = pattern.fullmatch(text)
        if match:
            values = {name: _value(name, value, lang, _depth) for name, value in match.groupdict().items()}
            return target.format(**values)
    return text


def translate_tally(text, lang):
    """'2 bad · 1 warning · 3 fine': each part separately."""
    if not isinstance(text, str) or not text:
        return text
    return TALLY_SEPARATOR.join(translate(part, lang) for part in text.split(TALLY_SEPARATOR))


def translate_plain(plain, lang):
    """A translated deep copy of a plain summary; the input itself is never changed."""
    if lang not in CATALOGS or not isinstance(plain, dict):
        return plain
    out = copy.deepcopy(plain)
    for key in TEXT_FIELDS:
        if isinstance(out.get(key), str):
            out[key] = translate(out[key], lang)
    if isinstance(out.get('tally'), str):
        out['tally'] = translate_tally(out['tally'], lang)
    for item in out.get('reasons') or []:
        if isinstance(item, dict):
            for key in ('title', 'detail'):
                if key in item:
                    item[key] = translate(item[key], lang)
    if isinstance(out.get('actions'), list):
        out['actions'] = [translate(action, lang) for action in out['actions']]
    for item in out.get('checks') or []:
        if isinstance(item, dict):
            for key in ('name', 'result'):
                if key in item:
                    item[key] = translate(item[key], lang)
    return out


def preferred_language(header):
    """The primary language of an Accept-Language header ('tr-TR,en;q=0.8' -> 'tr')."""
    if not isinstance(header, str):
        return ''
    first = header.split(',', 1)[0].split(';', 1)[0].strip()
    return first.split('-', 1)[0].lower()
