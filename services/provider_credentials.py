"""Optional provider credentials. Explicit file configuration takes precedence."""
import os

def abuseipdb_key():
    path = os.environ.get('ABUSEIPDB_API_KEY_FILE')
    if path:
        try:
            with open(path, encoding='utf-8') as source:
                value = source.read(4097).strip()
        except (OSError, UnicodeError):
            return None
    else:
        value = os.environ.get('ABUSEIPDB_API_KEY', '').strip()
    if not 16 <= len(value) <= 4095 or any(not 33 <= ord(c) <= 126 for c in value):
        return None
    return value
