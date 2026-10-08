"""Generate or extend isolated local credentials without replacing existing values."""
from pathlib import Path
import os
import re
import secrets

KEYS = {'LOCAL_SECRET_KEY': 48, 'LOCAL_DB_PASSWORD': 32,
        'LOCAL_APP_DB_PASSWORD': 32, 'LOCAL_MIGRATION_DB_PASSWORD': 32}

def initialize(directory):
    target = Path(directory) / '.env.docker.local'
    lock = target.with_suffix(target.suffix + '.lock')
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        original = target.read_bytes() if target.exists() else b''
        if len(original) > 65536:
            raise RuntimeError('Local configuration is too large.')
        values = {}
        for line in original.decode('utf-8').splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                if key in KEYS:
                    if key in values or not re.fullmatch('[0-9a-f]{' + str(KEYS[key] * 2) + '}', value):
                        raise RuntimeError('Local credential format is invalid.')
                    values[key] = value
        missing = [key for key in KEYS if key not in values]
        if not missing:
            return False
        extra = '' if original else '# Local Docker only; never copy hosted credentials here.\n'
        if original and not original.endswith(b'\n'):
            extra += '\n'
        extra += ''.join(key + '=' + secrets.token_hex(KEYS[key]) + '\n' for key in missing)
        temporary = target.with_suffix(target.suffix + '.new')
        file_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(file_descriptor, 'wb') as output:
                output.write(original + extra.encode('utf-8'))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return True
    finally:
        lock.unlink(missing_ok=True)

if __name__ == '__main__':
    try:
        changed = initialize(Path(__file__).resolve().parents[1])
        print('Local configuration prepared.' if changed else 'Existing local configuration preserved.')
    except Exception:
        raise SystemExit('Local configuration could not be prepared; no credentials printed.')
