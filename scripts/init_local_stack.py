"""Generate isolated Docker test credentials, preserving any existing setup."""
from pathlib import Path
import os
import secrets


def initialize(directory):
    target = Path(directory) / '.env.docker.local'
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as output:
        output.write('# Local Docker tests only; do not publish or copy Render secrets here.\n')
        output.write('LOCAL_SECRET_KEY=' + secrets.token_hex(48) + '\n')
        output.write('LOCAL_DB_PASSWORD=' + secrets.token_hex(32) + '\n')
    return True


if __name__ == '__main__':
    created = initialize(Path(__file__).resolve().parents[1])
    print('Local configuration created.' if created else 'Existing local configuration preserved.')
