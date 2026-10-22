"""Set which Android app builds the server tells to update (see services/app_release.py).

Run on the server from the repository root, once the new build is live on Google Play:

    python3 scripts/app_release.py                      # show the current settings
    python3 scripts/app_release.py --latest 12          # builds below 12 see "new version" (can skip)
    python3 scripts/app_release.py --latest 12 --min 12 # builds below 12 must update to continue

The values go into .env, which docker compose reads; then recreate the web service:
    dc up -d web
"""
import argparse
import os
import re

ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env')
KEYS = {'latest': 'MOBILE_LATEST_BUILD', 'min': 'MOBILE_MIN_BUILD'}


def read():
    try:
        with open(ENV) as handle:
            return handle.read()
    except FileNotFoundError:
        return ''


def current(text, key):
    found = re.search(rf'^{key}=(\d+)\s*$', text, re.M)
    return int(found.group(1)) if found else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--latest', type=int, help='newest versionCode live on Google Play')
    parser.add_argument('--min', type=int, help='oldest versionCode still allowed; older apps must update')
    args = parser.parse_args()
    text = read()
    changes = {KEYS[name]: value for name, value in (('latest', args.latest), ('min', args.min)) if value is not None}
    if any(value < 0 for value in changes.values()):
        parser.error('builds are positive numbers')
    latest = changes.get(KEYS['latest'], current(text, KEYS['latest']))
    minimum = changes.get(KEYS['min'], current(text, KEYS['min']))
    if minimum > latest:
        parser.error(f'--min {minimum} is above the latest build {latest}')
    for key, value in changes.items():
        line = f'{key}={value}'
        text = re.sub(rf'^{key}=.*$', line, text, flags=re.M) if re.search(rf'^{key}=', text, re.M) \
            else (text if not text or text.endswith('\n') else text + '\n') + line + '\n'
    if changes:
        with open(ENV, 'w') as handle:
            handle.write(text)
    print(f'Latest build: {latest or "off"}   Minimum build: {minimum or "off"}')
    if changes:
        print('Saved. Now run: dc up -d web')


if __name__ == '__main__':
    main()
