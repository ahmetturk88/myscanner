"""Download the free DB-IP Lite databases (IP location and network owner) for the IP check.

Run on the server from the repository root, then once a month (DB-IP publishes
a new file at the start of each month):

    python3 scripts/update_dbip.py

The files land in ./geoip, which compose mounts read-only into the app; the app
picks up a replaced file without a restart. Licence: CC BY 4.0, credited in the
IP report as "IP Geolocation by DB-IP". Uses only the standard library.
"""
import argparse
import datetime
import gzip
import os
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
URL = 'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz'
KINDS = ('city', 'asn')
MAX_SIZE = 512 * 1024 * 1024
AGENT = 'MyScanner-dbip-update/1.0 (+https://myscanners.com)'
# Every MaxMind DB file ends its data section with this marker before the metadata.
MARKER = b'\xab\xcd\xefMaxMind.com'


def months(today):
    """This month, then last month (the new file can appear a day or two late)."""
    first = today.replace(day=1)
    return [first.strftime('%Y-%m'), (first - datetime.timedelta(days=1)).strftime('%Y-%m')]


def download(kind, directory, today):
    for month in months(today):
        url = URL.format(kind=kind, month=month)
        try:
            # The download site refuses Python's default User-Agent (HTTP 403).
            request = urllib.request.Request(url, headers={'User-Agent': AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = gzip.decompress(response.read(MAX_SIZE + 1))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        if len(data) > MAX_SIZE or MARKER not in data[-256 * 1024:]:
            raise ValueError(f'{url} is not a valid database file')
        target = os.path.join(directory, f'dbip-{kind}-lite.mmdb')
        handle, temporary = tempfile.mkstemp(dir=directory, prefix='.dbip-')
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)  # atomic: a lookup never sees half a file
        return month, len(data)
    raise RuntimeError(f'No DB-IP {kind} database found for {" or ".join(months(today))}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--directory', default=os.path.join(ROOT, 'geoip'))
    args = parser.parse_args(argv)
    os.makedirs(args.directory, exist_ok=True)
    today = datetime.date.today()
    for kind in KINDS:
        try:
            month, size = download(kind, args.directory, today)
        except Exception as error:
            print(f'{kind}: failed: {error}', file=sys.stderr)
            return 1
        print(f'{kind}: {month} installed ({size // (1024 * 1024)} MB)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
