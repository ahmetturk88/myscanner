"""Approximate IP location and network owner from the local DB-IP Lite databases.

The lookup never leaves the server. scripts/update_dbip.py downloads the
monthly files (CC BY 4.0, attribution required) into DBIP_DIRECTORY.
"""
import ipaddress
import math
import os
import threading
from pathlib import Path

import maxminddb

CITY_FILE = 'dbip-city-lite.mmdb'
ASN_FILE = 'dbip-asn-lite.mmdb'
SOURCE = 'DB-IP Lite'
ATTRIBUTION = 'IP Geolocation by DB-IP (https://db-ip.com)'

_lock = threading.Lock()
_readers = {}  # path -> (mtime, reader)


def directory():
    return Path(os.environ.get('DBIP_DIRECTORY') or Path(__file__).resolve().parents[1] / 'geoip')


def _reader(name):
    """A reader for one database file, reopened when the monthly update replaces it."""
    path = directory() / name
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    with _lock:
        cached = _readers.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        reader = maxminddb.open_database(str(path))
        if cached:
            cached[1].close()
        _readers[path] = (mtime, reader)
        return reader


def _text(value):
    return value[:512] if isinstance(value, str) and value else None


def _name(record, key):
    names = (record.get(key) or {}).get('names') if isinstance(record.get(key), dict) else None
    return _text(names.get('en')) if isinstance(names, dict) else None


def lookup(ip):
    """Location fields for a public IP, or None when no database is installed.

    Raises ValueError for an invalid address or a damaged database.
    """
    ip = str(ipaddress.ip_address(ip))
    city_reader, asn_reader = _reader(CITY_FILE), _reader(ASN_FILE)
    if city_reader is None and asn_reader is None:
        return None
    try:
        city = (city_reader.get(ip) if city_reader else None) or {}
        network = (asn_reader.get(ip) if asn_reader else None) or {}
    except maxminddb.InvalidDatabaseError as error:
        raise ValueError('IP location database is damaged') from error
    if not isinstance(city, dict) or not isinstance(network, dict):
        raise ValueError('Unexpected IP location record')
    country = city.get('country') if isinstance(city.get('country'), dict) else {}
    subdivisions = city.get('subdivisions') if isinstance(city.get('subdivisions'), list) else []
    location = city.get('location') if isinstance(city.get('location'), dict) else {}
    result = {
        'country': _name(city, 'country'),
        'country_code': _text(country.get('iso_code')),
        'city': _name(city, 'city'),
        'region': _name({'region': subdivisions[0]}, 'region') if subdivisions and isinstance(subdivisions[0], dict) else None,
        'continent': _name(city, 'continent'),
        'timezone': _text(location.get('time_zone')),
        'asn': network.get('autonomous_system_number') if type(network.get('autonomous_system_number')) is int and network['autonomous_system_number'] > 0 else None,
        'org': _text(network.get('autonomous_system_organization')),
    }
    result['isp'] = result['org']
    result['network_domain'] = None
    for key, source, bound in [('lat', 'latitude', 90), ('lon', 'longitude', 180)]:
        value = location.get(source)
        result[key] = value if type(value) in (int, float) and math.isfinite(value) and -bound <= value <= bound else None
    return result
