"""Operator switches for external data sources.

MYSCANNER_DISABLED_SOURCES is a comma-separated list of source names. A
disabled source is never contacted; checks report it as not configured, so
reports say what was not checked. This lets a source be turned off at once,
for example while its commercial terms are unconfirmed.
"""
import os

SOURCES = frozenset({
    'urlhaus',          # abuse.ch URL reputation
    'malwarebazaar',    # abuse.ch file hash reputation
    'abuse_ch_feeds',   # abuse.ch bulk feeds (URLhaus, MalwareBazaar, Feodo Tracker)
    'abuseipdb',        # IP community reports
    'web_risk',         # Google Web Risk lists
    'crtsh',            # certificate transparency search
    'pwnedpasswords',   # password breach ranges (k-anonymity)
    'phishtank',        # PhishTank feed
    'openphish',        # OpenPhish feed
    'dbip',             # DB-IP Lite IP location database (local file)
})


def disabled_sources():
    raw = os.environ.get('MYSCANNER_DISABLED_SOURCES', '')
    return {name.strip().lower() for name in raw.split(',') if name.strip()}


def source_enabled(name):
    if name not in SOURCES:
        raise ValueError(f'Unknown data source: {name}')
    return name not in disabled_sources()
