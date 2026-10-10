"""Bounded public-IP metadata and report evidence; never a safety probability."""
import ipaddress
import math
import time
from datetime import datetime, timezone
from services.safe_http import PublicHTTPSession, _public_address, TargetResolutionError, UnsafeTargetError
from requests.exceptions import Timeout, ConnectionError

class IPAnalyzer:
    def __init__(self):
        self.deadline = time.monotonic() + 25
        self.session = PublicHTTPSession(response_limit=1024*1024, deadline=self.deadline)
        self.timeout = 8

    @staticmethod
    def _text(value):
        return value[:512] if isinstance(value, str) and value else None

    def _json(self, url, **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        response = self.session.get(url, timeout=min(self.timeout, remaining), allow_redirects=False, **kwargs)
        try:
            if response.status_code != 200:
                error = ValueError()
                error.source_status = response.status_code
                raise error
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        finally:
            response.close()

    @staticmethod
    def _reason(error):
        if isinstance(error, TargetResolutionError): return 'source_dns_failed'
        if isinstance(error, UnsafeTargetError): return 'source_connection_blocked'
        if isinstance(error, (Timeout, TimeoutError)): return 'source_timeout'
        if isinstance(error, ConnectionError): return 'source_connection_failed'
        code = getattr(error, 'source_status', None)
        if code == 429: return 'rate_limited'
        if code in (401, 403): return 'source_access_denied'
        if type(code) is int: return 'source_http_error'
        return 'source_response_invalid'

    def _get_ip_info(self, ip):
        try:
            data = self._json('https://ipwho.is/' + ip)
            if data.get('success') is not True or str(ipaddress.ip_address(data.get('ip'))) != ip:
                raise ValueError()
            connection = data.get('connection', {})
            zone = data.get('timezone', {})
            if not isinstance(connection, dict) or not isinstance(zone, dict):
                raise ValueError()
            result = {'coverage': {'metadata': 'assessed'}, 'metadata_source': 'ipwho.is'}
            for key, source in {'country':'country','country_code':'country_code','city':'city','region':'region','continent':'continent'}.items():
                result[key] = self._text(data.get(source))
            for key in ('isp', 'org', 'domain'):
                result['network_domain' if key == 'domain' else key] = self._text(connection.get(key))
            result['asn'] = connection.get('asn') if type(connection.get('asn')) is int and connection['asn'] > 0 else None
            result['timezone'] = self._text(zone.get('id'))
            for key, source, bound in [('lat','latitude',90),('lon','longitude',180)]:
                value = data.get(source)
                result[key] = value if type(value) in (int, float) and math.isfinite(value) and -bound <= value <= bound else None
            result['metadata_note'] = 'Approximate network location; not a person, device or verified owner location.'
            return result
        except Exception as error:
            return {'coverage': {'metadata': 'unavailable'}, 'metadata_source': 'ipwho.is', 'metadata_reason': self._reason(error)}

    def _check_abuseipdb(self, ip, key):
        try:
            data = self._json('https://api.abuseipdb.com/api/v2/check', params={'ipAddress':ip,'maxAgeInDays':90}, headers={'Key':key,'Accept':'application/json'})['data']
            if not isinstance(data, dict) or str(ipaddress.ip_address(data.get('ipAddress'))) != ip:
                raise ValueError()
            score, reports = data['abuseConfidenceScore'], data['totalReports']
            if type(score) is not int or not 0 <= score <= 100 or type(reports) is not int or reports < 0:
                raise ValueError()
            result = {'status':'matched' if score > 0 or reports > 0 else 'not_found', 'score':score, 'reports':reports, 'window_days':90, 'source':'AbuseIPDB', 'scope':'Community reports in the requested 90-day window; not an independent malware verdict or universal blocklist.'}
            result['distinct_reporters'] = data.get('numDistinctUsers') if type(data.get('numDistinctUsers')) is int and data['numDistinctUsers'] >= 0 else None
            result['last_reported_at'] = self._text(data.get('lastReportedAt'))
            result['usage_type'] = self._text(data.get('usageType'))
            result['is_tor'] = data.get('isTor') if type(data.get('isTor')) is bool else None
            return result
        except Exception as error:
            return {'status':'unavailable','source':'AbuseIPDB','reason':self._reason(error)}

    def analyze_ip(self, ip, abuseipdb_api_key=None):
        try:
            try:
                if not isinstance(ip, str) or len(ip) > 64 or '%' in ip:
                    raise ValueError()
                address = ipaddress.ip_address(ip.strip())
                ip = str(address)
                if not _public_address(ip): raise ValueError()
            except (ValueError, TypeError):
                return {'error':'A public IPv4 or IPv6 address is required','verdict':'unknown'}
            result = {'schema_version':2,'ip':ip,'ip_version':address.version,'verdict':'unknown','is_proxy':None,'is_hosting':None,'is_mobile':None,'blacklist_count':None,'blacklist_results':[], 'scope':'Network metadata and AbuseIPDB community reports only; no port scan, target connection, malware execution or safety guarantee.'}
            result.update(self._get_ip_info(ip))
            reputation = self._check_abuseipdb(ip, abuseipdb_api_key) if abuseipdb_api_key else {'status':'not_configured','source':'AbuseIPDB','reason':'api_key_not_configured'}
            result['reputation'] = reputation
            result['reputation_status'] = reputation['status']
            result['coverage']['reputation'] = reputation['status']
            if reputation['status'] in ('matched','not_found'):
                result['abuse_score'] = reputation['score']
                result['total_reports'] = reputation['reports']
                # Legacy fields remain null: a report lookup is not a blocklist membership check.
                result['verdict'] = 'reported' if reputation['status'] == 'matched' else 'not_found'
            completed = sum(status in ('assessed','matched','not_found') for status in result['coverage'].values())
            result['assessment'] = {'score':completed*50,'checks_completed':completed,'checks_total':2,'label':'Source coverage','warning':'Source coverage is not a safety score. A returned source may omit individual fields.'}
            result['coverage_status'] = 'completed' if completed == 2 else 'partial'
            result['analyzed_at'] = datetime.now(timezone.utc).isoformat()
            result['findings'] = []
            if reputation['status'] == 'matched':
                result['findings'].append({'code':'abuse_reports','severity':'warning','title':'Community abuse reports observed','detail':f"AbuseIPDB returned {reputation['reports']} reports in 90 days and a provider confidence score of {reputation['score']}/100. Review the source evidence; reports do not prove every use of this shared IP is malicious."})
            result['summary'] = [f"Public IPv{address.version} address {ip}.", f"Network organization: {result.get('org') or result.get('isp') or 'unavailable'}; ASN: {result.get('asn') or 'unavailable'}.", f"Approximate network location: {result.get('country') or 'unavailable'}. This does not locate an individual.", f"AbuseIPDB returned {reputation['reports']} reports in its 90-day window." if reputation['status'] in ('matched','not_found') else 'AbuseIPDB evidence was not available; no reputation conclusion is possible.', 'Metadata and missing reports do not establish safety.']
            return result
        finally:
            self.session.close()

    def analyze_with_tip(self, ip, user_id=None):
        # Compatibility only; local-index coverage is not part of this lookup.
        return self.analyze_ip(ip)
