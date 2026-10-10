"""Read-only domain metadata. Coverage never represents safety."""
import ipaddress
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from services.safe_http import PublicHTTPSession, normalize_url, TargetResolutionError, UnsafeTargetError
from requests.exceptions import Timeout, ConnectionError, HTTPError

KINDS = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 5: 'CNAME', 6: 'SOA'}

class DomainAnalyzer:
    def __init__(self):
        self.deadline = time.monotonic() + 30
        self.session = PublicHTTPSession(response_limit=1024*1024, deadline=self.deadline)
        self.timeout = 5
        self.dns_evidence = {}

    def _json(self, url, params):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        response = self.session.get(url, params=params, timeout=min(self.timeout, remaining), allow_redirects=False)
        try:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        finally:
            response.close()

    @staticmethod
    def normalize(domain):
        if not isinstance(domain, str) or len(domain) > 2048 or '#' in domain:
            raise ValueError()
        parts = urlsplit(normalize_url(domain.strip()))
        host = parts.hostname
        if parts.path != '/' or parts.query or parts.fragment or parts.port not in (None, 80, 443):
            raise ValueError()
        if not host or len(host) > 253 or '.' not in host or host.endswith(('.local', '.localhost', '.internal', '.test', '.invalid')):
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError()
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError()
        return host

    def _get_dns_records(self, domain):
        records = []
        self.dns_evidence = {}
        for kind in KINDS.values():
            try:
                data = self._dns_json(domain, kind)
                if type(data.get('Status')) is not int or data['Status'] not in (0, 3):
                    raise ValueError()
                answers = data.get('Answer', [])
                if not isinstance(answers, list):
                    raise ValueError()
                parsed = []
                for answer in answers[:30]:
                    if not isinstance(answer, dict) or not isinstance(answer.get('data'), str) or type(answer.get('type')) is not int:
                        raise ValueError()
                    rr = {'type': KINDS.get(answer['type'], str(answer['type'])), 'value': answer['data'][:4096], 'name': str(answer.get('name', domain))[:253], 'ttl': answer.get('TTL') if type(answer.get('TTL')) is int else None}
                    parsed.append(rr)
                    if rr not in records:
                        records.append(rr)
                status = 'not_found' if data['Status'] == 3 else ('completed' if parsed else 'no_record')
                self.dns_evidence[kind] = {'status': status, 'records': parsed, 'dnssec_validated': data.get('AD') is True, 'limited': len(answers) > 30}
            except Exception as error:
                self.dns_evidence[kind] = {'status': 'unavailable', 'records': [], 'reason': self._failure_reason(error)}
        return records, 'assessed' if all(v['status'] != 'unavailable' for v in self.dns_evidence.values()) else 'unavailable'

    @staticmethod
    def _failure_reason(error):
        if isinstance(error, TargetResolutionError):
            return 'resolver_connection_dns_failed'
        if isinstance(error, UnsafeTargetError):
            return 'resolver_connection_blocked'
        if isinstance(error, (Timeout, TimeoutError)):
            return 'source_timeout'
        if isinstance(error, HTTPError):
            return 'source_http_error'
        if isinstance(error, ConnectionError):
            return 'source_connection_failed'
        return 'source_response_invalid'

    def _dns_json(self, domain, kind):
        # One bounded retry for transient transport failures; never bypass policy.
        try:
            return self._json('https://dns.google/resolve', {'name': domain, 'type': kind})
        except (TargetResolutionError, Timeout, ConnectionError) as error:
            if isinstance(error, UnsafeTargetError) and not isinstance(error, TargetResolutionError):
                raise
            if self.deadline - time.monotonic() < 2:
                raise
            return self._json('https://dns.google/resolve', {'name': domain, 'type': kind})

    @staticmethod
    def spf_observation(domain, evidence):
        txt = evidence.get('TXT', {})
        values = []
        for row in txt.get('records', []):
            if row.get('type') != 'TXT' or str(row.get('name', '')).lower().rstrip('.') != domain:
                continue
            raw = row.get('value', '')
            # DNS TXT presentation can contain multiple quoted chunks in one RR.
            chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
            value = ''.join(chunks) if raw.startswith('"') and chunks else raw
            if re.match(r'^v=spf1(?:\s|$)', value, re.I) and value not in values:
                values.append(value)
        return {'status': 'multiple_records' if len(values) > 1 else ('published' if values else ('unavailable' if txt.get('status') == 'unavailable' else 'not_found')), 'records': values, 'scope': 'Exact-domain TXT record count only; no sender-IP or full SPF policy evaluation.'}

    def _get_whois_info(self, domain):
        try:
            bootstrap = self._json('https://data.iana.org/rdap/dns.json', {})
            matches = []
            for suffixes, endpoints in bootstrap.get('services', []):
                for suffix in suffixes:
                    if domain == suffix or domain.endswith('.' + suffix):
                        matches.append((len(suffix), endpoints))
            endpoints = max(matches, key=lambda row: row[0])[1]
            endpoint = next(u for u in endpoints if isinstance(u, str) and u.startswith('https://'))
            data = self._json(endpoint.rstrip('/') + '/domain/' + domain, {})
            if data.get('objectClassName') != 'domain' or str(data.get('ldhName', '')).lower().rstrip('.') != domain:
                raise ValueError()
            dates = {}
            for event in data.get('events', []):
                if isinstance(event, dict) and isinstance(event.get('eventDate'), str):
                    dates[event.get('eventAction')] = event['eventDate']
            registrar = None
            for entity in data.get('entities', []):
                if isinstance(entity, dict) and 'registrar' in entity.get('roles', []):
                    vcard = entity.get('vcardArray', [])
                    if len(vcard) == 2 and isinstance(vcard[1], list):
                        registrar = next((v[3] for v in vcard[1] if isinstance(v, list) and len(v) == 4 and v[0] == 'fn' and isinstance(v[3], str)), None)
            result = {'_whois_status': 'assessed', 'registration_source': 'RDAP', 'registrar': registrar, 'created': dates.get('registration'), 'expires': dates.get('expiration'), 'whois_updated': dates.get('last changed'), 'nameservers': [n['ldhName'] for n in data.get('nameservers', [])[:20] if isinstance(n, dict) and isinstance(n.get('ldhName'), str)], 'status': [s for s in data.get('status', [])[:20] if isinstance(s, str)]}
            now = datetime.now(timezone.utc)
            for field, target in (('created', 'age_days'), ('expires', 'days_until_expiry')):
                try:
                    date = datetime.fromisoformat(result[field].replace('Z', '+00:00'))
                    if date.tzinfo is None:
                        date = date.replace(tzinfo=timezone.utc)
                    delta = (now-date).days if field == 'created' else (date-now).days
                    result[target] = delta if field != 'created' or delta >= 0 else None
                except (ValueError, TypeError, AttributeError):
                    result[target] = None
            return result
        except Exception:
            return {'_whois_status': 'unavailable', 'registration_source': 'RDAP'}

    def analyze_domain(self, domain):
        try:
            try:
                domain = self.normalize(domain)
            except Exception:
                return {'error': 'A valid public domain name is required', 'verdict': 'unknown'}
            result = {'schema_version': 2, 'domain': domain, 'registrar': None, 'created': None, 'expires': None, 'ip': None, 'country': None, 'isp': None, 'nameservers': [], 'verdict': 'unknown', 'scope': 'DNS and registration metadata only. No website, malware, mailbox or ownership verification.'}
            result['dns'], dns_status = self._get_dns_records(domain)
            result['dns_evidence'] = self.dns_evidence
            result['spf_observation'] = self.spf_observation(domain, self.dns_evidence)
            result['findings'] = []
            if result['spf_observation']['status'] == 'multiple_records':
                result['findings'].append({'severity': 'warning', 'code': 'multiple_spf', 'title': 'Multiple SPF records published', 'detail': 'More than one SPF TXT record was observed for this domain. SPF record selection returns PermError; consolidate authorized senders into one policy after reviewing your mail configuration.'})
            result.update(self._get_whois_info(domain))
            registration_status = result.pop('_whois_status')
            result['coverage'] = {'dns': dns_status, 'whois': registration_status}
            completed = sum(v['status'] != 'unavailable' for v in self.dns_evidence.values()) + (registration_status == 'assessed')
            result['assessment'] = {'checks_completed': completed, 'checks_total': 8, 'score': round(completed / 8 * 100), 'label': 'Metadata coverage', 'warning': 'Coverage is not a safety score.'}
            result['coverage_status'] = 'completed' if completed == 8 else 'partial'
            result['ip'] = next((r['value'] for r in result['dns'] if r['type'] == 'A'), None)
            result['analyzed_at'] = datetime.now(timezone.utc).isoformat()
            result['summary'] = [f"Metadata lookup for {domain}.", f"{completed} of 8 metadata checks returned usable responses.", f"{len(result['dns'])} DNS observations were returned; absence and outages are distinguished.", 'Registration data is available.' if registration_status == 'assessed' else 'Registration data could not be retrieved; this does not mean the domain is unregistered.', 'These observations do not establish that the domain is safe.']
            return result
        finally:
            self.session.close()

    def analyze_with_tip(self, domain, user_id=None):
        # Retained compatibility: a metadata lookup does not imply reputation checks.
        return self.analyze_domain(domain)
