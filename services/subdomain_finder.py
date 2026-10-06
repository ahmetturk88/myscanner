"""Bounded DNS/CT discovery with explicit source and transport coverage."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import secrets
import time
from urllib.parse import urlsplit
import requests

from services.safe_http import PublicHTTPSession, UnsafeTargetError, normalize_url
from services.web_assessment import dns_records, certificate_details


def normalize_domain(value):
    if not isinstance(value, str) or not value or len(value) > 253 or '#' in value:
        raise ValueError('Enter a domain name, for example example.com')
    # Discovery accepts a hostname, never an arbitrary path/query/credential.
    url = normalize_url(value)
    parts = urlsplit(url)
    if parts.path != '/' or parts.query or parts.port is not None:
        raise ValueError('Enter only a hostname, without a path, query or port')
    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        return parts.hostname.rstrip('.')
    raise ValueError('Discovery requires a domain name, not an IP address')


class SubdomainFinder:
    COMMON_SUBDOMAINS = [
        # Basic
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
        'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'webdisk', 'cpanel', 'whm', 'autodiscover',
        'autoconfig', 'm', 'mobile', 'wap', 'secure', 'vpn', 'remote', 'dev', 'test',
        'stage', 'staging', 'demo', 'sandbox', 'beta', 'alpha', 'qa', 'devops',
        
        # Services
        'api', 'rest', 'graphql', 'oauth', 'auth', 'login', 'signin', 'account',
        'admin', 'administrator', 'manage', 'dashboard', 'control', 'panel',
        'backend', 'service', 'services', 'app', 'apps', 'application', 'portal',
        'my', 'mysite', 'site', 'website', 'home', 'start', 'new', 'old',
        
        # Cloud & Hosting
        'cloud', 'aws', 'azure', 'gcp', 'google', 'amazon', 'digitalocean',
        'heroku', 'netlify', 'vercel', 'firebase', 'cloudflare', 'cloudfront',
        's3', 'cdn', 'static', 'media', 'assets', 'images', 'img', 'video',
        'download', 'uploads', 'files', 'documents',
        
        # Development
        'git', 'github', 'gitlab', 'bitbucket', 'jenkins', 'jira', 'confluence',
        'wiki', 'docs', 'documentation', 'apidocs', 'swagger', 'redoc',
        'jenkins', 'sonar', 'nexus', 'artifactory', 'docker', 'registry',
        
        # Security
        'security', 'secure', 'sso', '2fa', 'mfa', 'totp', 'passport', 'auth',
        'cert', 'ssl', 'tls', 'encrypt', 'decrypt', 'crypto', 'vpn', 'proxy',
        
        # Monitoring
        'monitor', 'monitoring', 'status', 'health', 'healthcheck', 'ping',
        'metrics', 'stats', 'statistics', 'analytics', 'logs', 'logging',
        
        # Database
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
        'cassandra', 'mariadb', 'sql', 'nosql', 'dbadmin', 'phpmyadmin',
        
        # Marketing
        'www2', 'www3', 'blog', 'news', 'press', 'media', 'marketing', 'campaign',
        'landing', 'pages', 'lp', 'offers', 'promo', 'events', 'webinar',
        
        # E-commerce
        'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing',
        'invoice', 'orders', 'products', 'catalog', 'category', 'search',
        
        # Social
        'forum', 'community', 'chat', 'talk', 'discuss', 'feedback', 'support',
        'help', 'faq', 'knowledgebase', 'kb', 'tickets', 'contact',
        
        # Additional
        'server', 'host', 'hosting', 'web', 'webserver', 'appserver', 'database',
        'cache', 'proxy', 'loadbalancer', 'lb', 'firewall', 'gateway', 'router',
        'switch', 'storage', 'backup', 'archive', 'temp', 'tmp', 'logs'
    ]
    

    def __init__(self):
        self.max_workers = 8
        self.timeout = (1.5, 2)

    def certificate_names(self, domain, deadline):
        source = {'name':'Certificate Transparency (crt.sh)', 'status':'unavailable', 'candidate_count':0}
        names = set()
        try:
            with PublicHTTPSession(response_limit=2*1024*1024, deadline=deadline) as session:
                response = session.get('https://crt.sh/', params={'q':'%.'+domain, 'output':'json'}, timeout=(2, 4), allow_redirects=False)
                try:
                    if response.status_code != 200:
                        source['reason'] = 'Certificate index returned an unavailable response'
                        return names, source
                    data = response.json()
                finally:
                    response.close()
                if not isinstance(data, list):
                    raise ValueError('Invalid certificate index response')
                for row in data[:2000]:
                    if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
                        continue
                    for name in row['name_value'].splitlines()[:100]:
                        if '*' in name:
                            continue  # A wildcard certificate is not a discovered hostname.
                        try:
                            host = normalize_domain(name)
                        except (ValueError, UnsafeTargetError):
                            continue
                        if host.endswith('.'+domain):
                            names.add(host)
                source.update(status='completed', candidate_count=len(names), truncated=len(data)>2000)
        except (requests.exceptions.RequestException, ValueError, TypeError):
            source['reason'] = 'Certificate index timed out, was blocked, or returned invalid data'
        return names, source

    def wildcard_probe(self, domain, deadline):
        probes = [dns_records('myscanner-'+secrets.token_hex(8)+'.'+domain, ('A','AAAA','CNAME'), deadline) for _ in range(2)]
        sets = [{v for kind in ('A','AAAA') for v in probe[kind]['values']} for probe in probes]
        complete = all(r['status'] != 'unavailable' for p in probes for r in p.values())
        return {'status':'completed' if complete else 'partial', 'detected': all(bool(s) for s in sets),
                'addresses': sorted(set.union(*sets)), 'note':'Two random DNS labels were checked. Rotating wildcard DNS may have different addresses.'}

    def resolve_candidate(self, item, domain, deadline, wildcard):
        host, sources = item
        records = dns_records(host, ('A','AAAA','CNAME'), deadline)
        addresses = sorted({v for kind in ('A','AAAA') for v in records[kind]['values']})
        uncertain = any(r['status'] == 'unavailable' for r in records.values())
        exists = bool(addresses or records['CNAME']['values'])
        status = 'resolved' if exists else 'unavailable' if uncertain else 'not_found'
        possible_wildcard = bool(wildcard['detected'] and set(addresses).intersection(wildcard['addresses']))
        public = bool(addresses)
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
                if not address.is_global or address.is_multicast:
                    public = False
            except ValueError:
                public = False
        return {'subdomain':host[:-(len(domain)+1)], 'full_domain':host, 'sources':sources, 'dns':records,
                'addresses':addresses, 'ip':addresses[0] if addresses else None, 'dns_status':status, 'exists':exists,
                'possible_wildcard':possible_wildcard, 'public_addresses':public,
                'http':{'status':'not_requested'}, 'tls':{'status':'not_requested'}, 'verdict':'dns_only' if exists else status}

    def probe_web(self, row, deadline):
        if not row['public_addresses']:
            row['http'] = {'status':'blocked', 'reason':'No exclusively public addresses; no web request was sent'}
            row['verdict'] = 'blocked'
            return row
        if time.monotonic() >= deadline:
            row['http'] = {'status':'unavailable', 'reason':'Time budget reached before web inspection'}
            return row
        url = 'https://'+row['full_domain']+'/'
        try:
            with PublicHTTPSession(response_limit=65536, deadline=deadline) as session:
                session.headers['User-Agent'] = 'MyScanner/1.0 (read-only discovery)'
                response = session.head(url, timeout=self.timeout, allow_redirects=False)
                try:
                    code = response.status_code
                    row['http'] = {'status':'completed', 'url':url, 'status_code':code, 'location':response.headers.get('Location','')[:2048]}
                    row['verdict'] = 'redirect' if code in (301,302,303,307,308) else 'active' if code < 400 else 'http_error'
                finally:
                    response.close()
            row['tls'] = certificate_details(row['full_domain'], timeout=2) if time.monotonic() < deadline else {'status':'unavailable', 'reason':'Time budget reached'}
        except UnsafeTargetError:
            row['http'] = {'status':'blocked', 'reason':'Public-network policy blocked this connection'}
            row['verdict'] = 'blocked'
        except requests.exceptions.SSLError:
            row['http'] = {'status':'unavailable', 'reason':'HTTPS certificate validation failed'}
            row['tls'] = {'status':'invalid', 'verified':False, 'reason':'HTTPS certificate validation failed'}
        except requests.exceptions.RequestException:
            # Try HTTP only when HTTPS could not connect; do not follow redirects.
            if time.monotonic() < deadline:
                try:
                    with PublicHTTPSession(response_limit=65536, deadline=deadline) as session:
                        response = session.head('http://'+row['full_domain']+'/', timeout=self.timeout, allow_redirects=False)
                        try:
                            code = response.status_code
                            row['http'] = {'status':'completed', 'url':'http://'+row['full_domain']+'/', 'status_code':code, 'location':response.headers.get('Location','')[:2048], 'note':'HTTP observed; HTTPS connection was unavailable'}
                            row['verdict'] = 'redirect' if code in (301,302,303,307,308) else 'active' if code < 400 else 'http_error'
                            row['tls'] = {'status':'unavailable', 'reason':'HTTPS connection was unavailable'}
                            return row
                        finally:
                            response.close()
                except UnsafeTargetError:
                    row['http'] = {'status':'blocked', 'reason':'Public-network policy blocked this connection'}
                    row['verdict'] = 'blocked'
                    return row
                except requests.exceptions.RequestException:
                    pass
            row['http'] = {'status':'unavailable', 'reason':'Web connection unavailable; DNS still exists'}
        return row

    def find_subdomains(self, domain, max_subdomains=80, include_ct=True):
        domain = normalize_domain(domain)
        if isinstance(max_subdomains, bool) or not isinstance(max_subdomains, int) or not 1 <= max_subdomains <= 100:
            raise ValueError('Candidate limit must be between 1 and 100')
        start = time.monotonic()
        deadline = start + 20
        candidates = {}
        sources = []
        if include_ct:
            names, source = self.certificate_names(domain, deadline)
            sources.append(source)
            for host in sorted(names):
                candidates[host] = ['certificate_transparency']
        else:
            sources.append({'name':'Certificate Transparency (crt.sh)', 'status':'not_requested', 'candidate_count':0})
        common = list(dict.fromkeys(self.COMMON_SUBDOMAINS))
        for sub in common:
            candidates.setdefault(sub+'.'+domain, []).append('common_name')
        sources.append({'name':'Common-name DNS discovery', 'status':'completed', 'candidate_count':len(common)})
        selected = list(candidates.items())[:max_subdomains]
        wildcard = self.wildcard_probe(domain, deadline)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            rows = list(executor.map(lambda item: self.resolve_candidate(item, domain, deadline, wildcard), selected))
        found = [r for r in rows if r['exists']]
        # Preserve every DNS result; enrich only a documented bounded subset.
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            enriched = list(executor.map(lambda row:self.probe_web(row, deadline), found[:20]))
        found = enriched + found[20:]
        groups = {k:[r for r in found if r['verdict']==k] for k in ('active','redirect','http_error','dns_only','blocked')}
        groups['redirects'] = groups.pop('redirect')
        groups['inactive'] = []  # No HTTP response is not evidence of inactivity.
        unresolved = [r for r in rows if r['dns_status']=='unavailable']
        partial = bool(unresolved or any(s['status']=='unavailable' for s in sources) or wildcard['status']=='partial' or len(candidates)>len(selected) or len(found)>20 or any(r['http']['status'] not in ('completed','blocked') for r in found))
        return {'schema_version':2, 'domain':domain, 'assessment_status':'partial' if partial else 'completed',
                'analyzed_at':datetime.now(timezone.utc).isoformat(), 'duration_seconds':round(time.monotonic()-start,2),
                'total_checked':sum(r['dns_status']!='unavailable' for r in rows), 'candidates_selected':len(selected), 'candidates_available':len(candidates),
                'total_found':len(found), 'active_count':len(groups['active']), 'redirect_count':len(groups['redirects']), 'inactive_count':0,
                'dns_error_count':len(unresolved), 'not_found_count':sum(r['dns_status']=='not_found' for r in rows),
                'wildcard':wildcard, 'sources':sources, 'results':sorted(found,key=lambda r:r['full_domain']), 'unresolved':unresolved,
                'subdomains':groups, 'all_subdomains':sorted(r['full_domain'] for r in found),
                'limits':{'candidate_limit':max_subdomains,'web_probe_limit':20,'workers':self.max_workers,'time_budget_seconds':20},
                'limitations':['Discovery is a bounded sample, not a list of every possible subdomain.', 'Certificate names may be historical; DNS results reflect this lookup.', 'Wildcard matches are flagged, not claimed as confirmed independent hosts.', 'DNS errors are reported separately from names that do not resolve.', 'HTTP status and TLS validity do not prove safety. No redirects or exploit scans are performed during discovery.']}

    def check_subdomain(self, subdomain, domain):
        domain = normalize_domain(domain)
        host = normalize_domain(subdomain+'.'+domain)
        row = self.resolve_candidate((host,['common_name']), domain,time.monotonic()+10,{'detected':False,'addresses':[]})
        return self.probe_web(row,time.monotonic()+8) if row['exists'] else row

    def get_subdomain_suggestions(self, domain):
        domain = normalize_domain(domain)
        return [sub+'.'+domain for sub in list(dict.fromkeys(self.COMMON_SUBDOMAINS))[:10]]
