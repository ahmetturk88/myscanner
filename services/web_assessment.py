"""Evidence-based, read-only web assessment. No engine-count or safety guarantees."""
from datetime import datetime, timezone
import ipaddress
import math
import os
import re
import ssl
import time
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup
import dns.exception
import dns.resolver
import requests

from services.safe_http import PublicHTTPSession, UnsafeTargetError, normalize_url, public_connection, validate_public_url
from services.url_scan_coverage import apply_phishing_evidence

REDIRECT_CODES = {301, 302, 303, 307, 308}
SHORTENERS = {'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rebrand.ly', 'shorturl.at'}


def provider_observation(external):
    """A usable unknown verdict is evidence, not a provider outage or safety."""
    base = {'name': 'url.vet', 'status': 'unavailable'}
    if not isinstance(external, dict):
        return dict(base, reason='Provider response format was invalid', reason_code='invalid_response')
    if external.get('error'):
        error = str(external['error']).lower()
        code = 'timeout' if 'timeout' in error else 'connection_failed' if 'connect' in error else 'http_error' if 'api error' in error else 'request_failed'
        return dict(base, reason='Provider request failed ('+code+')', reason_code=code)
    external = apply_phishing_evidence(dict(external))
    verdict = external.get('verdict')
    score = external.get('trust_score')
    try:
        valid_score = not isinstance(score, bool) and math.isfinite(float(score)) and 0 <= float(score) <= 100
    except (ValueError, TypeError):
        valid_score = False
    if verdict not in ('harmless', 'unknown', 'suspicious', 'malicious') or not valid_score:
        return dict(base, reason='Provider verdict or score format was invalid', reason_code='invalid_assessment')
    errors = external.get('errors') or []
    partial = bool(errors) or external.get('incomplete') is True
    result = dict(base, status='partial' if partial else 'completed', verdict=verdict, trust_score=float(score),
                  reason='Some provider checks were unavailable' if partial else 'Provider observations received',
                  reason_code='partial_evidence' if partial else 'observed', incomplete=partial,
                  error_count=len(errors) if isinstance(errors, list) else 1)
    for key in ('red_flags', 'green_flags', 'neutral_reasons'):
        items = external.get(key)
        result[key] = [item[:1000] for item in items[:20] if isinstance(item, str)] if isinstance(items, list) else []
    for key in ('phishing_status', 'evidence_warning', 'verdict_reported'):
        if isinstance(external.get(key), str): result[key] = external[key][:1000]
    return result


def dns_records(host, types=('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'), deadline=None):
    records = {}
    for kind in types:
        if deadline is not None and time.monotonic() >= deadline:
            records[kind] = {'status': 'unavailable', 'values': [], 'reason': 'Time budget reached'}
            continue
        try:
            answer = dns.resolver.resolve(host + '.', kind, search=False, lifetime=min(1.0, max(.1, deadline-time.monotonic())) if deadline else 1.0)
            records[kind] = {'status': 'completed', 'values': [str(r)[:512] for r in list(answer)[:16]], 'ttl': answer.rrset.ttl}
        except dns.resolver.NXDOMAIN:
            records[kind] = {'status': 'not_found', 'values': []}
        except dns.resolver.NoAnswer:
            records[kind] = {'status': 'no_record', 'values': []}
        except (dns.exception.DNSException, OSError):
            records[kind] = {'status': 'unavailable', 'values': [], 'reason': 'DNS lookup unavailable'}
    return records


def certificate_details(host, port=443, timeout=3):
    try:
        with public_connection(host, port, timeout) as tcp:
            with ssl.create_default_context().wrap_socket(tcp, server_hostname=host) as connection:
                cert = connection.getpeercert()
                expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
                issuer = dict(part for rdn in cert.get('issuer', ()) for part in rdn)
                return {'status': 'completed', 'verified': True, 'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                        'expires_at': expires.isoformat(), 'days_remaining': (expires-datetime.now(timezone.utc)).days,
                        'tls_version': connection.version(), 'cipher': connection.cipher()[0],
                        'subject_names': [v for k,v in cert.get('subjectAltName', ()) if k == 'DNS'][:20]}
    except UnsafeTargetError:
        return {'status': 'blocked', 'reason': 'Certificate connection blocked by public-network policy'}
    except ssl.SSLCertVerificationError:
        return {'status': 'invalid', 'verified': False, 'reason': 'Certificate identity or trust validation failed'}
    except (OSError, ssl.SSLError, ValueError, KeyError):
        return {'status': 'unavailable', 'reason': 'TLS handshake could not be completed'}


def response_chain(session, url, deadline):
    chain = []
    seen = set()
    for _ in range(6):
        if time.monotonic() >= deadline:
            return None, chain, 'Time budget reached before the next request'
        url = normalize_url(url)
        if url in seen:
            return None, chain, 'Redirect loop detected'
        seen.add(url)
        try:
            response = session.get(url, allow_redirects=False, timeout=(2, 3))
        except requests.exceptions.RequestException as error:
            error.scan_chain = chain
            raise
        chain.append({'url': url, 'status_code': response.status_code})
        if response.status_code not in REDIRECT_CODES:
            return response, chain, None
        location = response.headers.get('Location')
        response.close()
        if not location:
            return None, chain, 'Redirect response has no destination'
        destination = normalize_url(urljoin(url, location))
        chain[-1]['destination'] = destination
        # The public adapter validates and pins every destination again.
        url = destination
    return None, chain, 'Redirect limit reached (5 redirects)'


class WebAssessment:
    def analyze(self, value, include_provider=False):
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError('Enter an HTTP or HTTPS URL of at most 2048 characters')
        from services.safe_http import pasted_url
        url = normalize_url(pasted_url(value))
        validate_public_url(url)  # Reject private/mixed addresses before optional providers.
        parsed = urlsplit(url)
        deadline = time.monotonic() + 18
        findings = []
        def finding(code, severity, title, detail):
            findings.append({'code': code, 'severity': severity, 'title': title, 'detail': detail})
        structure = {'url': url, 'hostname': parsed.hostname, 'scheme': parsed.scheme, 'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
                     'path': parsed.path, 'query_parameter_count': len(parse_qsl(parsed.query, keep_blank_values=True)),
                     'length': len(url), 'internationalized_hostname': any(label.startswith('xn--') for label in parsed.hostname.split('.')),
                     'shortener': parsed.hostname in SHORTENERS}
        if parsed.scheme == 'http':
            finding('unencrypted_entry', 'warning', 'Unencrypted starting URL', 'The first connection uses HTTP; a later HTTPS redirect does not protect that initial request.')
        if structure['internationalized_hostname']:
            finding('idn', 'info', 'Internationalized hostname', 'Punycode is legitimate but can conceal look-alike names. Check the displayed hostname carefully.')
        if structure['shortener']:
            finding('shortener', 'info', 'Shortened URL', 'The visible URL hides the destination; inspect the redirect chain.')
        if len(url) > 300:
            finding('long_url', 'info', 'Long URL', 'Length alone is not a threat; inspect the hostname rather than the full text.')
        if any(key.lower() in ('url','redirect','next','return','continue') for key,_ in parse_qsl(parsed.query)):
            finding('redirect_parameter', 'info', 'Destination parameter present', 'This parameter may point elsewhere. Its presence does not prove an exploitable redirect.')
        from services import site_trust
        age_future = site_trust.start_age_lookup(url)  # WHOIS runs while the page is fetched
        page_text, page_inputs, password_any = None, [], False
        dns = dns_records(parsed.hostname, deadline=deadline)
        http = {'status': 'unavailable', 'chain': [], 'reason': 'HTTP assessment unavailable'}
        content = {'status': 'unavailable'}
        try:
            with PublicHTTPSession(response_limit=1024*1024, deadline=deadline) as session:
                session.headers.update({'User-Agent': 'MyScanner/1.0 (read-only security assessment)',
                                        'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.6'})  # the Turkish page, not the server's country
                response, chain, reason = response_chain(session, url, deadline)
                http['chain'] = chain
                if response is not None:
                    final = urlsplit(chain[-1]['url'])
                    headers = response.headers
                    http = {'status': 'completed', 'chain': chain, 'final_url': chain[-1]['url'], 'status_code': response.status_code,
                            'content_type': headers.get('Content-Type', '')[:160],
                            'security_headers': {k: headers.get(k, '')[:512] for k in ('Strict-Transport-Security','Content-Security-Policy','X-Content-Type-Options','Referrer-Policy','X-Frame-Options')}}
                    if parsed.scheme == 'http' and final.scheme == 'https':
                        # Typing http:// is how people write addresses; the site moved to HTTPS by itself.
                        for item in findings:
                            if item['code'] == 'unencrypted_entry':
                                item['severity'] = 'info'
                    if final.scheme == 'http' and parsed.scheme == 'https':
                        finding('https_downgrade', 'warning', 'HTTPS downgrade', 'The redirect chain ends on an unencrypted HTTP page.')
                    if final.hostname != parsed.hostname:
                        finding('host_change', 'info', 'Destination hostname changed', 'A different hostname is used after redirects. Review every destination.')
                    if response.status_code >= 400:
                        finding('http_error', 'info', 'Page returned an error', 'An HTTP error does not establish that a website is inactive or malicious.')
                    if 'html' in http['content_type'].lower() and response.status_code < 400:
                        soup = BeautifulSoup(response.content[:1024*1024], 'html.parser')
                        page_inputs = [(i.get('type', 'text'), i.get('name', ''), i.get('placeholder', '')) for i in soup.find_all('input', limit=200)]
                        password_any = any(str(kind).lower() == 'password' for kind, _, _ in page_inputs)
                        forms = []
                        for form in soup.find_all('form', limit=20):
                            try:
                                action = urljoin(http['final_url'], str(form.get('action') or ''))
                                dest = urlsplit(action)
                            except ValueError:
                                finding('invalid_form_action', 'info', 'Invalid form destination', 'A form destination could not be parsed. The form was not submitted.')
                                continue
                            password = form.find('input', attrs={'type': re.compile('^password$', re.I)}) is not None
                            forms.append({'action': action[:2048], 'method': str(form.get('method','get')).upper()[:12], 'password_input': password,
                                          'external_host': dest.hostname != final.hostname, 'unencrypted': dest.scheme == 'http'})
                            if password and (dest.scheme == 'http' or final.scheme == 'http'):
                                finding('password_http', 'warning', 'Password form uses HTTP', 'Credentials may be exposed in transit. Do not enter a password on this form.')
                            if password and dest.hostname != final.hostname:
                                finding('external_password_form', 'warning', 'Password form sends to another hostname', 'This may be legitimate single sign-on; verify the destination before entering credentials.')
                        content = {'status': 'completed', 'title': soup.title.get_text(' ', strip=True)[:200] if soup.title else '', 'forms': forms,
                                   'script_count': len(soup.find_all('script')), 'iframe_count': len(soup.find_all('iframe')),
                                   'sample_limited': len(response.content) > 1024*1024,
                                   'note': 'Static HTML only. Scripts, downloads and forms are never executed or submitted.',
                                   'description': str((soup.find('meta', attrs={'name':re.compile('^description$', re.I)}) or {}).get('content',''))[:500],
                                   'headings': [h.get_text(' ', strip=True)[:200] for h in soup.find_all(['h1','h2'],limit=10)],
                                   'image_count': len(soup.find_all('img')), 'images_missing_alt': len([img for img in soup.find_all('img') if not img.get('alt')]),
                                   'stylesheet_count': len(soup.find_all('link',rel='stylesheet')),
                                   'viewport': str((soup.find('meta',attrs={'name':re.compile('^viewport$',re.I)}) or {}).get('content',''))[:200]}
                        page_text = ' '.join(filter(None, [content['title'], content['description'], soup.get_text(' ', strip=True)[:200000]]))
                        from services.site_posture import page_observations
                        try:
                            set_cookies = response.raw.headers.getlist('Set-Cookie')
                        except AttributeError:
                            set_cookies = [headers['Set-Cookie']] if headers.get('Set-Cookie') else []
                        content['posture'] = page_observations(soup, response.text if len(response.content) <= 1024*1024 else response.content[:1024*1024].decode('utf-8', 'replace'),
                                                               http['final_url'], headers, set_cookies)

                    else:
                        content = {'status': 'not_applicable', 'reason': 'No successful HTML page was returned'}
                    response.close()
                else:
                    http['reason'] = reason
        except UnsafeTargetError as error:
            http['chain'] = getattr(error, 'scan_chain', [])
            http.update(status='blocked', reason='A destination or response was blocked by the public-network policy')
        except requests.exceptions.SSLError as error:
            http['chain'] = getattr(error, 'scan_chain', [])
            http.update(status='unavailable', reason='TLS validation failed')
            finding('tls_http_failure', 'warning', 'HTTPS connection could not be validated', 'Do not bypass certificate verification. Review the certificate details below.')
        except requests.exceptions.RequestException as error:
            http['chain'] = getattr(error, 'scan_chain', [])
            http['reason'] = 'Connection failed or timed out'
        final_url = http.get('final_url', url)
        final = urlsplit(final_url)
        tls = certificate_details(final.hostname, final.port or 443) if final.scheme == 'https' and time.monotonic() < deadline else {'status': 'not_applicable' if final.scheme != 'https' else 'unavailable', 'reason': 'No TLS on this URL' if final.scheme != 'https' else 'Time budget reached'}
        if tls['status'] == 'invalid':
            finding('invalid_certificate', 'warning', 'Certificate validation failed', tls['reason'])
        if tls.get('verified') and tls.get('days_remaining', 999) < 14:
            finding('expiry', 'info', 'Certificate expires soon', 'Renewal may be automatic. This is an operational observation, not evidence of malware.')
        provider = {'name': 'url.vet', 'status': 'not_requested', 'reason': 'Optional external analysis was not requested'}
        if include_provider and http['status'] == 'blocked':
            provider.update(status='not_requested', reason='External analysis was skipped after the local network policy blocked a destination')
        elif include_provider:
            if os.getenv('URLVET_URL') and time.monotonic() < deadline:
                try:
                    from services.urlvet_client import URLVetClient
                    client = URLVetClient(timeout=5)
                    try:
                        external = client.analyze_url(url)
                    finally:
                        client.session.close()
                    provider = provider_observation(external)
                except (requests.exceptions.RequestException, ValueError, TypeError, AttributeError):
                    provider.update(status='unavailable', reason='External analysis unavailable')
            else:
                provider.update(status='unavailable', reason='External analysis is not configured or the time budget was reached')
        trust, trust_findings = site_trust.assess(url, final_url, page_text, page_inputs, password_any, age_future)
        findings.extend(trust_findings)
        risk_status = trust['web_risk']['status']
        checks = [{'name':'URL structure','status':'completed'}, {'name':'DNS','status':'completed' if all(v['status'] != 'unavailable' for v in dns.values()) else 'partial'},
                  {'name':'HTTP / redirects','status':http['status']}, {'name':'TLS certificate','status':tls['status']}, {'name':'Static page','status':content['status']}, {'name':'url.vet','status':provider['status']},
                  # A missing Web Risk key is configuration, not a failed check. Many registries (.com.tr among them)
                  # publish no registration date, so a missing age never blocks a result.
                  {'name':'Google Web Risk','status':'completed' if risk_status in ('matched', 'not_found') else 'not_requested' if risk_status == 'not_configured' else 'unavailable'},
                  {'name':'Domain age','status':'completed' if trust['domain_age'].get('status') == 'completed' else 'not_applicable'}]
        selected_checks = [c for c in checks if c['status'] not in ('not_requested', 'not_applicable')]
        completed_checks = sum(c['status'] in ('completed', 'invalid') for c in selected_checks)
        complete = bool(selected_checks) and completed_checks == len(selected_checks)
        warnings = [f for f in findings if f['severity'] == 'warning']
        # An unconfirmed community phishing report alone does not block a clean result (same rule as URL
        # scans, url-evidence-v7); any warning observed here already makes the verdict suspicious.
        unconfirmed_only = provider.get('phishing_status') == 'unverified' and provider.get('verdict_reported') == 'harmless'
        if unconfirmed_only:
            findings.append({'code':'unverified_phishing_report','severity':'info','title':'Unconfirmed phishing report',
                             'detail':'A community phishing database has an unconfirmed report for this address; reviewers have not confirmed it.'})
        # url.vet is optional; when it was not requested, the local checks and Google Web Risk decide (site-trust-v1).
        # An error page or a download shows no page to judge, so it stays unknown.
        provider_clean = provider.get('verdict') == 'harmless' or unconfirmed_only or provider.get('status') == 'not_requested'
        if http['status'] != 'completed':
            # The site didn't answer: only evidence that needs no page (a listing, a copied name) can warn.
            warnings = [f for f in warnings if f['code'] not in ('unencrypted_entry',)]
        verdict = 'malicious' if provider.get('verdict') == 'malicious' or risk_status == 'matched' else 'suspicious' if warnings or provider.get('verdict') == 'suspicious' else 'clean' if complete and provider_clean and content['status'] == 'completed' else 'unknown'
        return {'schema_version':2, 'url':url, 'verdict':verdict, 'assessment_status':'completed' if complete else 'partial',
                'summary': 'A threat list reports this address as dangerous.' if verdict == 'malicious' else 'Caution: review the observed indicators before proceeding.' if verdict == 'suspicious' else 'No threat indicators observed in the completed checks. This is not a guarantee of safety.' if verdict == 'clean' else 'The available evidence cannot establish whether this URL is safe.',
                'analyzed_at':datetime.now(timezone.utc).isoformat(), 'structure':structure, 'dns':dns, 'http':http, 'tls':tls, 'content':content, 'provider':provider, 'trust':trust,
                'assessment_scope':'local_and_provider' if include_provider else 'local',
                'checks':checks, 'findings':findings, 'stats':{'checks_completed':completed_checks, 'checks_total':len(selected_checks), 'checks_not_requested':sum(c['status']=='not_requested' for c in checks), 'warning_count':len(warnings), 'redirect_count':max(0,len(http['chain'])-1)},
                'limitations':['Read-only HTTP, DNS and TLS observations; no exploit attempts.', 'No browser execution, malware detonation or exhaustive threat-engine coverage.', 'A valid certificate and a responsive host do not prove that a page is trustworthy.']}


