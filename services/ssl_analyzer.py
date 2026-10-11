"""One verified, pinned TLS connection; no synthetic certificate-lifetime grade."""
import hashlib
import ssl
import socket
from urllib.parse import urlsplit
from datetime import datetime, timezone
from services.safe_http import validate_public_url, normalize_url, public_connection, UnsafeTargetError, TargetResolutionError

class SSLAnalyzer:
    def analyze_certificate(self, domain):
        if not isinstance(domain,str) or not domain.strip() or len(domain)>2048:
            raise ValueError('Provide a domain or HTTPS URL of at most 2048 characters')
        normalized=normalize_url(domain.strip())
        parsed=urlsplit(normalized)
        if parsed.port not in (None,80,443):raise ValueError('Only standard website ports are supported')
        host=parsed.hostname
        checks=[{'name':name,'status':'unavailable'} for name in
                ('Public target','Verified handshake','Chain trust','Hostname identity','Validity period','Negotiated TLS','Certificate details')]
        checks[0]['status']='unavailable'
        report={'schema_version':2,'domain':host,'port':443,'status':'unavailable','valid':None,'grade':None,
                'scope':'One verified TLS handshake on port 443. Not a website safety assessment or an exhaustive TLS configuration audit.',
                'checks':checks,'findings':[],'analyzed_at':datetime.now(timezone.utc).isoformat(),
                'not_checked':['All supported TLS versions and cipher suites','OCSP/CRL revocation status','Certificate transparency completeness','HTTP security headers'],
                'connection_note':'Hostname/SNI retained; connection uses an address validated by the public-network policy.'}
        try:
            target=validate_public_url(normalized)
            checks[0]['status']='completed'
            context=ssl.create_default_context()
            with public_connection(host,timeout=8) as connection:
                with context.wrap_socket(connection,server_hostname=host) as tls:
                    cert=tls.getpeercert()
                    binary=tls.getpeercert(binary_form=True)
                    version=tls.version()
                    cipher=tls.cipher()
            if not cert or not binary:raise ValueError('No certificate')
            for index in (1,2,3):checks[index]['status']='completed'
            def name(parts):
                values={k:v for part in parts for k,v in part}
                return values.get('organizationName') or values.get('commonName') or 'Not provided'
            before=datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notBefore']),timezone.utc)
            after=datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']),timezone.utc)
            now=datetime.now(timezone.utc)
            remaining=(after-now).total_seconds()
            checks[4]['status']='completed' if before<=now<after else 'invalid'
            checks[5]['status']='completed' if version and cipher else 'unavailable'
            checks[6]['status']='completed'
            report.update(status='assessed',valid=before<=now<after,issuer=name(cert.get('issuer',())),
                subject=name(cert.get('subject',())),valid_from=before.isoformat(),valid_until=after.isoformat(),
                expiry_date=after.date().isoformat(),days_remaining=int(remaining//86400),
                tls_version=version,cipher={'name':cipher[0],'protocol_label':cipher[1],'secret_bits':cipher[2]} if cipher else None,
                serial_number=cert.get('serialNumber'),certificate_sha256=hashlib.sha256(binary).hexdigest(),
                subject_names=[v for k,v in cert.get('subjectAltName',()) if k in ('DNS','IP Address')][:100])
            if remaining<14*86400:
                report['findings'].append({'severity':'warning','title':'Certificate renewal window','detail':'The observed certificate expires in less than 14 days. Renewal may be automatic; monitor it.'})
            if version not in ('TLSv1.2','TLSv1.3'):
                report['findings'].append({'severity':'warning','title':'Review negotiated TLS','detail':'This connection did not negotiate TLS 1.2 or TLS 1.3.'})
        except TargetResolutionError:
            report.update(status='unavailable',reason_code='dns_unavailable',error_msg='Target DNS unavailable; certificate validity remains unknown.')
        except UnsafeTargetError:
            raise
        except ssl.SSLCertVerificationError:
            checks[1]['status']='invalid'
            report.update(status='invalid',valid=False,reason_code='certificate_verification_failed',
                          error_msg='Certificate verification failed. The trust chain, hostname or validity period did not pass verification.')
            report['findings'].append({'severity':'danger','title':'Certificate verification failed','detail':'Do not treat this connection as verified. The failed verification does not identify every certificate defect.'})
        except (socket.timeout,TimeoutError):
            report.update(reason_code='connection_timeout',error_msg='TLS connection timed out; certificate validity remains unknown.')
        except Exception:
            report.update(reason_code='tls_unavailable',error_msg='TLS observation unavailable; certificate validity remains unknown.')
        completed=sum(c['status'] in ('completed','invalid') for c in checks)
        report['assessment']={'score':round(completed/len(checks)*100),'checks_completed':completed,'checks_total':len(checks),
                              'label':'Observation coverage','warning':'Coverage is not a safety or TLS security score. Failed verification is a usable negative observation.'}
        report['coverage_status']='completed' if completed==len(checks) else 'partial'
        report['verdict']='verified_connection' if report['valid'] is True else 'verification_failed' if report['valid'] is False else 'unknown'
        report['summary']=[f"TLS observation for {host}:443.",
                           'Certificate verification passed.' if report['valid'] is True else report.get('error_msg','Certificate validity remains unknown.'),
                           f"{completed} of {len(checks)} observations available.",
                           'Negotiated protocol: '+str(report.get('tls_version') or 'unavailable')+'.',
                           'A verified connection does not establish that the website is safe; supported protocol enumeration and revocation checks were not performed.']
        report['recommendations']=['Monitor automatic certificate renewal and expiry.','Review the untested TLS configuration and revocation checks separately.']
        if report['valid'] is False:report['recommendations'].insert(0,'Review certificate trust, hostname and validity; do not bypass verification to declare success.')
        return report
