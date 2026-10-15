"""One verified, pinned TLS connection; no synthetic certificate-lifetime grade."""
import hashlib
import ssl
import socket
from urllib.parse import urlsplit
from datetime import datetime, timezone
from services.safe_http import validate_public_url, normalize_url, public_connection, UnsafeTargetError, TargetResolutionError

# OpenSSL verify codes mapped to the check they fail and a plain explanation.
VERIFY_REASONS = {
    9: ('not_yet_valid', 4, 'Certificate is not yet valid', 'The certificate validity period has not started yet.'),
    10: ('expired', 4, 'Certificate has expired', 'The certificate validity period has ended. Browsers will warn visitors.'),
    18: ('self_signed', 2, 'Self-signed certificate', 'The certificate is signed by itself, not by a trusted certificate authority.'),
    19: ('self_signed_chain', 2, 'Untrusted root in chain', 'The chain ends in a self-signed root that is not in the trusted store.'),
    20: ('untrusted_issuer', 2, 'Issuer not trusted', 'The issuing certificate could not be found or is not trusted.'),
    21: ('incomplete_chain', 2, 'Incomplete certificate chain', 'The server did not send the intermediate certificates needed to verify it.'),
    23: ('revoked', 2, 'Certificate revoked', 'The certificate has been revoked by its issuer.'),
    62: ('hostname_mismatch', 3, 'Hostname does not match', 'The certificate was not issued for this hostname.'),
}


def _hostname_matches(host, names):
    host = host.lower().rstrip('.')
    for name in names:
        name = name.lower().rstrip('.')
        if name == host or (name.startswith('*.') and '.' in host and host.split('.', 1)[1] == name[2:]):
            return True
    return False


class SSLAnalyzer:
    def _unverified_details(self, host):
        """Read the presented certificate without trusting it, to explain a failed verification."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with public_connection(host, timeout=8) as connection:
            with context.wrap_socket(connection, server_hostname=host) as tls:
                binary = tls.getpeercert(binary_form=True)
                version, cipher = tls.version(), tls.cipher()
        cert = x509.load_der_x509_certificate(binary)
        def name(value):
            for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
                attrs = value.get_attributes_for_oid(oid)
                if attrs:
                    return str(attrs[0].value)
            return 'Not provided'
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = [str(v) for v in sans.get_values_for_type(x509.DNSName)][:100]
        except x509.ExtensionNotFound:
            names = []
        before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
        return {'issuer': name(cert.issuer), 'subject': name(cert.subject), 'valid_from': before.isoformat(), 'valid_until': after.isoformat(),
                'expiry_date': after.date().isoformat(), 'days_remaining': int((after - datetime.now(timezone.utc)).total_seconds() // 86400),
                'serial_number': format(cert.serial_number, 'X'), 'certificate_sha256': hashlib.sha256(binary).hexdigest(), 'subject_names': names,
                'self_signed': cert.issuer == cert.subject, 'tls_version': version,
                'cipher': {'name': cipher[0], 'protocol_label': cipher[1], 'secret_bits': cipher[2]} if cipher else None,
                '_before': before, '_after': after}

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
        except ssl.SSLCertVerificationError as error:
            checks[1]['status']='invalid'
            reason=VERIFY_REASONS.get(getattr(error,'verify_code',None))
            report.update(status='invalid',valid=False,reason_code=reason[0] if reason else 'certificate_verification_failed',
                          error_msg=f'Certificate verification failed: {reason[2].lower()}.' if reason else 'Certificate verification failed. The trust chain, hostname or validity period did not pass verification.')
            if reason:checks[reason[1]]['status']='invalid'
            report['findings'].append({'severity':'danger','title':reason[2] if reason else 'Certificate verification failed',
                                       'detail':(reason[3]+' ' if reason else '')+'Do not treat this connection as verified.'})
            try:
                details=self._unverified_details(host)
            except Exception:
                details=None
            if details:
                before,after=details.pop('_before'),details.pop('_after')
                now=datetime.now(timezone.utc)
                # Facts read from the presented (untrusted) certificate; trust itself stays failed.
                checks[4]['status']='completed' if before<=now<after else 'invalid'
                checks[3]['status']='completed' if _hostname_matches(host,details['subject_names']) else 'invalid'
                if details['self_signed'] or (reason and reason[1]==2):checks[2]['status']='invalid'
                checks[5]['status']='completed' if details['tls_version'] else 'unavailable'
                checks[6]['status']='completed'
                report.update(details,details_unverified=True)
                report['connection_note']='Certificate details below were read from an untrusted handshake made only to explain the failure.'
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
