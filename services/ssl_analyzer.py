# services/ssl_analyzer.py
import ssl
from services.safe_http import validate_public_url, public_connection, UnsafeTargetError
import socket
from datetime import datetime, timezone
import logging
logger = logging.getLogger(__name__)

class SSLAnalyzer:
    """تحليل متقدم لشهادات SSL"""
    
    def __init__(self):
        logger.info("✅ SSLAnalyzer initialized successfully")
    
    def analyze_certificate(self, domain: str) -> dict:
        logger.info(f"🔍 Starting SSL certificate analysis for: {domain}")
        """تحليل شهادة SSL للنطاق"""
        
        # تنظيف النطاق
        domain = validate_public_url(domain).hostname
        logger.debug(f"Cleaned domain: {domain}")
        
        try:
            logger.debug(f"Connecting to {domain}:443...")
            context = ssl.create_default_context()
            with public_connection(domain, timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    logger.debug(f"TLS version: {tls_version}")
            
            if not cert:
                logger.warning(f"No certificate found for {domain}")
                return {"valid": None, "status": "unavailable", "error_msg": "Certificate evidence unavailable"}
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days
            
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            
            # Grade calculation
            if days_remaining > 180:
                grade = 'A+'
            elif days_remaining > 90:
                grade = 'A'
            elif days_remaining > 60:
                grade = 'B'
            elif days_remaining > 30:
                grade = 'C'
            elif days_remaining > 0:
                grade = 'D'
            else:
                grade = 'F'
            
            if days_remaining <= 30:
                logger.warning(f"⚠️ SSL certificate for {domain} expires in {days_remaining} days (Grade: {grade})")
            else:
                logger.info(f"SSL certificate for {domain} valid for {days_remaining} days (Grade: {grade})")
            
            result = {
                "domain": domain,
                "status": "assessed",
                "scope": "Verified TLS handshake and certificate lifetime; not a website safety assessment.",
                "grade_scope": "Certificate lifetime only",
                "valid": not_after > now,
                "days_remaining": days_remaining,
                "issuer": issuer.get('organizationName', issuer.get('commonName', 'N/A')),
                "subject": subject.get('commonName', domain),
                "valid_from": not_before.strftime('%Y-%m-%d'),
                "valid_until": not_after.strftime('%Y-%m-%d'),
                "expiry_date": not_after.strftime('%B %d, %Y'),
                "tls_version": tls_version,
                "grade": grade,
                "serial_number": cert.get('serialNumber', 'N/A'),
            }
            
            logger.info(f"✅ SSL analysis completed for {domain} | Valid: {result['valid']} | Days: {days_remaining} | Grade: {grade}")
            return result
            
        except UnsafeTargetError:
            raise
        except ssl.SSLCertVerificationError:
            return {"domain":domain,"valid":False,"status":"invalid","grade":None,
                    "error_msg":"Certificate verification failed; trust or hostname validation failed."}
        except Exception:
            return {"domain":domain,"valid":None,"status":"unavailable","grade":None,
                    "error_msg":"TLS observation unavailable; no certificate validity conclusion."}
