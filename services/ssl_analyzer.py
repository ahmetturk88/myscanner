# services/ssl_analyzer.py
import ssl
import socket
from datetime import datetime
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
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        logger.debug(f"Cleaned domain: {domain}")
        
        try:
            logger.debug(f"Connecting to {domain}:443...")
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    logger.debug(f"TLS version: {tls_version}")
            
            if not cert:
                logger.warning(f"No certificate found for {domain}")
                return {"valid": False, "error_msg": "No certificate found"}
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()
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
                "valid": days_remaining > 0,
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
            
        except socket.timeout:
            logger.error(f"Connection timeout for {domain}:443")
            return {"valid": False, "error_msg": "Connection timeout"}
        except ConnectionRefusedError:
            logger.error(f"Connection refused for {domain}:443 - SSL may not be enabled")
            return {"valid": False, "error_msg": "Connection refused - SSL may not be enabled"}
        except Exception as e:
            logger.error(f"Error analyzing SSL for {domain}: {str(e)}")
            return {"valid": False, "error_msg": str(e)}