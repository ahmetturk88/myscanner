# url_analyzer.py - تحليل متقدم للروابط
import re
import socket
import dns.resolver
import ssl
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, Any, List, Optional
import Levenshtein

class URLAnalyzer:
    """تحليل متقدم للروابط قبل إرسالها إلى VirusTotal"""
    
    # قائمة النطاقات المختصرة المعروفة
    SHORTENED_DOMAINS = {
        'bit.ly', 'tinyurl.com', 'short.link', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 't.co', 'lnkd.in',
        'db.tt', 'qr.ae', 'cur.lv', 'bitly.com', 'tiny.cc', 'tr.im',
        'v.gd', 'da.gd', 'clck.ru', 'cutt.ly', 'rebrand.ly', 'shorturl.at'
    }
    
    # أنماط التصيد (Phishing Patterns)
    PHISHING_PATTERNS = [
        (r'login|signin|account|secure|verify|update|confirm', 'Suspicious keywords'),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP address instead of domain'),
        (r'@', 'Contains @ symbol (phishing characteristic)'),
        (r'-[a-z0-9]{5,}\.', 'Long random subdomain'),
        (r'\.(tk|ml|ga|cf|gq)$', 'Suspicious free TLD'),
        (r'bit\.ly|tinyurl|is\.gd|da\.gd', 'URL shortener'),
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
    
    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """تحليل بنية الرابط"""
        parsed = urlparse(url)
        
        result = {
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "has_query": bool(parsed.query),
            "query_params": len(parsed.query.split('&')) if parsed.query else 0,
            "has_fragment": bool(parsed.fragment),
            "length": len(url),
            "is_https": parsed.scheme == 'https',
            "contains_ip": bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
            "subdomain_count": parsed.netloc.count('.') - 1 if parsed.netloc else 0,
            "suspicious_chars": []
        }
        
        # كشف الأحرف المشبوهة
        suspicious_chars = []
        if '%' in url:
            suspicious_chars.append("URL encoded characters (%)")
        if '\\' in url:
            suspicious_chars.append("Backslash character")
        if '//' in url.replace('://', ''):
            suspicious_chars.append("Double slash")
        
        result["suspicious_chars"] = suspicious_chars
        
        # درجة ثقة الرابط
        trust_score = 100
        
        if not result["is_https"]:
            trust_score -= 30
        if result["contains_ip"]:
            trust_score -= 40
        if result["subdomain_count"] > 3:
            trust_score -= 15
        if result["length"] > 100:
            trust_score -= 10
        if result["query_params"] > 5:
            trust_score -= 10
        if suspicious_chars:
            trust_score -= len(suspicious_chars) * 10
        
        trust_score = max(0, min(100, trust_score))
        result["trust_score"] = trust_score
        
        if trust_score >= 80:
            result["trust_level"] = "High"
        elif trust_score >= 50:
            result["trust_level"] = "Medium"
        else:
            result["trust_level"] = "Low"
        
        return result
    
    def check_phishing_indicators(self, url: str) -> Dict[str, Any]:
        """كشف مؤشرات التصيد"""
        url_lower = url.lower()
        issues = []
        
        for pattern, description in self.PHISHING_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                issues.append(description)
        
        # كشف نطاقات مشابهة لنطاقات مشهورة (Typosquatting)
        popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']
        domain = urlparse(url).netloc.lower()
        
        for popular in popular_domains:
            if popular in domain and not domain.startswith(popular):
                ratio = Levenshtein.ratio(popular, domain.split('.')[0])
                if ratio > 0.7 and ratio < 1.0:
                    issues.append(f"Possible typosquatting of {popular}.com")
        
        # كشف النطاقات المختصرة
        parsed = urlparse(url)
        if parsed.netloc in self.SHORTENED_DOMAINS:
            issues.append("URL shortener detected - destination unknown")
        
        return {
            "is_phishing_suspected": len(issues) > 0,
            "issues": issues[:5],
            "risk_score": min(100, len(issues) * 20)
        }
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """فحص شهادة SSL للموقع"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
            
            if not cert:
                return {"valid": False, "error": "No certificate found"}
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()
            days_remaining = (not_after - now).days
            
            issuer = dict(x[0] for x in cert['issuer'])
            
            if days_remaining > 180:
                grade = "A+"
            elif days_remaining > 90:
                grade = "A"
            elif days_remaining > 30:
                grade = "B"
            elif days_remaining > 0:
                grade = "C"
            else:
                grade = "F"
            
            return {
                "valid": days_remaining > 0,
                "days_remaining": days_remaining,
                "issuer": issuer.get('organizationName', issuer.get('commonName', 'N/A')),
                "tls_version": tls_version,
                "grade": grade,
                "valid_from": not_before.strftime('%Y-%m-%d'),
                "valid_until": not_after.strftime('%Y-%m-%d')
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """فحص سجلات DNS للموقع"""
        result = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "has_spf": False,
            "has_dmarc": False
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result["a_records"] = [str(r) for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            result["aaaa_records"] = [str(r) for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result["mx_records"] = [{"preference": r.preference, "exchange": str(r.exchange).rstrip('.')} for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result["ns_records"] = [str(r).rstrip('.') for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for r in answers:
                txt_str = str(r).strip('"')
                result["txt_records"].append(txt_str)
                if 'v=spf1' in txt_str.lower():
                    result["has_spf"] = True
        except:
            pass
        
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_answers:
                if 'v=DMARC1' in str(r):
                    result["has_dmarc"] = True
                    break
        except:
            pass
        
        return result
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        """فحص رؤوس الأمان"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                "strict_transport_security": headers.get("Strict-Transport-Security", "Missing"),
                "content_security_policy": headers.get("Content-Security-Policy", "Missing"),
                "x_frame_options": headers.get("X-Frame-Options", "Missing"),
                "x_content_type_options": headers.get("X-Content-Type-Options", "Missing"),
                "x_xss_protection": headers.get("X-XSS-Protection", "Missing"),
                "referrer_policy": headers.get("Referrer-Policy", "Missing")
            }
            
            score = 0
            recommendations = []
            
            if security_headers["strict_transport_security"] != "Missing":
                score += 20
                if "max-age" in security_headers["strict_transport_security"]:
                    score += 5
            else:
                recommendations.append("Enable HSTS")
            
            if security_headers["content_security_policy"] != "Missing":
                score += 25
            else:
                recommendations.append("Implement CSP")
            
            if security_headers["x_frame_options"] != "Missing":
                score += 15
            else:
                recommendations.append("Set X-Frame-Options")
            
            if security_headers["x_content_type_options"] == "nosniff":
                score += 15
            else:
                recommendations.append("Set X-Content-Type-Options: nosniff")
            
            return {
                "headers": security_headers,
                "score": score,
                "grade": "A" if score >= 70 else "B" if score >= 50 else "C" if score >= 30 else "D",
                "recommendations": recommendations
            }
        except Exception as e:
            return {"error": str(e), "score": 0, "grade": "F"}
    
    def check_reputation(self, domain: str) -> Dict[str, Any]:
        """فحص سمعة النطاق"""
        # يمكن توسيعها لاستخدام APIs خارجية
        return {
            "age_days": None,
            "is_new": False,
            "risk_factors": []
        }
    
    def comprehensive_analysis(self, url: str) -> Dict[str, Any]:
        """التحليل الشامل للرابط"""
        
        # تنظيف الرابط
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        results = {
            "url": url,
            "domain": domain,
            "structure": self.analyze_url_structure(url),
            "phishing": self.check_phishing_indicators(url),
            "ssl": self.check_ssl_certificate(domain) if parsed.scheme == 'https' else {"valid": False, "error": "Not using HTTPS"},
            "dns": self.check_dns_records(domain),
            "security_headers": self.check_security_headers(url),
            "reputation": self.check_reputation(domain),
            "is_shortened": parsed.netloc in self.SHORTENED_DOMAINS
        }
        
        # حساب درجة الأمان الكلية
        security_score = 100
        
        if not results["structure"]["is_https"]:
            security_score -= 30
        if results["structure"]["contains_ip"]:
            security_score -= 25
        if results["phishing"]["is_phishing_suspected"]:
            security_score -= min(40, results["phishing"]["risk_score"])
        if results["ssl"].get("valid") == False:
            security_score -= 30
        if results["security_headers"].get("score", 0) < 50:
            security_score -= 15
        if results["is_shortened"]:
            security_score -= 10
        
        security_score = max(0, min(100, security_score))
        
        if security_score >= 80:
            verdict = "safe"
        elif security_score >= 50:
            verdict = "suspicious"
        else:
            verdict = "malicious"
        
        results["security_score"] = security_score
        results["verdict"] = verdict
        
        # جمع التوصيات
        recommendations = []
        
        if not results["structure"]["is_https"]:
            recommendations.append("🔒 Website does not use HTTPS - data transmitted insecurely")
        
        if results["phishing"]["is_phishing_suspected"]:
            for issue in results["phishing"]["issues"][:3]:
                recommendations.append(f"⚠️ {issue}")
        
        if results["security_headers"].get("recommendations"):
            for rec in results["security_headers"]["recommendations"][:3]:
                recommendations.append(f"🛡️ {rec}")
        
        if results["is_shortened"]:
            recommendations.append("🔗 URL shortener used - destination unknown until clicked")
        
        results["recommendations"] = recommendations
        
        return results