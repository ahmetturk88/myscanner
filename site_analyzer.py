# site_analyzer.py - نسخة مبسطة للاختبار
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
from typing import Dict, Any
import time

class SiteAnalyzer:
    """تحليل المواقع الإلكترونية - نسخة مبسطة"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        
    def comprehensive_analysis(self, domain: str) -> Dict[str, Any]:
        """التحليل الشامل للموقع"""
        
        # تأكد من وجود http:// أو https://
        original_domain = domain
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        
        url = domain
        parsed = urlparse(url)
        clean_domain = parsed.netloc
        
        # محاولة الاتصال بالموقع
        response = None
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except:
            # جرب HTTP إذا فشل HTTPS
            try:
                url = 'http://' + clean_domain
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except Exception as e:
                return {
                    "error": f"Could not reach website: {str(e)}",
                    "domain": clean_domain
                }
        
        if not response or response.status_code != 200:
            return {
                "error": f"Website returned status code: {response.status_code if response else 'No response'}",
                "domain": clean_domain
            }
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # SSL Check
        ssl_result = self._check_ssl(clean_domain)
        
        # Security Headers
        headers_result = self._check_security_headers(url)
        
        # نتائج مبسطة
        results = {
            "domain": clean_domain,
            "url": url,
            "status": "success",
            "ssl": ssl_result,
            "security_headers": headers_result,
            "dns": {
                "a_records": [],
                "has_spf": False,
                "has_dmarc": False
            },
            "seo": {
                "title": soup.find('title').get_text().strip() if soup.find('title') else "No title",
                "description": "",
                "h1_tags": [h1.get_text().strip() for h1 in soup.find_all('h1')[:3]],
                "seo_score": 70
            },
            "performance": {
                "load_time_ms": 0,
                "grade": "Unknown"
            },
            "mobile_friendly": {
                "is_mobile_friendly": bool(soup.find('meta', attrs={'name': 'viewport'})),
                "viewport": bool(soup.find('meta', attrs={'name': 'viewport'}))
            },
            "security_score": 50,
            "verdict": "moderate",
            "recommendations": []
        }
        
        # حساب درجة الأمان
        security_score = 50
        recommendations = []
        
        if ssl_result.get("valid"):
            security_score += 30
        else:
            recommendations.append("⚠️ SSL certificate is invalid or missing")
        
        if headers_result.get("score", 0) > 50:
            security_score += 20
        else:
            recommendations.append("⚠️ Missing security headers (HSTS, CSP)")
        
        # تحديد الحكم
        if security_score >= 80:
            verdict = "secure"
        elif security_score >= 50:
            verdict = "moderate"
        else:
            verdict = "insecure"
        
        results["security_score"] = security_score
        results["verdict"] = verdict
        results["recommendations"] = recommendations
        
        return results
    
    def _check_ssl(self, domain: str) -> Dict[str, Any]:
        """فحص شهادة SSL"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            if not cert:
                return {"valid": False, "error": "No certificate found"}
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()
            days_remaining = (not_after - now).days
            
            return {
                "valid": days_remaining > 0,
                "days_remaining": days_remaining,
                "issuer": "Unknown",
                "grade": "A" if days_remaining > 90 else "B" if days_remaining > 30 else "C"
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """فحص رؤوس الأمان"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            security_headers = {
                "strict_transport_security": headers.get("Strict-Transport-Security", "Missing"),
                "content_security_policy": headers.get("Content-Security-Policy", "Missing"),
                "x_frame_options": headers.get("X-Frame-Options", "Missing"),
                "x_content_type_options": headers.get("X-Content-Type-Options", "Missing")
            }
            
            score = 0
            if security_headers["strict_transport_security"] != "Missing":
                score += 25
            if security_headers["content_security_policy"] != "Missing":
                score += 25
            if security_headers["x_frame_options"] != "Missing":
                score += 25
            if security_headers["x_content_type_options"] == "nosniff":
                score += 25
            
            return {
                "headers": security_headers,
                "score": score,
                "grade": "A" if score >= 75 else "B" if score >= 50 else "C" if score >= 25 else "D"
            }
        except Exception as e:
            return {"error": str(e), "score": 0, "grade": "F"}