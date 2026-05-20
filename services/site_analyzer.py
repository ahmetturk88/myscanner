# services/site_analyzer.py
# =================================================================
# Site Analyzer - تحليل عميق وشامل للمواقع الإلكترونية
# =================================================================
# الميزات المتضمنة:
# 1. فحص الثغرات الأساسي (SQL Injection, XSS - Static Analysis)
# 2. تحليل رؤوس الأمان (Security Headers)
# 3. فحص شهادات TLS/SSL (الصلاحية، قوة التشفير، التاريخ)
# 4. تحليل robots.txt و sitemap.xml
# 5. فحص DNS كامل (A, AAAA, MX, NS, TXT, SPF, DMARC)
# 6. كشف التصيد (Phishing - Typosquatting, Keywords)
# 7. تحليل الأداء (وقت التحميل، الحجم، الموارد)
# 8. تحليل SEO (عنوان، وصف، كلمات مفتاحية، H1/H2)
# 9. فحص السمعة (Blacklists - اختياري مع API)
# 10. تخزين مؤقت للنتائج (Cache)
# 11. تقرير كامل مع درجة خطورة وتوصيات
# =================================================================

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import ssl
import socket
import dns.resolver
import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import time

# محاولة استيراد المكتبات الاختيارية
try:
    import Levenshtein
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False
    print("[WARNING] Levenshtein not installed. Run: pip install python-Levenshtein")

try:
    from OpenSSL import crypto
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False


class SiteAnalyzer:
    """
    التحليل العميق والشامل للمواقع الإلكترونية
    
    الاستخدام:
        analyzer = SiteAnalyzer()
        result = analyzer.comprehensive_analysis("example.com")
    """
    
    def __init__(self, cache_dir='cache/site_cache', cache_ttl=86400, use_external_scanners=False):
        """
        تهيئة المحلل
        
        Args:
            cache_dir: مجلد التخزين المؤقت
            cache_ttl: مدة صلاحية cache بالثواني (افتراضي 24 ساعة)
            use_external_scanners: استخدام Nikto/ZAP (يتطلب تثبيت)
        """
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self.use_external_scanners = use_external_scanners
        os.makedirs(cache_dir, exist_ok=True)
        
        # ============================================================
        # 1. أنماط كشف الثغرات (Vulnerability Patterns)
        # ============================================================
        
        # أنماط حقن SQL (SQL Injection Patterns)
        self.SQL_INJECTION_PATTERNS = [
            # أنماط في الكود المصدري
            (r"['\"]\s*\+\s*\$_(GET|POST|REQUEST|COOKIE)", "Potential SQL injection via concatenation"),
            (r"mysql_query\s*\(\s*['\"]\s*\$", "MySQL query with variable concatenation"),
            (r"mysqli_query\s*\(\s*['\"]\s*\$", "MySQLi query with variable concatenation"),
            (r"odbc_exec\s*\(\s*['\"]\s*\$", "ODBC query with variable concatenation"),
            (r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]\s*\$", "SELECT query with variable in WHERE"),
            (r"INSERT\s+INTO\s+.*\s+VALUES\s*\(\s*['\"]\s*\$", "INSERT query with variables"),
            (r"UPDATE\s+.*\s+SET\s+.*=\s*['\"]\s*\$", "UPDATE query with variables"),
            (r"DELETE\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]\s*\$", "DELETE query with variables"),
            # أنماط في استجابات الخادم
            (r"SQL syntax.*MySQL|You have an error in your SQL syntax", "MySQL error message leaked"),
            (r"Warning:\s+mysql_|mysqli_|pg_|odbc_", "Database function warning"),
            (r"Unclosed quotation mark|Microsoft OLE DB", "SQL Server error message"),
            (r"PostgreSQL.*ERROR|PG::Error", "PostgreSQL error message"),
        ]
        
        # أنماط XSS (Cross-Site Scripting Patterns)
        self.XSS_PATTERNS = [
            # أنماط في الكود المصدري
            (r"echo\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via echo with user input"),
            (r"print\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via print with user input"),
            (r"document\.write\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via document.write"),
            (r"innerHTML\s*=\s*\$_(GET|POST|REQUEST)", "Potential XSS via innerHTML"),
            (r"eval\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via eval"),
            (r"\.html\s*\(\s*\$_(GET|POST|REQUEST)", "jQuery .html() with user input"),
            (r"\.append\s*\(\s*\$_(GET|POST|REQUEST)", "jQuery .append() with user input"),
            # أنماط في استجابات الخادم
            (r"<script[^>]*>.*?</script>", "Script tag detected in response"),
            (r"onload=|onclick=|onmouseover=|onerror=", "Event handler attribute detected"),
            (r"javascript:", "JavaScript pseudo-protocol detected"),
            (r"alert\(|confirm\(|prompt\(", "JavaScript alert function detected"),
        ]
        
        # أنماط الثغرات الأخرى
        self.OTHER_VULNERABILITIES = [
            (r"include\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Local File Inclusion (LFI)"),
            (r"require\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Local File Inclusion (LFI)"),
            (r"file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)", "Potential File Disclosure"),
            (r"unserialize\s*\(\s*\$_(GET|POST|REQUEST)", "Potential PHP Object Injection"),
            (r"exec\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
            (r"system\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
            (r"passthru\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
            (r"shell_exec\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
            (r"popen\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
            (r"proc_open\s*\(\s*\$_(GET|POST|REQUEST)", "Potential Command Injection"),
        ]
        
        # الكلمات المفتاحية المشبوهة (للكشف عن التصيد)
        self.SUSPICIOUS_KEYWORDS = [
            'verify', 'confirm', 'update', 'account', 'login', 'signin', 
            'password', 'credit', 'card', 'paypal', 'bank', 'secure',
            'authenticate', 'validate', 'unlock', 'suspended', 'limited',
            'verify your account', 'confirm your identity', 'security alert'
        ]
        
        # النطاقات المختصرة
        self.SHORTENED_DOMAINS = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 't.co',
            'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'lnkd.in', 'db.tt',
            'qr.ae', 'cur.lv', 'bitly.com', 'tiny.cc', 'tr.im', 'v.gd'
        ]
        
        # النطاقات الشرعية (لقاعدة whitelist)
        self.LEGITIMATE_DOMAINS = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'yahoo.com', 'bing.com', 'duckduckgo.com'
        ]
    
    # ================================================================
    # 1. دوال التخزين المؤقت (Cache)
    # ================================================================
    
    def _get_cache_key(self, domain: str) -> str:
        """إنشاء مفتاح cache فريد للنطاق"""
        return hashlib.md5(domain.encode()).hexdigest()
    
    def _get_cached_result(self, domain: str) -> Optional[dict]:
        """استرجاع نتيجة من cache إذا كانت موجودة وصالحة"""
        cache_key = self._get_cache_key(domain)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['cached_at'])
                if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                    return cached['result']
            except Exception:
                pass
        return None
    
    def _save_cached_result(self, domain: str, result: dict):
        """حفظ نتيجة في cache"""
        cache_key = self._get_cache_key(domain)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'domain': domain,
                    'cached_at': datetime.now().isoformat(),
                    'result': result
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    
    # ================================================================
    # 2. فحص الثغرات الأساسي (Vulnerability Scan)
    # ================================================================
    
    def scan_vulnerabilities_static(self, html_content: str, url: str) -> Dict[str, Any]:
        """
        الفحص الساكن للثغرات (Static Analysis)
        يبحث في الكود المصدري للصفحة عن أنماط قد تشير إلى ثغرات
        """
        result = {
            "sql_injection": [],
            "xss": [],
            "other_vulnerabilities": [],
            "risk_score": 0,
            "total_findings": 0
        }
        
        # فحص SQL Injection
        for pattern, description in self.SQL_INJECTION_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["sql_injection"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
        # فحص XSS
        for pattern, description in self.XSS_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["xss"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
        # فحص ثغرات أخرى
        for pattern, description in self.OTHER_VULNERABILITIES:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["other_vulnerabilities"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
        # حساب درجة الخطورة
        result["total_findings"] = (len(result["sql_injection"]) + 
                                    len(result["xss"]) + 
                                    len(result["other_vulnerabilities"]))
        
        if result["total_findings"] > 10:
            result["risk_score"] = 80
        elif result["total_findings"] > 5:
            result["risk_score"] = 60
        elif result["total_findings"] > 0:
            result["risk_score"] = 30
        else:
            result["risk_score"] = 0
        
        return result
    
    def scan_vulnerabilities_dynamic(self, url: str) -> Dict[str, Any]:
        """
        الفحص الديناميكي للثغرات (Dynamic Analysis)
        يرسل طلبات اختبارية للكشف عن الثغرات
        """
        result = {
            "tested_endpoints": [],
            "sql_injection_suspected": False,
            "xss_suspected": False,
            "risk_score": 0,
            "details": []
        }
        
        # أنماط اختبارية لـ SQL Injection
        sql_test_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --"]
        
        # أنماط اختبارية لـ XSS
        xss_test_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
        
        # اختبار endpoints مختلفة
        parsed = urlparse(url)
        test_endpoints = [
            url,
            f"{parsed.scheme}://{parsed.netloc}/search?q=test",
            f"{parsed.scheme}://{parsed.netloc}/?id=1",
            f"{parsed.scheme}://{parsed.netloc}/page?param=value"
        ]
        
        for endpoint in test_endpoints[:3]:  # حد أقصى 3 endpoints لتجنب الإزعاج
            try:
                # اختبار SQL Injection
                for payload in sql_test_payloads:
                    test_url = f"{endpoint}{payload if '?' in endpoint else '?q=' + payload}"
                    response = self.session.get(test_url, timeout=10, allow_redirects=True)
                    
                    # فحص استجابة الخادم بحثاً عن أخطاء SQL
                    sql_errors = ["sql syntax", "mysql", "odbc", "driver", "unclosed quotation", 
                                 "microsoft ole db", "postgresql error", "ora-", "sqlite"]
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            result["sql_injection_suspected"] = True
                            result["details"].append(f"SQL error detected: {error} at {test_url[:100]}")
                            break
                
                # اختبار XSS
                for payload in xss_test_payloads:
                    test_url = f"{endpoint}{payload if '?' in endpoint else '?q=' + payload}"
                    response = self.session.get(test_url, timeout=10, allow_redirects=True)
                    
                    if payload.replace("'", '"') in response.text:
                        result["xss_suspected"] = True
                        result["details"].append(f"XSS payload reflected: {payload[:50]} at {test_url[:100]}")
                        break
                        
            except Exception:
                pass
        
        # حساب درجة الخطورة
        if result["sql_injection_suspected"]:
            result["risk_score"] += 50
        if result["xss_suspected"]:
            result["risk_score"] += 40
        
        result["risk_score"] = min(100, result["risk_score"])
        
        return result
    
    # ================================================================
    # 3. تحليل رؤوس الأمان (Security Headers)
    # ================================================================
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        """فحص وتحليل رؤوس الأمان HTTP"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                "strict_transport_security": headers.get("Strict-Transport-Security", "Missing"),
                "content_security_policy": headers.get("Content-Security-Policy", "Missing"),
                "x_frame_options": headers.get("X-Frame-Options", "Missing"),
                "x_content_type_options": headers.get("X-Content-Type-Options", "Missing"),
                "x_xss_protection": headers.get("X-XSS-Protection", "Missing"),
                "referrer_policy": headers.get("Referrer-Policy", "Missing"),
                "permissions_policy": headers.get("Permissions-Policy", "Missing"),
                "cross_origin_opener_policy": headers.get("Cross-Origin-Opener-Policy", "Missing"),
                "cross_origin_embedder_policy": headers.get("Cross-Origin-Embedder-Policy", "Missing"),
                "cache_control": headers.get("Cache-Control", "Missing")
            }
            
            # تحليل وتقييم كل رأس
            analysis = {}
            score = 0
            max_score = 100
            
            # HSTS
            if security_headers["strict_transport_security"] != "Missing":
                analysis["hsts"] = {"status": "present", "value": security_headers["strict_transport_security"][:100]}
                if "max-age=31536000" in security_headers["strict_transport_security"]:
                    score += 12
                    analysis["hsts"]["quality"] = "good"
                elif "max-age" in security_headers["strict_transport_security"]:
                    score += 8
                    analysis["hsts"]["quality"] = "medium"
                else:
                    score += 5
                    analysis["hsts"]["quality"] = "low"
            else:
                analysis["hsts"] = {"status": "missing", "recommendation": "Enable HSTS with max-age=31536000"}
            
            # CSP
            if security_headers["content_security_policy"] != "Missing":
                analysis["csp"] = {"status": "present", "value": security_headers["content_security_policy"][:100]}
                score += 15
                if "default-src 'none'" in security_headers["content_security_policy"]:
                    score += 5
                    analysis["csp"]["quality"] = "excellent"
                elif "default-src 'self'" in security_headers["content_security_policy"]:
                    score += 3
                    analysis["csp"]["quality"] = "good"
                else:
                    analysis["csp"]["quality"] = "medium"
            else:
                analysis["csp"] = {"status": "missing", "recommendation": "Implement Content Security Policy (CSP)"}
                score -= 10
            
            # X-Frame-Options
            if security_headers["x_frame_options"] != "Missing":
                analysis["xfo"] = {"status": "present", "value": security_headers["x_frame_options"]}
                if security_headers["x_frame_options"] == "DENY":
                    score += 12
                    analysis["xfo"]["quality"] = "excellent"
                elif security_headers["x_frame_options"] == "SAMEORIGIN":
                    score += 8
                    analysis["xfo"]["quality"] = "good"
                else:
                    score += 4
                    analysis["xfo"]["quality"] = "low"
            else:
                analysis["xfo"] = {"status": "missing", "recommendation": "Set X-Frame-Options: DENY"}
            
            # X-Content-Type-Options
            if security_headers["x_content_type_options"] == "nosniff":
                analysis["xcto"] = {"status": "present", "value": security_headers["x_content_type_options"], "quality": "good"}
                score += 10
            else:
                analysis["xcto"] = {"status": "missing", "recommendation": "Set X-Content-Type-Options: nosniff"}
            
            # X-XSS-Protection
            if security_headers["x_xss_protection"] != "Missing":
                analysis["xxp"] = {"status": "present", "value": security_headers["x_xss_protection"]}
                if "block" in security_headers["x_xss_protection"].lower():
                    score += 8
                    analysis["xxp"]["quality"] = "good"
                else:
                    score += 4
                    analysis["xxp"]["quality"] = "low"
            else:
                analysis["xxp"] = {"status": "missing", "recommendation": "Set X-XSS-Protection: 1; mode=block"}
            
            # Referrer-Policy
            if security_headers["referrer_policy"] != "Missing":
                analysis["referrer"] = {"status": "present", "value": security_headers["referrer_policy"]}
                score += 8
                analysis["referrer"]["quality"] = "good"
            else:
                analysis["referrer"] = {"status": "missing", "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin"}
            
            # Permissions-Policy
            if security_headers["permissions_policy"] != "Missing":
                analysis["permissions"] = {"status": "present", "value": security_headers["permissions_policy"][:100]}
                score += 5
            else:
                analysis["permissions"] = {"status": "missing", "recommendation": "Consider implementing Permissions-Policy"}
            
            score = max(0, min(100, score))
            
            # تحديد الدرجة
            if score >= 80:
                grade = "A"
            elif score >= 60:
                grade = "B"
            elif score >= 40:
                grade = "C"
            elif score >= 20:
                grade = "D"
            else:
                grade = "F"
            
            return {
                "headers": security_headers,
                "analysis": analysis,
                "score": score,
                "grade": grade,
                "recommendations": [v["recommendation"] for k, v in analysis.items() if "recommendation" in v]
            }
            
        except Exception as e:
            return {"error": str(e), "score": 0, "grade": "F", "recommendations": []}
    
    # ================================================================
    # 4. فحص شهادات TLS/SSL (متقدم)
    # ================================================================
    
    def check_ssl_advanced(self, domain: str) -> Dict[str, Any]:
        """فحص متقدم لشهادة TLS/SSL"""
        result = {
            "valid": False,
            "domain": domain,
            "issuer": None,
            "subject": None,
            "version": None,
            "serial_number": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": 0,
            "days_since_issue": 0,
            "signature_algorithm": None,
            "tls_version": None,
            "cipher_strength": None,
            "certificate_chain": [],
            "vulnerabilities": [],
            "grade": "F",
            "risk_score": 0
        }
        
        try:
            # إنشاء سياق SSL
            context = ssl.create_default_context()
            
            # الاتصال بالمنفذ 443
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    tls_version = ssock.version()
                    result["tls_version"] = tls_version
                    
                    # فحص قوة التشفير
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher_strength"] = f"{cipher[0]} ({cipher[1]} bits)"
                    
                    # استخدام pyOpenSSL للحصول على تفاصيل إضافية
                    if SSL_AVAILABLE:
                        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                        result["issuer"] = x509.get_issuer().CN
                        result["subject"] = x509.get_subject().CN
                        result["version"] = x509.get_version()
                        result["serial_number"] = hex(x509.get_serial_number())
                        result["signature_algorithm"] = x509.get_signature_algorithm().decode()
                        
                        # تواريخ الصلاحية
                        not_before = datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
                        not_after = datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                        
                        result["valid_from"] = not_before.strftime('%Y-%m-%d')
                        result["valid_until"] = not_after.strftime('%Y-%m-%d')
                        
                        now = datetime.utcnow()
                        result["days_remaining"] = (not_after - now).days
                        result["days_since_issue"] = (now - not_before).days
                        result["valid"] = result["days_remaining"] > 0
                        
                        # فحص سلسلة الشهادات
                        cert_chain = []
                        for i in range(x509.get_extension_count()):
                            ext = x509.get_extension(i)
                            cert_chain.append({
                                "name": ext.get_short_name().decode(),
                                "critical": ext.get_critical()
                            })
                        result["certificate_chain"] = cert_chain[:10]
            
            # تحديد درجة SSL
            if not result["valid"]:
                result["grade"] = "F"
                result["risk_score"] = 80
                result["vulnerabilities"].append("Certificate expired or invalid")
            elif result["days_remaining"] < 7:
                result["grade"] = "D"
                result["risk_score"] = 60
                result["vulnerabilities"].append(f"Certificate expires in {result['days_remaining']} days")
            elif result["days_remaining"] < 30:
                result["grade"] = "C"
                result["risk_score"] = 40
                result["vulnerabilities"].append(f"Certificate expires soon ({result['days_remaining']} days)")
            elif result["days_remaining"] < 90:
                result["grade"] = "B"
                result["risk_score"] = 20
            else:
                result["grade"] = "A"
                result["risk_score"] = 0
            
            # فحص TLS version
            if result["tls_version"] and "TLSv1.0" in result["tls_version"]:
                result["vulnerabilities"].append("Outdated TLS version (1.0) - vulnerable to attacks")
                result["risk_score"] += 30
            elif result["tls_version"] and "TLSv1.1" in result["tls_version"]:
                result["vulnerabilities"].append("Outdated TLS version (1.1) - consider upgrading")
                result["risk_score"] += 20
            
            # فحص قوة التشفير
            if result["cipher_strength"] and "256" not in result["cipher_strength"]:
                if "128" in result["cipher_strength"]:
                    result["vulnerabilities"].append("Medium cipher strength (128-bit)")
                    result["risk_score"] += 10
                else:
                    result["vulnerabilities"].append("Weak cipher strength detected")
                    result["risk_score"] += 20
            
            result["risk_score"] = min(100, result["risk_score"])
            
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["risk_score"] = 50
        except ConnectionRefusedError:
            result["error"] = "Connection refused - SSL may not be enabled"
            result["risk_score"] = 50
        except Exception as e:
            result["error"] = str(e)
            result["risk_score"] = 50
        
        return result
    
    # ================================================================
    # 5. تحليل robots.txt و sitemap.xml
    # ================================================================
    
    def analyze_robots_txt(self, domain: str) -> Dict[str, Any]:
        """تحليل ملف robots.txt"""
        result = {
            "exists": False,
            "content": None,
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps": [],
            "user_agents": [],
            "sensitive_paths_found": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        sensitive_patterns = [
            'admin', 'config', 'backup', 'wp-admin', 'phpmyadmin', '.git',
            '.env', 'password', 'secret', 'private', 'internal', 'api'
        ]
        
        try:
            robots_url = f"{domain}/robots.txt"
            response = self.session.get(robots_url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                result["exists"] = True
                content = response.text
                result["content"] = content[:2000]  # أول 2000 حرف
                
                # تحليل المحتوى
                for line in content.split('\n'):
                    line = line.strip().lower()
                    
                    if line.startswith('user-agent:'):
                        agent = line.replace('user-agent:', '').strip()
                        if agent:
                            result["user_agents"].append(agent)
                    
                    elif line.startswith('disallow:'):
                        path = line.replace('disallow:', '').strip()
                        if path and path != '/':
                            result["disallowed_paths"].append(path)
                            
                            # فحص المسارات الحساسة
                            for pattern in sensitive_patterns:
                                if pattern in path:
                                    result["sensitive_paths_found"].append({
                                        "path": path,
                                        "pattern": pattern,
                                        "risk": "medium"
                                    })
                    
                    elif line.startswith('allow:'):
                        path = line.replace('allow:', '').strip()
                        if path:
                            result["allowed_paths"].append(path)
                    
                    elif 'sitemap:' in line:
                        sitemap_url = line.replace('sitemap:', '').strip()
                        result["sitemaps"].append(sitemap_url)
                
                # حساب درجة الخطورة
                if result["sensitive_paths_found"]:
                    result["risk_score"] = min(70, len(result["sensitive_paths_found"]) * 10)
                    result["recommendations"].append("Remove sensitive paths from robots.txt")
                
                if result["sitemaps"]:
                    result["recommendations"].append("Ensure sitemap doesn't expose sensitive URLs")
                
            elif response.status_code == 404:
                result["exists"] = False
                result["recommendations"].append("Consider adding robots.txt for SEO")
            else:
                result["exists"] = False
                result["error"] = f"HTTP {response.status_code}"
                
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def analyze_sitemap(self, domain: str) -> Dict[str, Any]:
        """تحليل ملف sitemap.xml"""
        result = {
            "exists": False,
            "urls": [],
            "total_urls": 0,
            "sensitive_urls_found": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        sensitive_patterns = ['admin', 'config', 'backup', 'private', 'internal', 'test', 'debug']
        
        sitemap_urls = [
            f"{domain}/sitemap.xml",
            f"{domain}/sitemap_index.xml",
            f"{domain}/sitemap.gz"
        ]
        
        for sitemap_url in sitemap_urls[:2]:
            try:
                response = self.session.get(sitemap_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    result["exists"] = True
                    content = response.text
                    
                    # استخراج URLs من sitemap
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(content)
                        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                        
                        for loc in root.findall('.//ns:loc', namespace):
                            url_text = loc.text if loc.text else ""
                            if url_text:
                                result["urls"].append(url_text[:200])
                                
                                # فحص URLs الحساسة
                                for pattern in sensitive_patterns:
                                    if pattern in url_text.lower():
                                        result["sensitive_urls_found"].append({
                                            "url": url_text[:100],
                                            "pattern": pattern
                                        })
                    except ET.ParseError:
                        # ليس XML صالح
                        pass
                    
                    break
                    
            except Exception:
                continue
        
        result["total_urls"] = len(result["urls"])
        
        if result["sensitive_urls_found"]:
            result["risk_score"] = min(50, len(result["sensitive_urls_found"]) * 5)
            result["recommendations"].append("Review sitemap for sensitive URLs")
        
        return result
    
    # ================================================================
    # 6. فحص DNS كامل
    # ================================================================
    
    def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """فحص جميع سجلات DNS"""
        result = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "soa_record": None,
            "has_spf": False,
            "has_dmarc": False,
            "spf_record": None,
            "dmarc_record": None,
            "risk_score": 0,
            "warnings": []
        }
        
        try:
            # A Records
            answers = dns.resolver.resolve(domain, 'A')
            result["a_records"] = [str(r) for r in answers]
        except:
            result["warnings"].append("No A records found")
        
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            result["aaaa_records"] = [str(r) for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result["mx_records"] = [{"preference": r.preference, "exchange": str(r.exchange).rstrip('.')} for r in answers]
        except:
            result["warnings"].append("No MX records - email may not work")
            result["risk_score"] += 15
        
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result["ns_records"] = [str(r).rstrip('.') for r in answers]
        except:
            result["warnings"].append("No NS records found")
            result["risk_score"] += 20
        
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            result["cname_records"] = [str(r).rstrip('.') for r in answers]
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for r in answers:
                txt_str = str(r).strip('"')
                result["txt_records"].append(txt_str[:200])
                if 'v=spf1' in txt_str.lower():
                    result["has_spf"] = True
                    result["spf_record"] = txt_str[:200]
        except:
            pass
        
        try:
            soa = dns.resolver.resolve(domain, 'SOA')
            for r in soa:
                result["soa_record"] = {
                    "mname": str(r.mname).rstrip('.'),
                    "rname": str(r.rname).rstrip('.'),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
        except:
            pass
        
        # فحص DMARC
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_answers:
                txt_str = str(r).strip('"')
                if 'v=DMARC1' in txt_str:
                    result["has_dmarc"] = True
                    result["dmarc_record"] = txt_str[:200]
                    break
        except:
            pass
        
        # حساب درجة الخطورة
        if not result["has_spf"]:
            result["warnings"].append("No SPF record - email spoofing possible")
            result["risk_score"] += 15
        
        if not result["has_dmarc"]:
            result["warnings"].append("No DMARC record - email authentication weak")
            result["risk_score"] += 15
        
        result["risk_score"] = min(100, result["risk_score"])
        
        return result
    
    # ================================================================
    # 7. كشف مؤشرات التصيد (Phishing Detection)
    # ================================================================
    
    def check_phishing_indicators(self, domain: str, soup: BeautifulSoup = None) -> Dict[str, Any]:
        """كشف مؤشرات التصيد المتقدمة"""
        issues = []
        risk_score = 0
        domain_lower = domain.lower()
        
        # 1. فحص Typosquatting (نطاقات مشابهة لنطاقات مشهورة)
        popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                          'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
                          'yahoo', 'bing', 'dropbox', 'adobe', 'wordpress']
        
        for popular in popular_domains:
            if popular in domain_lower and not domain_lower.startswith(popular):
                if LEVENSHTEIN_AVAILABLE:
                    ratio = Levenshtein.ratio(popular, domain_lower.split('.')[0])
                    if ratio > 0.7 and ratio < 1.0:
                        issues.append(f"Possible typosquatting of {popular}.com (similarity: {ratio:.0%})")
                        risk_score += 25
                else:
                    # فحص بسيط بدون Levenshtein
                    if len(popular) - len(domain_lower.split('.')[0]) <= 2:
                        issues.append(f"Possible typosquatting of {popular}.com")
                        risk_score += 20
        
        # 2. فحص النطاقات المختصرة
        parsed = urlparse(f"https://{domain}")
        if parsed.netloc in self.SHORTENED_DOMAINS:
            issues.append("Domain is a URL shortener - destination unknown")
            risk_score += 15
        
        # 3. فحص نطاقات free TLD المشبوهة
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site']
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                issues.append(f"Suspicious TLD: {tld} - commonly used for phishing")
                risk_score += 15
                break
        
        # 4. فحص الأرقام في النطاق (نطاقات عشوائية)
        if re.search(r'\d{5,}', domain_lower):
            issues.append("Domain contains long number sequence - possible random generation")
            risk_score += 10
        
        # 5. فحص محتوى الصفحة إذا كان متاحاً
        if soup:
            text_lower = soup.get_text().lower()
            
            # كلمات مفتاحية مشبوهة
            suspicious_found = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in text_lower]
            if suspicious_found:
                issues.append(f"Suspicious keywords found: {', '.join(suspicious_found[:3])}")
                risk_score += min(30, len(suspicious_found) * 5)
            
            # فحص نماذج تسجيل الدخول
            has_login_form = False
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'password'}):
                    has_login_form = True
                    break
            
            if has_login_form and domain not in self.LEGITIMATE_DOMAINS:
                issues.append("Login form detected on non-legitimate domain")
                risk_score += 20
            
            # فحص شعارات PayPal/Amazon/Google (قد تكون مزيفة)
            logo_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple']
            for keyword in logo_keywords:
                if keyword in text_lower and keyword not in domain_lower:
                    issues.append(f"Logo/brand '{keyword}' mentioned but domain mismatch")
                    risk_score += 15
                    break
        
        risk_score = min(100, risk_score)
        
        return {
            "is_phishing_suspected": len(issues) > 0,
            "issues": issues[:8],
            "risk_score": risk_score,
            "severity": "high" if risk_score > 60 else "medium" if risk_score > 30 else "low"
        }
    
    # ================================================================
    # 8. فحص السمعة (Reputation Check)
    # ================================================================
    
    def check_reputation(self, domain: str) -> Dict[str, Any]:
        """فحص سمعة الموقع"""
        result = {
            "is_blacklisted": False,
            "blacklist_sources": [],
            "risk_score": 0,
            "details": []
        }
        
        # يمكن توسيعها لاستخدام APIs خارجية مثل:
        # - Google Safe Browsing API
        # - VirusTotal API
        # - AbuseIPDB API
        
        # فحص بسيط للقوائم السوداء المعروفة (محلي)
        # هذا مجرد مثال - يتطلب API حقيقي للفحص الفعلي
        
        return result
    
    # ================================================================
    # 9. تحليل الأداء
    # ================================================================
    
    def analyze_performance(self, url: str) -> Dict[str, Any]:
        """تحليل أداء الموقع"""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout)
            load_time = (time.time() - start_time) * 1000  # مللي ثانية
            
            page_size = len(response.content) / 1024  # KB
            
            soup = BeautifulSoup(response.text, 'html.parser')
            resources = {
                "images": len(soup.find_all('img')),
                "scripts": len(soup.find_all('script')),
                "stylesheets": len(soup.find_all('link', rel='stylesheet')),
                "total": 0
            }
            resources["total"] = resources["images"] + resources["scripts"] + resources["stylesheets"]
            
            # التقييم
            if load_time < 500:
                grade = "A+"
                score = 100
            elif load_time < 1000:
                grade = "A"
                score = 85
            elif load_time < 2000:
                grade = "B"
                score = 70
            elif load_time < 4000:
                grade = "C"
                score = 50
            elif load_time < 8000:
                grade = "D"
                score = 30
            else:
                grade = "F"
                score = 10
            
            return {
                "load_time_ms": round(load_time, 2),
                "page_size_kb": round(page_size, 2),
                "resource_count": resources["total"],
                "resources_breakdown": resources,
                "grade": grade,
                "score": score,
                "risk_score": 0 if grade in ['A+', 'A'] else 10 if grade == 'B' else 20 if grade == 'C' else 35
            }
        except Exception as e:
            return {"error": str(e), "grade": "Unknown", "score": 0, "risk_score": 0}
    
    # ================================================================
    # 10. التحليل الشامل الكامل
    # ================================================================
    
    def comprehensive_analysis(self, domain: str) -> Dict[str, Any]:
        """
        التحليل الشامل للموقع - يجمع جميع الميزات في تقرير واحد
        """
        
        # التحقق من cache
        cached_result = self._get_cached_result(domain)
        if cached_result:
            cached_result['from_cache'] = True
            return cached_result
        
        # تنظيف النطاق
        original_domain = domain
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        
        url = domain
        parsed = urlparse(url)
        clean_domain = parsed.netloc
        
        # محاولة الاتصال بالموقع
        response = None
        html_content = ""
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            final_url = response.url
            html_content = response.text
        except:
            try:
                url = 'http://' + clean_domain
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                final_url = response.url
                html_content = response.text
            except Exception as e:
                return {
                    "error": f"Could not reach website: {str(e)}",
                    "domain": clean_domain,
                    "from_cache": False
                }
        
        if not response:
            return {
                "error": "No response from website",
                "domain": clean_domain,
                "from_cache": False
            }
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # ============================================================
        # تنفيذ جميع التحليلات
        # ============================================================
        
        # 1. فحص الثغرات
        vulnerabilities_static = self.scan_vulnerabilities_static(html_content, final_url)
        vulnerabilities_dynamic = self.scan_vulnerabilities_dynamic(final_url)
        
        # 2. رؤوس الأمان
        security_headers = self.check_security_headers(final_url)
        
        # 3. شهادة SSL
        ssl_result = self.check_ssl_advanced(clean_domain)
        
        # 4. robots.txt و sitemap
        robots_txt = self.analyze_robots_txt(f"{parsed.scheme}://{clean_domain}")
        sitemap = self.analyze_sitemap(f"{parsed.scheme}://{clean_domain}")
        
        # 5. سجلات DNS
        dns_records = self.check_dns_records(clean_domain)
        
        # 6. مؤشرات التصيد
        phishing = self.check_phishing_indicators(clean_domain, soup)
        
        # 7. السمعة
        reputation = self.check_reputation(clean_domain)
        
        # 8. الأداء
        performance = self.analyze_performance(final_url)
        
        # 9. SEO وتحليل المحتوى
        seo = {
            "title": soup.find('title').get_text().strip() if soup.find('title') else "No title",
            "description": "",
            "keywords": "",
            "h1_tags": [h1.get_text().strip() for h1 in soup.find_all('h1')[:5]],
            "h2_tags": [h2.get_text().strip() for h2 in soup.find_all('h2')[:5]],
            "has_meta_description": bool(soup.find('meta', attrs={'name': 'description'})),
            "has_meta_keywords": bool(soup.find('meta', attrs={'name': 'keywords'})),
            "images_without_alt": len([img for img in soup.find_all('img') if not img.get('alt')]),
            "total_images": len(soup.find_all('img')),
            "seo_score": 70
        }
        
        # حساب درجة SEO
        seo_score = 100
        if not seo["title"] or len(seo["title"]) < 10:
            seo_score -= 20
        if not seo["has_meta_description"]:
            seo_score -= 20
        if seo["images_without_alt"] > 5:
            seo_score -= 10
        if seo["images_without_alt"] > seo["total_images"] * 0.5:
            seo_score -= 15
        seo["seo_score"] = max(0, seo_score)
        
        # 10. التوافق مع الجوال
        mobile = {
            "has_viewport": bool(soup.find('meta', attrs={'name': 'viewport'})),
            "is_mobile_friendly": bool(soup.find('meta', attrs={'name': 'viewport'})),
            "viewport_content": soup.find('meta', attrs={'name': 'viewport'}).get('content', '') if soup.find('meta', attrs={'name': 'viewport'}) else None
        }
        
        # 11. إحصائيات عامة
        stats = {
            "internal_links": len([a for a in soup.find_all('a', href=True) if a['href'].startswith('/') or clean_domain in a['href']]),
            "external_links": len([a for a in soup.find_all('a', href=True) if a['href'].startswith('http') and clean_domain not in a['href']]),
            "scripts": len(soup.find_all('script')),
            "external_scripts": len([s for s in soup.find_all('script', src=True) if clean_domain not in s.get('src', '')]),
            "images": len(soup.find_all('img')),
            "forms": len(soup.find_all('form')),
            "iframes": len(soup.find_all('iframe'))
        }
        
        # ============================================================
        # حساب درجة الأمان الكلية
        # ============================================================
        
        total_risk_score = 0
        risk_factors = []
        
        # SSL (وزن 25%)
        total_risk_score += ssl_result.get("risk_score", 0) * 0.25
        
        # Security Headers (وزن 20%)
        total_risk_score += (100 - security_headers.get("score", 0)) * 0.20
        
        # الثغرات (وزن 25%)
        vuln_score = max(vulnerabilities_static.get("risk_score", 0), 
                        vulnerabilities_dynamic.get("risk_score", 0))
        total_risk_score += vuln_score * 0.25
        
        # التصيد (وزن 15%)
        total_risk_score += phishing.get("risk_score", 0) * 0.15
        
        # DNS (وزن 10%)
        total_risk_score += dns_records.get("risk_score", 0) * 0.10
        
        # robots.txt (وزن 5%)
        total_risk_score += robots_txt.get("risk_score", 0) * 0.05
        
        total_risk_score = min(100, int(total_risk_score))
        security_score = 100 - total_risk_score
        
        # تحديد الحكم النهائي
        if security_score >= 80:
            verdict = "secure"
            verdict_icon = "✅"
            severity = "low"
            severity_color = "green"
        elif security_score >= 60:
            verdict = "moderate"
            verdict_icon = "⚠️"
            severity = "medium"
            severity_color = "yellow"
        elif security_score >= 40:
            verdict = "risky"
            verdict_icon = "🔴"
            severity = "high"
            severity_color = "orange"
        else:
            verdict = "insecure"
            verdict_icon = "💀"
            severity = "critical"
            severity_color = "red"
        
        # جمع التوصيات
        recommendations = []
        
        # توصيات SSL
        if not ssl_result.get("valid"):
            recommendations.append("🔒 Install a valid SSL certificate immediately")
        elif ssl_result.get("days_remaining", 0) < 30:
            recommendations.append(f"⚠️ SSL certificate expires in {ssl_result.get('days_remaining')} days - renew soon")
        
        if ssl_result.get("vulnerabilities"):
            for vuln in ssl_result["vulnerabilities"][:2]:
                recommendations.append(f"🔐 {vuln}")
        
        # توصيات رؤوس الأمان
        for rec in security_headers.get("recommendations", [])[:3]:
            recommendations.append(f"🛡️ {rec}")
        
        # توصيات الثغرات
        if vulnerabilities_static.get("total_findings", 0) > 0:
            recommendations.append(f"🔍 {vulnerabilities_static['total_findings']} potential vulnerabilities found - review code")
        
        if vulnerabilities_dynamic.get("sql_injection_suspected"):
            recommendations.append("💉 Potential SQL injection vulnerability - sanitize inputs")
        
        if vulnerabilities_dynamic.get("xss_suspected"):
            recommendations.append("⚠️ Potential XSS vulnerability - encode outputs")
        
        # توصيات التصيد
        if phishing.get("is_phishing_suspected"):
            for issue in phishing.get("issues", [])[:2]:
                recommendations.append(f"🎣 {issue}")
        
        # توصيات DNS
        if not dns_records.get("has_spf"):
            recommendations.append("📧 Add SPF record to prevent email spoofing")
        if not dns_records.get("has_dmarc"):
            recommendations.append("📧 Add DMARC record for email authentication")
        
        # توصيات robots.txt
        if robots_txt.get("sensitive_paths_found"):
            recommendations.append("📁 Remove sensitive paths from robots.txt")
        
        # توصيات الأداء
        if performance.get("grade") in ["D", "F"]:
            recommendations.append(f"⚡ Poor performance ({performance.get('load_time_ms', 0)}ms) - optimize website")
        
        # توصيات SEO
        if seo.get("seo_score", 0) < 50:
            recommendations.append("📈 Improve SEO: add meta description and optimize titles")
        
        if not mobile.get("has_viewport"):
            recommendations.append("📱 Add viewport meta tag for mobile optimization")
        
        if not recommendations:
            recommendations.append("✅ No critical issues detected - website appears secure")
        
        # إزالة التكرارات
        recommendations = list(dict.fromkeys(recommendations))[:10]
        
        # ============================================================
        # تجميع النتيجة النهائية
        # ============================================================
        
        result = {
            "domain": clean_domain,
            "url": final_url,
            "status": "success",
            "from_cache": False,
            "timestamp": datetime.now().isoformat(),
            
            # نتائج التحليل
            "vulnerabilities": {
                "static": vulnerabilities_static,
                "dynamic": vulnerabilities_dynamic,
                "overall_risk": vuln_score
            },
            "security_headers": security_headers,
            "ssl": ssl_result,
            "robots_txt": robots_txt,
            "sitemap": sitemap,
            "dns": dns_records,
            "phishing": phishing,
            "reputation": reputation,
            "performance": performance,
            "seo": seo,
            "mobile": mobile,
            "stats": stats,
            
            # النتيجة النهائية
            "security_score": security_score,
            "risk_score": total_risk_score,
            "verdict": verdict,
            "verdict_icon": verdict_icon,
            "severity": severity,
            "severity_color": severity_color,
            "risk_factors": risk_factors[:5],
            "recommendations": recommendations,
            
            # ملخص سريع
            "summary": {
                "has_ssl": ssl_result.get("valid", False),
                "has_hsts": security_headers.get("headers", {}).get("strict_transport_security") != "Missing",
                "has_csp": security_headers.get("headers", {}).get("content_security_policy") != "Missing",
                "vulnerabilities_found": vulnerabilities_static.get("total_findings", 0),
                "phishing_suspected": phishing.get("is_phishing_suspected", False)
            }
        }
        
        # حفظ في cache
        self._save_cached_result(clean_domain, result)
        
        return result


# ================================================================
# دالة مساعدة للاستخدام المباشر
# ================================================================

def analyze_site(domain: str) -> Dict[str, Any]:
    """دالة سريعة لتحليل موقع"""
    analyzer = SiteAnalyzer()
    return analyzer.comprehensive_analysis(domain)


def analyze_site_deep(domain: str, use_external_scanners: bool = False) -> Dict[str, Any]:
    """دالة للتحليل العميق مع خيار استخدام ماسحات خارجية"""
    analyzer = SiteAnalyzer(use_external_scanners=use_external_scanners)
    return analyzer.comprehensive_analysis(domain)


# ================================================================
# مثال الاستخدام
# ================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python site_analyzer.py <domain>")
        print("\nExample: python site_analyzer.py google.com")
        print("\n" + "=" * 70)
        print(" SITE SECURITY ANALYSIS - COMPLETE VERSION ")
        print("=" * 70)
        print("\n📋 Features included:")
        print("   1. Vulnerability Scan (SQL Injection, XSS)")
        print("   2. Security Headers Analysis")
        print("   3. TLS/SSL Certificate Check")
        print("   4. robots.txt & sitemap.xml Analysis")
        print("   5. DNS Records (A, MX, NS, TXT, SPF, DMARC)")
        print("   6. Phishing Detection (Typosquatting, Keywords)")
        print("   7. Performance Analysis")
        print("   8. SEO Analysis")
        print("   9. Mobile Friendliness")
        print("  10. Comprehensive Risk Scoring")
        sys.exit(1)
    
    domain = sys.argv[1]
    analyzer = SiteAnalyzer()
    
    print("\n" + "=" * 70)
    print(" COMPREHENSIVE SITE SECURITY ANALYSIS ".center(70, "="))
    print("=" * 70)
    
    result = analyzer.comprehensive_analysis(domain)
    
    if result.get("error"):
        print(f"\n❌ Error: {result['error']}")
        sys.exit(1)
    
    print(f"\n🌐 Domain: {result['domain']}")
    print(f"🔗 URL: {result['url']}")
    print(f"📊 Security Score: {result['security_score']}/100")
    print(f"🎯 Verdict: {result['verdict_icon']} {result['verdict'].upper()}")
    print(f"⚠️ Severity: {result['severity']}")
    
    print(f"\n🔒 SSL Certificate:")
    ssl = result.get('ssl', {})
    print(f"   Valid: {'✅ Yes' if ssl.get('valid') else '❌ No'}")
    print(f"   Days Remaining: {ssl.get('days_remaining', 0)}")
    print(f"   Grade: {ssl.get('grade', 'N/A')}")
    print(f"   TLS Version: {ssl.get('tls_version', 'N/A')}")
    
    print(f"\n🛡️ Security Headers Grade: {result.get('security_headers', {}).get('grade', 'N/A')}")
    print(f"   Score: {result.get('security_headers', {}).get('score', 0)}/100")
    
    print(f"\n🔍 Vulnerability Scan:")
    vuln = result.get('vulnerabilities', {})
    static = vuln.get('static', {})
    print(f"   SQL Injection patterns: {len(static.get('sql_injection', []))}")
    print(f"   XSS patterns: {len(static.get('xss', []))}")
    print(f"   Other vulnerabilities: {len(static.get('other_vulnerabilities', []))}")
    
    print(f"\n🎣 Phishing Indicators: {'⚠️ Detected' if result.get('phishing', {}).get('is_phishing_suspected') else '✅ Clean'}")
    if result.get('phishing', {}).get('issues'):
        for issue in result['phishing']['issues'][:3]:
            print(f"   - {issue}")
    
    print(f"\n📁 robots.txt: {'✅ Exists' if result.get('robots_txt', {}).get('exists') else '❌ Not found'}")
    if result.get('robots_txt', {}).get('sensitive_paths_found'):
        print(f"   ⚠️ Sensitive paths: {len(result['robots_txt']['sensitive_paths_found'])}")
    
    print(f"\n📈 Performance Grade: {result.get('performance', {}).get('grade', 'N/A')}")
    print(f"   Load Time: {result.get('performance', {}).get('load_time_ms', 0)} ms")
    print(f"   Page Size: {result.get('performance', {}).get('page_size_kb', 0)} KB")
    
    print(f"\n📱 Mobile Friendly: {'✅ Yes' if result.get('mobile', {}).get('has_viewport') else '❌ No'}")
    
    print(f"\n📋 Recommendations:")
    for rec in result.get('recommendations', [])[:8]:
        print(f"   {rec}")
    
    print(f"\n📊 Summary:")
    summary = result.get('summary', {})
    print(f"   SSL Active: {summary.get('has_ssl', False)}")
    print(f"   HSTS Enabled: {summary.get('has_hsts', False)}")
    print(f"   CSP Enabled: {summary.get('has_csp', False)}")
    print(f"   Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
    print(f"   Phishing Suspected: {summary.get('phishing_suspected', False)}")
    
    print("\n" + "=" * 70)
    
    # حفظ التقرير
    report_path = f"{domain.replace('.', '_')}_analysis_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n📁 Full report saved to: {report_path}")