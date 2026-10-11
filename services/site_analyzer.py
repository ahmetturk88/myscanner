# Site Analyzer compatibility adapter.
# Comprehensive reports use site_evidence and the shared read-only WebAssessment.
# Legacy helpers remain for callers; their heuristic scores are not used in reports.

import logging
logger = logging.getLogger(__name__)

import requests
from services.active_scan_policy import skipped_active_analysis
from services.safe_http import PublicHTTPSession, UnsafeTargetError, validate_public_url, public_connection
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
    logger.warning("Levenshtein not installed. Run: pip install python-Levenshtein")

try:
    from OpenSSL import crypto
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False
    logger.warning("pyOpenSSL not installed. Run: pip install pyOpenSSL")


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
        self.session = PublicHTTPSession()
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
            (r"['\"]\s*\+\s*\$_(GET|POST|REQUEST|COOKIE)", "Potential SQL injection via concatenation"),
            (r"mysql_query\s*\(\s*['\"]\s*\$", "MySQL query with variable concatenation"),
            (r"mysqli_query\s*\(\s*['\"]\s*\$", "MySQLi query with variable concatenation"),
            (r"odbc_exec\s*\(\s*['\"]\s*\$", "ODBC query with variable concatenation"),
            (r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]\s*\$", "SELECT query with variable in WHERE"),
            (r"INSERT\s+INTO\s+.*\s+VALUES\s*\(\s*['\"]\s*\$", "INSERT query with variables"),
            (r"UPDATE\s+.*\s+SET\s+.*=\s*['\"]\s*\$", "UPDATE query with variables"),
            (r"DELETE\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]\s*\$", "DELETE query with variables"),
            (r"SQL syntax.*MySQL|You have an error in your SQL syntax", "MySQL error message leaked"),
            (r"Warning:\s+mysql_|mysqli_|pg_|odbc_", "Database function warning"),
            (r"Unclosed quotation mark|Microsoft OLE DB", "SQL Server error message"),
            (r"PostgreSQL.*ERROR|PG::Error", "PostgreSQL error message"),
        ]
        
        # أنماط XSS (Cross-Site Scripting Patterns)
        self.XSS_PATTERNS = [
            (r"echo\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via echo with user input"),
            (r"print\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via print with user input"),
            (r"document\.write\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via document.write"),
            (r"innerHTML\s*=\s*\$_(GET|POST|REQUEST)", "Potential XSS via innerHTML"),
            (r"eval\s*\(\s*\$_(GET|POST|REQUEST)", "Potential XSS via eval"),
            (r"\.html\s*\(\s*\$_(GET|POST|REQUEST)", "jQuery .html() with user input"),
            (r"\.append\s*\(\s*\$_(GET|POST|REQUEST)", "jQuery .append() with user input"),
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
        
        # الكلمات المفتاحية المشبوهة
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
        
        # النطاقات الشرعية
        self.LEGITIMATE_DOMAINS = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'yahoo.com', 'bing.com', 'duckduckgo.com'
        ]
        
        logger.info("✅ SiteAnalyzer initialized successfully")
    
    # ================================================================
    # 1. دوال التخزين المؤقت (Cache)
    # ================================================================
    
    def _get_cache_key(self, domain: str) -> str:
        return hashlib.md5(('passive-v2:' + domain).encode()).hexdigest()
    
    def _get_cached_result(self, domain: str) -> Optional[dict]:
        cache_key = self._get_cache_key(domain)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['cached_at'])
                if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                    logger.info(f"📦 Returning cached result for domain: {domain}")
                    return cached['result']
            except Exception as e:
                logger.warning(f"Failed to read cache for {domain}: {str(e)}")
        return None
    
    def _save_cached_result(self, domain: str, result: dict):
        cache_key = self._get_cache_key(domain)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'domain': domain,
                    'cached_at': datetime.now().isoformat(),
                    'result': result
                }, f, ensure_ascii=False, indent=2)
            logger.info(f"💾 Cached result for domain: {domain}")
        except Exception as e:
            logger.warning(f"Failed to save cache for {domain}: {str(e)}")
    
    # ================================================================
    # 2. فحص الثغرات الأساسي
    # ================================================================
    
    def scan_vulnerabilities_static(self, html_content: str, url: str) -> Dict[str, Any]:
        logger.debug(f"Running static vulnerability scan on: {url}")
        result = {
            "sql_injection": [],
            "xss": [],
            "other_vulnerabilities": [],
            "risk_score": 0,
            "total_findings": 0
        }
        
        for pattern, description in self.SQL_INJECTION_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["sql_injection"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
        for pattern, description in self.XSS_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["xss"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
        for pattern, description in self.OTHER_VULNERABILITIES:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                result["other_vulnerabilities"].append({
                    "pattern": pattern[:50],
                    "description": description,
                    "matches": len(matches)
                })
        
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
        
        if result["total_findings"] > 0:
            logger.warning(f"Found {result['total_findings']} potential vulnerabilities in {url}")
        
        return result
    
    def scan_vulnerabilities_dynamic(self, url: str) -> Dict[str, Any]:
        """Compatibility result only; general site analysis sends no payloads."""
        return skipped_active_analysis()

    # ================================================================
    # 3. تحليل رؤوس الأمان
    # ================================================================
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        logger.debug(f"Checking security headers for: {url}")
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
            
            analysis = {}
            score = 0
            
            if security_headers["strict_transport_security"] != "Missing":
                analysis["hsts"] = {"status": "present", "value": security_headers["strict_transport_security"][:100]}
                if "max-age=31536000" in security_headers["strict_transport_security"]:
                    score += 12
                elif "max-age" in security_headers["strict_transport_security"]:
                    score += 8
                else:
                    score += 5
            else:
                analysis["hsts"] = {"status": "missing", "recommendation": "Enable HSTS with max-age=31536000"}
            
            if security_headers["content_security_policy"] != "Missing":
                analysis["csp"] = {"status": "present", "value": security_headers["content_security_policy"][:100]}
                score += 15
                if "default-src 'none'" in security_headers["content_security_policy"]:
                    score += 5
                elif "default-src 'self'" in security_headers["content_security_policy"]:
                    score += 3
            else:
                analysis["csp"] = {"status": "missing", "recommendation": "Implement Content Security Policy (CSP)"}
                score -= 10
            
            if security_headers["x_frame_options"] != "Missing":
                analysis["xfo"] = {"status": "present", "value": security_headers["x_frame_options"]}
                if security_headers["x_frame_options"] == "DENY":
                    score += 12
                elif security_headers["x_frame_options"] == "SAMEORIGIN":
                    score += 8
                else:
                    score += 4
            else:
                analysis["xfo"] = {"status": "missing", "recommendation": "Set X-Frame-Options: DENY"}
            
            if security_headers["x_content_type_options"] == "nosniff":
                analysis["xcto"] = {"status": "present", "value": security_headers["x_content_type_options"], "quality": "good"}
                score += 10
            else:
                analysis["xcto"] = {"status": "missing", "recommendation": "Set X-Content-Type-Options: nosniff"}
            
            if security_headers["x_xss_protection"] != "Missing":
                analysis["xxp"] = {"status": "present", "value": security_headers["x_xss_protection"]}
                if "block" in security_headers["x_xss_protection"].lower():
                    score += 8
                else:
                    score += 4
            else:
                analysis["xxp"] = {"status": "missing", "recommendation": "Set X-XSS-Protection: 1; mode=block"}
            
            if security_headers["referrer_policy"] != "Missing":
                analysis["referrer"] = {"status": "present", "value": security_headers["referrer_policy"]}
                score += 8
            else:
                analysis["referrer"] = {"status": "missing", "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin"}
            
            if security_headers["permissions_policy"] != "Missing":
                analysis["permissions"] = {"status": "present", "value": security_headers["permissions_policy"][:100]}
                score += 5
            else:
                analysis["permissions"] = {"status": "missing", "recommendation": "Consider implementing Permissions-Policy"}
            
            score = max(0, min(100, score))
            
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
            
            logger.debug(f"Security headers score for {url}: {score} ({grade})")
            
            return {
                "headers": security_headers,
                "analysis": analysis,
                "score": score,
                "grade": grade,
                "recommendations": [v["recommendation"] for k, v in analysis.items() if "recommendation" in v]
            }
            
        except UnsafeTargetError:
            raise
        except Exception as e:
            logger.error(f"Failed to check security headers for {url}: {str(e)}")
            return {"error": str(e), "score": 0, "grade": "F", "recommendations": []}
    
    # ================================================================
    # 4. فحص شهادات TLS/SSL
    # ================================================================
    
    def check_ssl_advanced(self, domain: str) -> Dict[str, Any]:
        logger.debug(f"Checking SSL certificate for: {domain}")
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
            context = ssl.create_default_context()
            
            with public_connection(domain, timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    result["tls_version"] = ssock.version()
                    
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher_strength"] = f"{cipher[0]} ({cipher[1]} bits)"
                    
                    if SSL_AVAILABLE:
                        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                        result["issuer"] = x509.get_issuer().CN
                        result["subject"] = x509.get_subject().CN
                        result["version"] = x509.get_version()
                        result["serial_number"] = hex(x509.get_serial_number())
                        result["signature_algorithm"] = x509.get_signature_algorithm().decode()
                        
                        not_before = datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
                        not_after = datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                        
                        result["valid_from"] = not_before.strftime('%Y-%m-%d')
                        result["valid_until"] = not_after.strftime('%Y-%m-%d')
                        
                        now = datetime.utcnow()
                        result["days_remaining"] = (not_after - now).days
                        result["days_since_issue"] = (now - not_before).days
                        result["valid"] = result["days_remaining"] > 0
            
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
            
            if result["tls_version"] and "TLSv1.0" in result["tls_version"]:
                result["vulnerabilities"].append("Outdated TLS version (1.0)")
                result["risk_score"] += 30
            elif result["tls_version"] and "TLSv1.1" in result["tls_version"]:
                result["vulnerabilities"].append("Outdated TLS version (1.1)")
                result["risk_score"] += 20
            
            logger.info(f"SSL check for {domain}: Valid={result['valid']}, Days left={result['days_remaining']}, Grade={result['grade']}")
            
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["risk_score"] = 50
            logger.error(f"SSL timeout for {domain}")
        except ConnectionRefusedError:
            result["error"] = "Connection refused - SSL may not be enabled"
            result["risk_score"] = 50
            logger.error(f"SSL connection refused for {domain}")
        except UnsafeTargetError:
            raise
        except Exception as e:
            result["error"] = str(e)
            result["risk_score"] = 50
            logger.error(f"SSL check failed for {domain}: {str(e)}")
        
        return result
    
    # ================================================================
    # 5. تحليل robots.txt و sitemap.xml
    # ================================================================
    
    def analyze_robots_txt(self, domain: str) -> Dict[str, Any]:
        logger.debug(f"Analyzing robots.txt for: {domain}")
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
        
        sensitive_patterns = ['admin', 'config', 'backup', 'wp-admin', 'phpmyadmin', '.git', '.env', 'password', 'secret', 'private', 'internal', 'api']
        
        try:
            robots_url = f"{domain}/robots.txt"
            response = self.session.get(robots_url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                result["exists"] = True
                content = response.text
                result["content"] = content[:2000]
                logger.info(f"Found robots.txt for {domain}")
                
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
                            for pattern in sensitive_patterns:
                                if pattern in path:
                                    result["sensitive_paths_found"].append({"path": path, "pattern": pattern})
                    elif line.startswith('allow:'):
                        path = line.replace('allow:', '').strip()
                        if path:
                            result["allowed_paths"].append(path)
                    elif 'sitemap:' in line:
                        sitemap_url = line.replace('sitemap:', '').strip()
                        result["sitemaps"].append(sitemap_url)
                
                if result["sensitive_paths_found"]:
                    result["risk_score"] = min(70, len(result["sensitive_paths_found"]) * 10)
                    logger.warning(f"Found {len(result['sensitive_paths_found'])} sensitive paths in robots.txt for {domain}")
                
            elif response.status_code == 404:
                logger.debug(f"No robots.txt found for {domain}")
            else:
                logger.warning(f"robots.txt returned status {response.status_code} for {domain}")
                
        except UnsafeTargetError:
            raise
        except Exception as e:
            logger.error(f"Failed to analyze robots.txt for {domain}: {str(e)}")
        
        return result
    
    def analyze_sitemap(self, domain: str) -> Dict[str, Any]:
        logger.debug(f"Analyzing sitemap for: {domain}")
        result = {
            "exists": False,
            "urls": [],
            "total_urls": 0,
            "sensitive_urls_found": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        sensitive_patterns = ['admin', 'config', 'backup', 'private', 'internal', 'test', 'debug']
        sitemap_urls = [f"{domain}/sitemap.xml", f"{domain}/sitemap_index.xml", f"{domain}/sitemap.gz"]
        
        for sitemap_url in sitemap_urls[:2]:
            try:
                response = self.session.get(sitemap_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    result["exists"] = True
                    content = response.text
                    
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(content)
                        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                        
                        for loc in root.findall('.//ns:loc', namespace):
                            url_text = loc.text if loc.text else ""
                            if url_text:
                                result["urls"].append(url_text[:200])
                                for pattern in sensitive_patterns:
                                    if pattern in url_text.lower():
                                        result["sensitive_urls_found"].append({"url": url_text[:100], "pattern": pattern})
                    except ET.ParseError:
                        pass
                    
                    logger.info(f"Found sitemap for {domain} with {len(result['urls'])} URLs")
                    break
            except UnsafeTargetError:
                raise
            except Exception:
                continue
        
        result["total_urls"] = len(result["urls"])
        
        if result["sensitive_urls_found"]:
            result["risk_score"] = min(50, len(result["sensitive_urls_found"]) * 5)
            logger.warning(f"Found {len(result['sensitive_urls_found'])} sensitive URLs in sitemap for {domain}")
        
        return result
    
    # ================================================================
    # 6. فحص DNS كامل
    # ================================================================
    
    def check_dns_records(self, domain):
        result={'a_records':[],'aaaa_records':[],'mx_records':[],'ns_records':[],'txt_records':[],
                'cname_records':[],'soa_record':None,'has_spf':None,'has_dmarc':None,
                'spf_record':None,'dmarc_record':None,'risk_score':0,'warnings':[],'checks':{}}
        for kind in ('A','AAAA','MX','NS','TXT','SOA','DMARC'):
            query='_dmarc.'+domain if kind=='DMARC' else domain
            try:
                answers=list(dns.resolver.resolve(query,'TXT' if kind=='DMARC' else kind,lifetime=3))
                result['checks'][kind]='found' if answers else 'not_found'
                if kind in ('A','AAAA'):result[kind.lower()+'_records']=[str(r) for r in answers]
                elif kind=='MX':result['mx_records']=[{'preference':r.preference,'exchange':str(r.exchange).rstrip('.')} for r in answers]
                elif kind=='NS':result['ns_records']=[str(r).rstrip('.') for r in answers]
                elif kind=='TXT':
                    result['txt_records']=[str(r).strip('"')[:200] for r in answers]
                    result['has_spf']=any(value.lower().startswith('v=spf1') for value in result['txt_records'])
                    result['spf_record']=next((value for value in result['txt_records'] if value.lower().startswith('v=spf1')),None)
                elif kind=='DMARC':
                    values=[str(r).strip('"') for r in answers]
                    result['has_dmarc']=any(value.startswith('v=DMARC1') for value in values)
                    result['dmarc_record']=next((value[:200] for value in values if value.startswith('v=DMARC1')),None)
                elif kind=='SOA' and answers:
                    r=answers[0];result['soa_record']={'mname':str(r.mname),'rname':str(r.rname),'serial':r.serial,'refresh':r.refresh,'retry':r.retry,'expire':r.expire,'minimum':r.minimum}
            except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):
                result['checks'][kind]='not_found'
                if kind=='TXT':result['has_spf']=False
                if kind=='DMARC':result['has_dmarc']=False
            except Exception:result['checks'][kind]='unavailable'
        for kind,penalty in (('MX',15),('NS',20)):
            if result['checks'][kind]=='not_found':result['risk_score']+=penalty;result['warnings'].append('No '+kind+' records returned')
        for key,penalty in (('has_spf',15),('has_dmarc',15)):
            if result[key] is False:result['risk_score']+=penalty;result['warnings'].append(key.replace('has_','').upper()+' record not found')
        result['evidence_policy']='site-passive-v2'
        result['coverage_status']='partial' if 'unavailable' in result['checks'].values() else 'completed'
        return result

    # ================================================================
    # 7. كشف مؤشرات التصيد
    # ================================================================
    
    def check_phishing_indicators(self, domain: str, soup: BeautifulSoup = None) -> Dict[str, Any]:
        logger.debug(f"Checking phishing indicators for: {domain}")
        issues = []
        risk_score = 0
        domain_lower = domain.lower()
        
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
                    if len(popular) - len(domain_lower.split('.')[0]) <= 2:
                        issues.append(f"Possible typosquatting of {popular}.com")
                        risk_score += 20
        
        parsed = urlparse(f"https://{domain}")
        if parsed.netloc in self.SHORTENED_DOMAINS:
            issues.append("Domain is a URL shortener - destination unknown")
            risk_score += 15
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site']
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                issues.append(f"Suspicious TLD: {tld}")
                risk_score += 15
                break
        
        if re.search(r'\d{5,}', domain_lower):
            issues.append("Domain contains long number sequence")
            risk_score += 10
        
        if soup:
            text_lower = soup.get_text().lower()
            
            suspicious_found = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in text_lower]
            if suspicious_found:
                issues.append(f"Suspicious keywords: {', '.join(suspicious_found[:3])}")
                risk_score += min(30, len(suspicious_found) * 5)
            
            has_login_form = False
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'password'}):
                    has_login_form = True
                    break
            
            if has_login_form and domain not in self.LEGITIMATE_DOMAINS:
                issues.append("Login form on non-legitimate domain")
                risk_score += 20
            
            logo_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple']
            for keyword in logo_keywords:
                if keyword in text_lower and keyword not in domain_lower:
                    issues.append(f"Logo/brand '{keyword}' mentioned but domain mismatch")
                    risk_score += 15
                    break
        
        risk_score = min(100, risk_score)
        
        if issues:
            logger.warning(f"Phishing indicators for {domain}: {len(issues)} issues found")
        
        return {
            "is_phishing_suspected": len(issues) > 0,
            "issues": issues[:8],
            "risk_score": risk_score,
            "severity": "high" if risk_score > 60 else "medium" if risk_score > 30 else "low"
        }
    
    # ================================================================
    # 8. فحص السمعة
    # ================================================================
    
    def check_reputation(self, domain: str) -> Dict[str, Any]:
        logger.debug(f"Checking reputation for: {domain}")
        return {
            "is_blacklisted": None,
            "status": "not_checked",
            "blacklist_sources": [],
            "risk_score": 0,
            "details": []
        }
    
    # ================================================================
    # 9. تحليل الأداء
    # ================================================================
    
    def analyze_performance(self, url: str) -> Dict[str, Any]:
        logger.debug(f"Analyzing performance for: {url}")
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout)
            load_time = (time.time() - start_time) * 1000
            
            page_size = len(response.content) / 1024
            
            soup = BeautifulSoup(response.text, 'html.parser')
            resources = {
                "images": len(soup.find_all('img')),
                "scripts": len(soup.find_all('script')),
                "stylesheets": len(soup.find_all('link', rel='stylesheet')),
                "total": 0
            }
            resources["total"] = resources["images"] + resources["scripts"] + resources["stylesheets"]
            
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
            
            logger.debug(f"Performance for {url}: {load_time:.0f}ms ({grade})")
            
            return {
                "load_time_ms": round(load_time, 2),
                "page_size_kb": round(page_size, 2),
                "resource_count": resources["total"],
                "resources_breakdown": resources,
                "grade": grade,
                "score": score,
                "risk_score": 0 if grade in ['A+', 'A'] else 10 if grade == 'B' else 20 if grade == 'C' else 35
            }
        except UnsafeTargetError:
            raise
        except Exception as e:
            logger.error(f"Performance analysis failed for {url}: {str(e)}")
            return {"error": str(e), "grade": "Unknown", "score": 0, "risk_score": 0}
    
    # ================================================================
    # 10. التحليل الشامل الكامل
    # ================================================================
    
    def comprehensive_analysis(self, domain, include_provider=False, include_discovery=False):
        """Read-only evidence pipeline; legacy heuristic scores are not used."""
        from services.site_evidence import assess_site
        try:
            return assess_site(domain, include_provider, include_discovery)
        finally:
            self.session.close()


# ================================================================
# دالة مساعدة للاستخدام المباشر
# ================================================================

def analyze_site(domain: str) -> Dict[str, Any]:
    analyzer = SiteAnalyzer()
    return analyzer.comprehensive_analysis(domain)


def analyze_site_deep(domain: str, use_external_scanners: bool = False) -> Dict[str, Any]:
    analyzer = SiteAnalyzer(use_external_scanners=use_external_scanners)
    return analyzer.comprehensive_analysis(domain)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python site_analyzer.py <domain>")
        print("\nExample: python site_analyzer.py google.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    analyzer = SiteAnalyzer()
    result = analyzer.comprehensive_analysis(domain)
    
    if result.get("error"):
        print(f"\n❌ Error: {result['error']}")
        sys.exit(1)
    
    print(f"\n🌐 Domain: {result['domain']}")
    print(f"Inspection coverage: {result['assessment']['score']}%")
    print(f"Verdict: {result['verdict']}")
    for line in result['report_brief']:
        print(line)
