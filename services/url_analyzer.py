# services/url_deep_analyzer.py
# =================================================================
# URL DEEP ANALYZER - تحليل عميق وشامل للروابط
# دمج URLDeepAnalyzer + URLAnalyzer في كلاس واحد متكامل
# =================================================================

import re
import socket
import ssl
import dns.resolver
import requests
import hashlib
import json
import os
import Levenshtein
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging
logger = logging.getLogger(__name__)

class URLDeepAnalyzer:
    """
    تحليل عميق وشامل للروابط
    يحتوي على:
    1. تحليل بنية الرابط
    2. كشف مؤشرات التصيد (Phishing)
    3. فحص SSL/TLS
    4. فحص DNS records
    5. فحص رؤوس الأمان
    6. تحليل محتوى الصفحة
    7. تحليل سلوك الرابط (redirects, shorteners)
    8. فحص WHOIS
    9. فحص OSINT (URLhaus)
    10. تخزين مؤقت للنتائج
    """
    
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
    
    # الكلمات المفتاحية المشبوهة لمحتوى الصفحة
    SUSPICIOUS_KEYWORDS = [
        'verify', 'confirm', 'update', 'account', 'login', 'signin', 
        'password', 'credit', 'card', 'paypal', 'bank', 'secure',
        'authenticate', 'validate', 'unlock', 'suspended', 'limited',
        'verify your account', 'confirm your identity', 'security alert'
    ]
    
    def __init__(self, cache_dir='cache/url_cache', cache_ttl=86400):
        """
        تهيئة المحلل
        
        Args:
            cache_dir: مجلد التخزين المؤقت
            cache_ttl: مدة صلاحية الكache بالثواني (افتراضي 24 ساعة)
        """
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        os.makedirs(cache_dir, exist_ok=True)
        
        # تحميل قاعدة بيانات التصيد المحلية
        self.PHISHING_DOMAINS = self._load_phishing_cache()
        logger.info("✅ URLDeepAnalyzer initialized successfully")

    
    # ================================================================
    # 1. دوال التخزين المؤقت (Cache)
    # ================================================================
    
    def _get_cache_key(self, url: str) -> str:
        """إنشاء مفتاح cache فريد للرابط"""
        return hashlib.md5(url.encode()).hexdigest()
    
    def _get_cached_result(self, url: str) -> Optional[dict]:
        """استرجاع نتيجة من cache إذا كانت موجودة وصالحة"""
        cache_key = self._get_cache_key(url)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['cached_at'])
                if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                    logger.info(f"📦 Returning cached result for URL: {url}")
                    return cached['result']
            except Exception:
                pass
        return None
    
    def _save_cached_result(self, url: str, result: dict):
        """حفظ نتيجة في cache"""
        cache_key = self._get_cache_key(url)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'url': url,
                    'cached_at': datetime.now().isoformat(),
                    'result': result
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    
    def _load_phishing_cache(self) -> set:
        """تحميل قاعدة بيانات النطاقات الخبيثة المحلية"""
        cache_file = os.path.join(self.cache_dir, 'phishing_domains.json')
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()
    
    def _save_phishing_cache(self, domain: str):
        """حفظ نطاق خبيث في قاعدة البيانات المحلية"""
        cache_file = os.path.join(self.cache_dir, 'phishing_domains.json')
        self.PHISHING_DOMAINS.add(domain)
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(list(self.PHISHING_DOMAINS), f, ensure_ascii=False, indent=2)
    
    # ================================================================
    # 2. تحليل بنية الرابط (URL Structure)
    # ================================================================
    
    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        logger.debug(f"Analyzing URL structure for: {url}")
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
        if '%' in url:
            result["suspicious_chars"].append("URL encoded characters (%)")
        if '\\' in url:
            result["suspicious_chars"].append("Backslash character")
        if '//' in url.replace('://', ''):
            result["suspicious_chars"].append("Double slash")
        
        # حساب درجة الثقة
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
        if result["suspicious_chars"]:
            trust_score -= len(result["suspicious_chars"]) * 10
        
        trust_score = max(0, min(100, trust_score))
        result["trust_score"] = trust_score
        
        if trust_score >= 80:
            result["trust_level"] = "High"
        elif trust_score >= 50:
            result["trust_level"] = "Medium"
        else:
            result["trust_level"] = "Low"
        
        return result
    
    # ================================================================
    # 3. كشف مؤشرات التصيد (Phishing Indicators)
    # ================================================================
    
    def check_phishing_indicators(self, url: str) -> Dict[str, Any]:
        logger.debug(f"Checking phishing indicators for: {url}")
        """كشف مؤشرات التصيد"""
        url_lower = url.lower()
        issues = []
        
        for pattern, description in self.PHISHING_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                issues.append(description)
        
        # كشف نطاقات مشابهة لنطاقات مشهورة (Typosquatting)
        popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                          'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']
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
    
    # ================================================================
    # 4. فحص SSL/TLS
    # ================================================================
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        logger.debug(f"Checking SSL certificate for: {domain}")
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
            logger.error(f"Error in function_name: {str(e)}")
            return {"valid": False, "error": str(e)}
    
    # ================================================================
    # 5. فحص DNS Records
    # ================================================================
    
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
                result["txt_records"].append(txt_str[:200])
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
    
    # ================================================================
    # 6. فحص رؤوس الأمان (Security Headers)
    # ================================================================
    
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
            logger.error(f"Error in function_name: {str(e)}")
            return {"error": str(e), "score": 0, "grade": "F"}
    
    # ================================================================
    # 7. فحص WHOIS
    # ================================================================
    
    def analyze_whois(self, domain: str) -> Dict[str, Any]:
        """تحليل معلومات WHOIS للنطاق"""
        result = {
            "domain": domain,
            "age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": "N/A",
            "is_new": False,
            "is_expiring_soon": False,
            "whois_risk_score": 0,
            "red_flags": []
        }
        
        try:
            import whois
            from datetime import timezone
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                
                result["creation_date"] = creation.strftime("%Y-%m-%d")
                now = datetime.now(timezone.utc)
                result["age_days"] = (now - creation).days
                
                if result["age_days"] < 30:
                    result["is_new"] = True
                    result["whois_risk_score"] += 30
                    result["red_flags"].append("Domain is very new (less than 30 days)")
                elif result["age_days"] < 90:
                    result["whois_risk_score"] += 15
                    result["red_flags"].append("Domain is relatively new (less than 90 days)")
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    exp = w.expiration_date[0]
                else:
                    exp = w.expiration_date
                
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                
                result["expiration_date"] = exp.strftime("%Y-%m-%d")
                days_to_expire = (exp - datetime.now(timezone.utc)).days
                if days_to_expire < 30 and days_to_expire > 0:
                    result["is_expiring_soon"] = True
                    result["red_flags"].append("Domain expiring soon (less than 30 days)")
            
            result["registrar"] = str(w.registrar) if w.registrar else "N/A"
            
            if w.name and 'Private' in str(w.name):
                result["red_flags"].append("Private registration - may hide identity")
        except Exception as e:
            logger.error(f"Error in function_name: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    # ================================================================
    # 8. فحص OSINT (URLhaus)
    # ================================================================
    
    def check_urlhaus(self, url: str) -> Dict[str, Any]:
        """فحص الرابط ضد URLhaus API"""
        result = {
            "is_malicious": False,
            "urlhaus_id": None,
            "first_seen": None,
            "last_seen": None,
            "threat": None,
            "tags": [],
            "reporter": None,
            "details": ""
        }
        
        try:
            resp = self.session.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url},
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('query_status') == 'ok':
                    result["is_malicious"] = True
                    logger.warning(f"🚨 Malicious URL detected in URLhaus: {url} - {result['threat']}")
                    result["urlhaus_id"] = data.get('id')
                    result["first_seen"] = data.get('firstseen')
                    result["last_seen"] = data.get('lastseen')
                    result["threat"] = data.get('threat')
                    result["tags"] = data.get('tags', [])
                    result["reporter"] = data.get('reporter')
                    result["details"] = f"Malicious URL detected - Type: {result['threat']}"
                    
                    # حفظ في القائمة المحلية
                    domain = urlparse(url).netloc
                    self._save_phishing_cache(domain)
                elif data.get('query_status') == 'no_results':
                    result["details"] = "URL not found in URLhaus database"
                else:
                    result["details"] = f"Query status: {data.get('query_status')}"
            else:
                result["details"] = f"API Error: {resp.status_code}"
        except Exception as e:
            logger.error(f"Error in function_name: {str(e)}")
            result["details"] = f"Error: {str(e)}"
        
        return result
    
    def check_osint_sources(self, url: str) -> Dict[str, Any]:
        """فحص الرابط ضد مصادر OSINT"""
        result = {
            "urlhaus": False,
            "urlhaus_details": {},
            "osint_risk_score": 0,
            "details": []
        }
        
        domain = urlparse(url).netloc
        
        # فحص URLhaus
        urlhaus_result = self.check_urlhaus(url)
        if urlhaus_result["is_malicious"]:
            result["urlhaus"] = True
            result["urlhaus_details"] = {
                "id": urlhaus_result.get("urlhaus_id"),
                "threat": urlhaus_result.get("threat"),
                "tags": urlhaus_result.get("tags", [])[:3],
                "first_seen": urlhaus_result.get("first_seen")
            }
            result["osint_risk_score"] += 60
            result["details"].append(f"Found in URLhaus - {urlhaus_result.get('threat', 'Malicious')}")
        
        # فحص القائمة المحلية
        if domain in self.PHISHING_DOMAINS:
            result["osint_risk_score"] += 30
            result["details"].append("Domain found in local phishing database")
        
        return result
    
    # ================================================================
    # 9. تحليل محتوى الصفحة
    # ================================================================
    
    def analyze_page_content(self, url: str, html: str = None) -> Dict[str, Any]:
        """تحليل محتوى الصفحة"""
        if html is None:
            try:
                response = self.session.get(url, timeout=self.timeout)
                html = response.text
            except Exception as e:
                logger.error(f"Error in function_name: {str(e)}")
                return {"error": f"Could not fetch page content: {str(e)}"}
        
        soup = BeautifulSoup(html, 'html.parser')
        
        result = {
            "title": "",
            "meta_description": "",
            "meta_keywords": "",
            "text_content": "",
            "forms": [],
            "external_links": [],
            "internal_links": [],
            "scripts": [],
            "suspicious_keywords_found": [],
            "has_login_form": False,
            "has_password_field": False,
            "content_risk_score": 0
        }
        
        if soup.title:
            result["title"] = soup.title.get_text()[:200]
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            result["meta_description"] = meta_desc['content'][:300]
        
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords and meta_keywords.get('content'):
            result["meta_keywords"] = meta_keywords['content'][:200]
        
        text_content = soup.get_text()
        result["text_content"] = text_content[:2000]
        
        text_lower = text_content.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                result["suspicious_keywords_found"].append(keyword)
        
        for form in soup.find_all('form'):
            form_data = {
                "action": form.get('action', ''),
                "method": form.get('method', 'get'),
                "inputs": []
            }
            
            for input_tag in form.find_all('input'):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                form_data["inputs"].append({"type": input_type, "name": input_name})
                
                if input_type == 'password':
                    result["has_password_field"] = True
                if input_type == 'password' or 'login' in input_name.lower():
                    result["has_login_form"] = True
            
            if form_data["inputs"]:
                result["forms"].append(form_data)
        
        domain = urlparse(url).netloc
        for link in soup.find_all('a', href=True):
            href = urljoin(url, link['href'])
            parsed = urlparse(href)
            if parsed.netloc == domain or not parsed.netloc:
                if len(result["internal_links"]) < 50:
                    result["internal_links"].append(href[:100])
            elif parsed.netloc:
                if len(result["external_links"]) < 30:
                    result["external_links"].append(href[:100])
        
        for script in soup.find_all('script', src=True):
            if len(result["scripts"]) < 20:
                result["scripts"].append(script['src'])
        
        # حساب درجة الخطورة للمحتوى
        risk_score = 0
        if result["has_login_form"]:
            risk_score += 20
        if result["has_password_field"]:
            risk_score += 25
        if len(result["suspicious_keywords_found"]) > 0:
            risk_score += min(30, len(result["suspicious_keywords_found"]) * 5)
        if len(result["external_links"]) > 10:
            risk_score += 10
        
        result["content_risk_score"] = min(100, risk_score)
        
        return result
    
    # ================================================================
    # 10. تحليل سلوك الرابط (Behavior)
    # ================================================================
    
    def analyze_behavior(self, url: str) -> Dict[str, Any]:
        """تحليل سلوك الرابط (redirects, shorteners, status)"""
        result = {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "redirect_chain": [],
            "is_shortened": False,
            "status_code": None,
            "behavior_risk_score": 0,
            "error": None
        }
        
        parsed = urlparse(url)
        if parsed.netloc in self.SHORTENED_DOMAINS:
            result["is_shortened"] = True
            result["behavior_risk_score"] += 15
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            
            if response.history:
                result["redirect_count"] = len(response.history)
                for r in response.history:
                    result["redirect_chain"].append({
                        "url": r.url[:200],
                        "status_code": r.status_code
                    })
                
                if result["redirect_count"] > 3:
                    result["behavior_risk_score"] += 20
                elif result["redirect_count"] > 1:
                    result["behavior_risk_score"] += 10
            
            final_domain = urlparse(result["final_url"]).netloc
            if final_domain in self.PHISHING_DOMAINS:
                result["behavior_risk_score"] += 40
        except Exception as e:
            logger.error(f"Error in function_name: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    # ================================================================
    # 11. التحليل الشامل الكامل
    # ================================================================
    
    def comprehensive_analysis(self, url: str) -> Dict[str, Any]:
        logger.info(f"🔍 Starting quick URL analysis for: {url}")
        """
        التحليل الشامل للرابط (بدون تخزين مؤقت - سريع)
        يستخدم للفحص السريع قبل إرسال إلى VirusTotal
        """
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
        if results["ssl"].get("valid") is False:
            security_score -= 30
        if results["security_headers"].get("score", 0) < 50:
            security_score -= 15
        if results["is_shortened"]:
            security_score -= 10
        
        security_score = max(0, min(100, security_score))
        
        if security_score >= 80:
            verdict = "safe"
            verdict_icon = "✅"
        elif security_score >= 50:
            verdict = "suspicious"
            verdict_icon = "⚠️"
        else:
            verdict = "malicious"
            verdict_icon = "🔴"
        
        results["security_score"] = security_score
        results["verdict"] = verdict
        results["verdict_icon"] = verdict_icon
        
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
        logger.info(f"✅ Quick analysis completed for {url} | Score: {security_score} | Verdict: {verdict}")
        return results
    
    # ================================================================
    # 12. التحليل العميق الكامل (مع تخزين مؤقت ومحتوى الصفحة)
    # ================================================================
    
    def comprehensive_deep_analysis(self, url: str, fetch_content: bool = True) -> Dict[str, Any]:
        logger.info(f"🚀 Starting deep URL analysis for: {url}")
        """
        التحليل العميق الشامل للرابط (مع تخزين مؤقت وتحليل محتوى)
        
        Args:
            url: الرابط المراد تحليله
            fetch_content: هل يتم جلب محتوى الصفحة (قد يبطئ العملية)
        
        Returns:
            تحليل كامل للرابط
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # التحقق من cache
        cached_result = self._get_cached_result(url)
        if cached_result:
            cached_result['from_cache'] = True
            return cached_result
        
        result = {
            "url": url,
            "domain": urlparse(url).netloc,
            "timestamp": datetime.now().isoformat(),
            "from_cache": False,
            "page_content": {},
            "behavior": {},
            "whois": {},
            "osint": {},
            "structure": {},
            "phishing": {},
            "ssl": {},
            "dns": {},
            "security_headers": {},
            "overall_risk_score": 0,
            "verdict": "unknown",
            "verdict_icon": "❓",
            "summary": {},
            "recommendations": []
        }
        
        # 1. تحليل السلوك
        result["behavior"] = self.analyze_behavior(url)
        
        # 2. تحليل المحتوى (إذا طلب)
        if fetch_content and result["behavior"].get("final_url"):
            result["page_content"] = self.analyze_page_content(result["behavior"]["final_url"])
        else:
            result["page_content"] = {"content_risk_score": 0}
        
        # 3. تحليل WHOIS
        result["whois"] = self.analyze_whois(result["domain"])
        
        # 4. فحص OSINT
        result["osint"] = self.check_osint_sources(url)
        
        # 5. تحليل بنية الرابط
        result["structure"] = self.analyze_url_structure(url)
        
        # 6. كشف مؤشرات التصيد
        result["phishing"] = self.check_phishing_indicators(url)
        
        # 7. فحص SSL
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            result["ssl"] = self.check_ssl_certificate(result["domain"])
        else:
            result["ssl"] = {"valid": False, "error": "Not using HTTPS"}
        
        # 8. فحص DNS
        result["dns"] = self.check_dns_records(result["domain"])
        
        # 9. فحص رؤوس الأمان
        try:
            result["security_headers"] = self.check_security_headers(url)
        except:
            result["security_headers"] = {"error": "Could not fetch headers"}
        
        # حساب درجة الخطورة الإجمالية
        risk_score = 0
        risk_score += result["behavior"].get("behavior_risk_score", 0)
        risk_score += result["page_content"].get("content_risk_score", 0) * 0.3
        risk_score += result["whois"].get("whois_risk_score", 0)
        risk_score += result["osint"].get("osint_risk_score", 0)
        risk_score += result["phishing"].get("risk_score", 0) * 0.5
        
        # إضافة نقاط إضافية لضعف الأمان
        if not result["structure"].get("is_https", False):
            risk_score += 15
        if result["structure"].get("contains_ip", False):
            risk_score += 10
        if result["security_headers"].get("score", 0) < 30:
            risk_score += 10
        
        result["overall_risk_score"] = min(100, int(risk_score))
        
        # تحديد الحكم النهائي
        if result["overall_risk_score"] >= 70:
            result["verdict"] = "malicious"
            result["verdict_icon"] = "💀"
            result["summary"] = {
                "level": "Critical Risk", 
                "color": "red", 
                "message": "Multiple malicious indicators detected. DO NOT visit this URL!"
            }
        elif result["overall_risk_score"] >= 45:
            result["verdict"] = "high_risk"
            result["verdict_icon"] = "🔴"
            result["summary"] = {
                "level": "High Risk", 
                "color": "orange", 
                "message": "Significant suspicious indicators found. Avoid this URL."
            }
        elif result["overall_risk_score"] >= 25:
            result["verdict"] = "suspicious"
            result["verdict_icon"] = "⚠️"
            result["summary"] = {
                "level": "Medium Risk", 
                "color": "yellow", 
                "message": "Some suspicious indicators found. Proceed with caution."
            }
        else:
            result["verdict"] = "safe"
            result["verdict_icon"] = "✅"
            result["summary"] = {
                "level": "Low Risk", 
                "color": "green", 
                "message": "No significant threats detected. URL appears safe."
            }
        
        # جمع التوصيات
        recommendations = []
        
        if result["behavior"].get("is_shortened"):
            recommendations.append("⚠️ URL shortener detected - destination unknown")
        if result["behavior"].get("redirect_count", 0) > 2:
            recommendations.append("🔄 Multiple redirects detected - possible malicious behavior")
        if result["whois"].get("is_new"):
            recommendations.append("🆕 Domain is very new - typical of phishing sites")
        if result["whois"].get("red_flags"):
            for flag in result["whois"]["red_flags"][:2]:
                recommendations.append(f"📋 {flag}")
        if result["page_content"].get("has_login_form"):
            recommendations.append("🔐 Login form detected - verify site legitimacy before entering credentials")
        if result["osint"].get("urlhaus"):
            recommendations.append("💀 URL found in malware database - DO NOT visit!")
        if result["phishing"].get("is_phishing_suspected"):
            for issue in result["phishing"]["issues"][:2]:
                recommendations.append(f"🎣 {issue}")
        if not result["structure"].get("is_https"):
            recommendations.append("🔓 No HTTPS - connection is not secure")
        
        if not recommendations:
            recommendations.append("✅ No threats detected - URL appears safe to visit")
        
        result["recommendations"] = recommendations[:8]
        
        # حفظ في cache
        self._save_cached_result(url, result)
        logger.info(f"✅ Deep analysis completed for {url} | Risk Score: {result['overall_risk_score']} | Verdict: {result['verdict']}")
        return result


# ================================================================
# دوال مساعدة للاستخدام المباشر
# ================================================================

def analyze_url(url: str, deep: bool = False) -> Dict[str, Any]:
    """
    دالة سريعة لتحليل رابط
    
    Args:
        url: الرابط المراد تحليله
        deep: هل تريد تحليل عميق (يشمل جلب المحتوى)
    
    Returns:
        تحليل كامل للرابط
    """
    analyzer = URLDeepAnalyzer()
    
    if deep:
        return analyzer.comprehensive_deep_analysis(url)
    else:
        return analyzer.comprehensive_analysis(url)


def analyze_url_batch(urls: List[str], deep: bool = False) -> List[Dict[str, Any]]:
    """
    تحليل مجموعة من الروابط دفعة واحدة
    
    Args:
        urls: قائمة الروابط
        deep: هل تريد تحليل عميق
    
    Returns:
        قائمة بنتائج التحليل
    """
    analyzer = URLDeepAnalyzer()
    results = []
    
    for url in urls:
        if deep:
            results.append(analyzer.comprehensive_deep_analysis(url))
        else:
            results.append(analyzer.comprehensive_analysis(url))
    
    return results


# ================================================================
# مثال الاستخدام
# ================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python url_deep_analyzer.py <url>")
        print("\nExample: python url_deep_analyzer.py https://google.com")
        sys.exit(1)
    
    url = sys.argv[1]
    analyzer = URLDeepAnalyzer()
    
    print("\n" + "=" * 70)
    print(" URL DEEP ANALYSIS REPORT ".center(70, "="))
    print("=" * 70)
    
    # تحليل سريع
    print("\n📡 Quick Analysis:")
    quick_result = analyzer.comprehensive_analysis(url)
    print(f"   URL: {quick_result['url']}")
    print(f"   Verdict: {quick_result['verdict_icon']} {quick_result['verdict'].upper()}")
    print(f"   Security Score: {quick_result['security_score']}/100")
    
    # تحليل عميق
    print("\n🔍 Deep Analysis:")
    deep_result = analyzer.comprehensive_deep_analysis(url)
    print(f"   Overall Risk Score: {deep_result['overall_risk_score']}/100")
    print(f"   Verdict: {deep_result['verdict_icon']} {deep_result['verdict'].upper()}")
    print(f"   Summary: {deep_result['summary']['message']}")
    
    print(f"\n📋 Recommendations:")
    for rec in deep_result['recommendations'][:5]:
        print(f"   {rec}")
    
    print("\n" + "=" * 70)