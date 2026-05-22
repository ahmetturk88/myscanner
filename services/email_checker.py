import hashlib
import json
import socket
import smtplib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import dns.resolver
import Levenshtein
from email_validator import validate_email, EmailNotValidError
from constants import DISPOSABLE_DOMAINS, FREE_DOMAINS, BLACKLISTS
import logging
logger = logging.getLogger(__name__)
class AdvancedEmailChecker:
    """أداة متقدمة لفحص الإيميلات مع جميع الميزات"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.cache_ttl = 3600
        self.executor = ThreadPoolExecutor(max_workers=10)
        logger.info("✅ AdvancedEmailChecker initialized successfully")
        
    def _get_cache_key(self, email: str, check_type: str) -> str:
        return f"email_check:{hashlib.md5(email.encode()).hexdigest()}:{check_type}"
    
    def _cache_get(self, key: str):
        if self.redis:
            try:
                data = self.redis.get(key)
                if data:
                    return json.loads(data)
            except:
                pass
        return None

    def _cache_set(self, key: str, value: Any, ttl: int = None):
        if self.redis:
            try:
                self.redis.setex(key, ttl or self.cache_ttl, json.dumps(value))
            except:
                pass

    def validate_format(self, email: str):
        logger.debug(f"Validating email format: {email}")
        """التحقق من صحة صيغة الإيميل مع اقتراح تصحيحات"""
        try:
            validation = validate_email(email, check_deliverability=False)
            normalized = validation.normalized
            
            domain = email.split('@')[-1] if '@' in email else email
            suggestions = []
            
            common_domains = {
                'gmial.com': 'gmail.com', 'gmail.co': 'gmail.com',
                'yaho.com': 'yahoo.com', 'hotmai.com': 'hotmail.com',
                'outloo.com': 'outlook.com', 'protonmal.com': 'protonmail.com'
            }
            
            if domain in common_domains:
                corrected = email.replace(domain, common_domains[domain])
                suggestions.append({
                    "original": email,
                    "suggested": corrected,
                    "type": "domain_typo",
                    "confidence": 0.95
                })
            
            for known_domain in FREE_DOMAINS:
                ratio = Levenshtein.ratio(domain, known_domain)
                if ratio > 0.8 and ratio < 1.0:
                    corrected = email.replace(domain, known_domain)
                    suggestions.append({
                        "original": email,
                        "suggested": corrected,
                        "type": "similar_domain",
                        "confidence": ratio
                    })
                    break
            
            return True, normalized, {"suggestions": suggestions}
            
        except EmailNotValidError as e:
            return False, email, {"error": str(e), "suggestions": []}
    
    def check_smtp(self, email: str, timeout: int = 10):
        logger.debug(f"Checking SMTP for: {email}")
        """فحص SMTP المباشر للتأكد من وجود الصندوق"""
        cache_key = self._get_cache_key(email, "smtp")
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        
        domain = email.split('@')[-1]
        result = {
            "valid": False,
            "message": "Not checked",
            "mx_servers": [],
            "response_code": None,
            "response_message": None
        }
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_records])
            result["mx_servers"] = [{"preference": pref, "server": server} for pref, server in mx_servers]
            
            if not mx_servers:
                result["message"] = "No MX records found"
                self._cache_set(cache_key, result, 3600)
                return result
            
            for pref, mx in mx_servers[:3]:
                try:
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.connect(mx, 25)
                    smtp.helo('checker.local')
                    smtp.mail('verify@checker.local')
                    code, message = smtp.rcpt(email)
                    
                    result["response_code"] = code
                    result["response_message"] = message.decode() if isinstance(message, bytes) else str(message)
                    
                    if code == 250:
                        result["valid"] = True
                        logger.info(f"✅ SMTP check passed for: {email}")
                        result["message"] = "Mailbox exists"
                    elif code in (550, 551):
                        result["valid"] = False
                        logger.warning(f"SMTP check failed for: {email} - {result['message']}")
                        result["message"] = "Mailbox does not exist"
                    else:
                        result["message"] = f"Response: {code}"
                    
                    smtp.quit()
                    break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            result["message"] = f"Error: {str(e)}"
        
        self._cache_set(cache_key, result, 3600)
        return result
    
    def check_dns_records(self, domain: str):
        logger.debug(f"Checking DNS records for domain: {domain}")
        """فحص جميع سجلات DNS المتعلقة بالإيميل"""
        cache_key = self._get_cache_key(domain, "dns")
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        
        result = {
            "spf": {"exists": False, "record": None, "valid": False, "details": None},
            "dkim": {"exists": False, "records": [], "valid": False},
            "dmarc": {"exists": False, "record": None, "policy": None, "pct": None},
            "mx": {"exists": False, "records": []},
            "txt": {"records": []}
        }
        
        # فحص MX
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            result["mx"]["exists"] = True
            result["mx"]["records"] = [{"preference": r.preference, "exchange": str(r.exchange).rstrip('.')} for r in mx]
        except:
            pass
        
        # فحص TXT (يشمل SPF)
        try:
            txt = dns.resolver.resolve(domain, 'TXT')
            for r in txt:
                txt_str = str(r).strip('"')
                result["txt"]["records"].append(txt_str)
                
                if 'v=spf1' in txt_str.lower():
                    result["spf"]["exists"] = True
                    result["spf"]["record"] = txt_str
                    result["spf"]["valid"] = True
        except:
            pass
        
        # فحص DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc = dns.resolver.resolve(dmarc_domain, 'TXT')
            for r in dmarc:
                txt_str = str(r).strip('"')
                if 'v=DMARC1' in txt_str:
                    result["dmarc"]["exists"] = True
                    result["dmarc"]["record"] = txt_str
                    if 'p=reject' in txt_str.lower():
                        result["dmarc"]["policy"] = "reject"
                    elif 'p=quarantine' in txt_str.lower():
                        result["dmarc"]["policy"] = "quarantine"
                    elif 'p=none' in txt_str.lower():
                        result["dmarc"]["policy"] = "none"
                    break
        except:
            pass
        
        self._cache_set(cache_key, result, 7200)
        return result
    
    def check_blacklists(self, domain: str, ip: str = None):
        logger.debug(f"Checking blacklists for domain: {domain}")
        """فحص النطاق أو IP ضد قوائم الحظر السوداء"""
        cache_key = self._get_cache_key(f"{domain}:{ip}", "blacklist")
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        
        result = {
            "is_blacklisted": False,
            "total_lists": len(BLACKLISTS),
            "blacklisted_on": [],
            "clean_on": []
        }
        
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
            except:
                ip = "unknown"
        
        if ip != "unknown":
            ip_reversed = '.'.join(reversed(ip.split('.')))
            
            for bl in BLACKLISTS[:10]:  # حددنا العدد لتجنب الوقت الطويل
                bl_domain = f"{ip_reversed}.{bl}"
                try:
                    socket.gethostbyname(bl_domain)
                    result["is_blacklisted"] = True
                    logger.warning(f"⚠️ Domain {domain} found in blacklist: {bl}")
                    result["blacklisted_on"].append(bl)
                except socket.gaierror:
                    result["clean_on"].append(bl)
                except Exception:
                    pass
        
        self._cache_set(cache_key, result, 3600)
        return result
    
    def check_domain_info(self, domain: str):
        logger.debug(f"Getting WHOIS info for domain: {domain}")
        """الحصول على معلومات النطاق"""
        cache_key = self._get_cache_key(domain, "domain_info")
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        
        result = {
            "domain": domain,
            "age_days": None,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "name_servers": []
        }
        
        try:
            import whois
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                result["creation_date"] = creation.strftime("%Y-%m-%d")
                result["age_days"] = (datetime.now() - creation).days
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    exp = w.expiration_date[0]
                else:
                    exp = w.expiration_date
                result["expiration_date"] = exp.strftime("%Y-%m-%d")
            
            result["registrar"] = w.registrar or "Unknown"
            result["name_servers"] = w.name_servers or []
            
        except Exception as e:
            result["error"] = str(e)
        
        self._cache_set(cache_key, result, 86400)
        return result
    
    def check_all(self, email: str):
        logger.info(f"🔍 Starting comprehensive email check for: {email}")
        """الفحص الشامل للإيميل بكل الميزات"""
        
        valid_format, normalized, format_details = self.validate_format(email)
        
        if not valid_format:
            return {
                "email": email,
                "valid": False,
                "verdict": "invalid",
                "error": format_details.get("error"),
                "suggestions": format_details.get("suggestions", [])
            }
        
        domain = normalized.split('@')[-1]
        
        smtp_result = self.check_smtp(normalized)
        dns_result = self.check_dns_records(domain)
        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free = domain in FREE_DOMAINS
        blacklist_result = self.check_blacklists(domain)
        domain_info = self.check_domain_info(domain)
        
        # حساب نقاط الجودة
        quality_score = 100
        
        if not smtp_result.get("valid", False):
            quality_score -= 30
        if is_disposable:
            quality_score -= 50
        if blacklist_result.get("is_blacklisted", False):
            quality_score -= 40
        if not dns_result.get("spf", {}).get("exists", False):
            quality_score -= 10
        if not dns_result.get("dmarc", {}).get("exists", False):
            quality_score -= 10
        if domain_info.get("age_days", 0) and domain_info.get("age_days", 0) < 30:
            quality_score -= 20
        
        quality_score = max(0, min(100, quality_score))
        
        # تحديد الحكم النهائي
        if is_disposable:
            verdict = "disposable"
        elif blacklist_result.get("is_blacklisted", False):
            verdict = "blacklisted"
        elif not smtp_result.get("valid", False):
            verdict = "undeliverable"
        elif quality_score >= 80:
            verdict = "safe"
        elif quality_score >= 50:
            verdict = "moderate_risk"
        else:
            verdict = "high_risk"

        logger.info(f"✅ Email check completed for: {email} | Verdict: {verdict} | Score: {quality_score}")
        return {
            "email": normalized,
            "domain": domain,
            "valid": True,
            "verdict": verdict,
            "quality_score": quality_score,
            "format_suggestions": format_details.get("suggestions", []),
            "smtp": smtp_result,
            "dns": dns_result,
            "is_disposable": is_disposable,
            "is_free": is_free,
            "blacklist": blacklist_result,
            "domain_info": domain_info,
            "deliverability": "DELIVERABLE" if smtp_result.get("valid", False) else "UNDELIVERABLE",
            "checked_at": datetime.now().isoformat()
        }