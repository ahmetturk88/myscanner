import hashlib
import json
import socket
from services.public_smtp import PublicSMTP
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
        if cached and cached.get("coverage_status") == "checked":
            return cached
        
        domain = email.split('@')[-1]
        result = {
            "valid": None,
            "coverage_status": "unavailable",
            "message": "SMTP verification could not be completed",
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
                smtp = None
                try:
                    smtp = PublicSMTP(timeout=timeout)
                    smtp.connect(mx, 25)
                    smtp.helo('checker.local')
                    smtp.mail('verify@checker.local')
                    code, message = smtp.rcpt(email)
                    
                    result["response_code"] = code
                    result["response_message"] = message.decode() if isinstance(message, bytes) else str(message)
                    
                    if code == 250:
                        result["coverage_status"] = "checked"
                        result["valid"] = True
                        logger.info(f"✅ SMTP check passed for: {email}")
                        result["message"] = "Mailbox exists"
                    elif code in (550, 551):
                        result["coverage_status"] = "checked"
                        result["valid"] = False
                        logger.warning(f"SMTP check failed for: {email} - {result['message']}")
                        result["message"] = "Mailbox does not exist"
                    else:
                        result["message"] = f"Response: {code}"
                    
                    smtp.quit()
                    break
                    
                except Exception:
                    continue
                finally:
                    if smtp is not None:
                        smtp.close()
                    
        except Exception:
            result["message"] = "SMTP verification could not be completed"
        
        self._cache_set(cache_key, result, 3600)
        return result
    
    def check_dns_records(self, domain: str):
        result = {"spf":{"exists":False,"record":None,"valid":False,"status":"unavailable"},
                  "dmarc":{"exists":False,"record":None,"policy":None,"status":"unavailable"},
                  "dkim":{"exists":None,"status":"not_checked","records":[]},
                  "mx":{"exists":False,"records":[],"status":"unavailable"},"txt":{"records":[]}}
        def lookup(name, kind):
            try:return list(dns.resolver.resolve(name,kind,lifetime=3)), "found"
            except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer):return [], "not_found"
            except Exception:return [], "unavailable"
        records,status=lookup(domain,'MX');result['mx']['status']=status
        result['mx']['records']=[{'preference':r.preference,'exchange':str(r.exchange).rstrip('.')} for r in records]
        result['mx']['exists']=bool(records)
        records,status=lookup(domain,'TXT')
        texts=[''.join(part.decode('utf-8',errors='replace') for part in r.strings) for r in records]
        result['txt']['records']=texts
        spf=[text for text in texts if text.lower().startswith('v=spf1')]
        result['spf'].update(exists=bool(spf),record=spf[0] if spf else None,valid=bool(spf),status='found' if spf else 'not_found' if status!='unavailable' else 'unavailable')
        records,status=lookup('_dmarc.'+domain,'TXT')
        texts=[''.join(part.decode('utf-8',errors='replace') for part in r.strings) for r in records]
        dmarc=[text for text in texts if text.lower().startswith('v=dmarc1')]
        record=dmarc[0] if dmarc else None
        tags={item.split('=',1)[0].strip().lower():item.split('=',1)[1].strip().lower() for item in (record or '').split(';') if '=' in item}
        result['dmarc'].update(exists=bool(dmarc),record=record,policy=tags.get('p'),status='found' if dmarc else 'not_found' if status!='unavailable' else 'unavailable')
        return result

    def check_blacklists(self, domain: str, ip: str = None):
        import ipaddress
        sources=list(BLACKLISTS[:10])
        result={'is_blacklisted':False,'total_lists':len(sources),'blacklisted_on':[], 'clean_on':[], 'unavailable_on':[], 'coverage_status':'partial'}
        try:
            address=ip or str(dns.resolver.resolve(domain,'A',lifetime=3)[0])
            parsed=ipaddress.ip_address(address)
            if parsed.version!=4 or not parsed.is_global:raise ValueError()
        except Exception:
            result['unavailable_on']=sources;return result
        reverse='.'.join(reversed(address.split('.')))
        for source in sources:
            try:
                answers=[str(r) for r in dns.resolver.resolve(reverse+'.'+source,'A',lifetime=2)]
                # Resolver/provider error codes (e.g. 127.255.*) are not listings.
                if answers and all(a.startswith('127.0.0.') and a.rsplit('.',1)[1].isdigit() and 2<=int(a.rsplit('.',1)[1])<=11 for a in answers):
                    result['blacklisted_on'].append(source)
                else:result['unavailable_on'].append(source)
            except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer):result['clean_on'].append(source)
            except Exception:result['unavailable_on'].append(source)
        result['is_blacklisted']=bool(result['blacklisted_on'])
        result['coverage_status']='completed' if sources and not result['unavailable_on'] else 'partial'
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
    
    def check_all(self, email: str, verify_smtp: bool = False):
        if not isinstance(verify_smtp, bool):
            raise ValueError('SMTP consent must be a boolean')
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
        
        smtp_result = self.check_smtp(normalized) if verify_smtp else {
            'valid': None, 'coverage_status': 'skipped',
            'message': 'Direct SMTP recipient verification was not requested.', 'servers': []
        }
        dns_result = self.check_dns_records(domain)
        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free = domain in FREE_DOMAINS
        blacklist_result = self.check_blacklists(domain)
        domain_info = self.check_domain_info(domain)
        
        # حساب نقاط الجودة
        quality_score = 100
        
        if smtp_result.get("valid") is False:
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
        elif smtp_result.get("valid") is False:
            verdict = "undeliverable"
        elif smtp_result.get("valid") is not True:
            verdict = "unknown"
        elif quality_score >= 80:
            verdict = "safe"
        elif quality_score >= 50:
            verdict = "moderate_risk"
        else:
            verdict = "high_risk"

        logger.info(f"✅ Email check completed for: {email} | Verdict: {verdict} | Score: {quality_score}")
        report = {
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
            "deliverability": "DELIVERABLE" if smtp_result.get("valid") is True else "UNDELIVERABLE" if smtp_result.get("valid") is False else "UNKNOWN",
            "checked_at": datetime.now().isoformat()
        }
        from services.email_assessment import assess_email
        report["assessment"] = assess_email(report)
        return report
