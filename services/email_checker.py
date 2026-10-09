import hashlib
import json
import socket
import time
import ssl
from services.public_smtp import PublicSMTP
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import dns.resolver
import Levenshtein
from email_validator import validate_email, EmailNotValidError
from constants import DISPOSABLE_DOMAINS, FREE_DOMAINS
# DNS query zones, not provider website domains.
BLACKLISTS = ["zen.spamhaus.org", "bl.spamcop.net"]
import logging
logger = logging.getLogger(__name__)
class AdvancedEmailChecker:
    """Bounded email-domain evidence collection, with optional recipient probes."""
    
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
            
            domain = normalized.rsplit('@', 1)[-1].lower()
            suggestions = []
            
            common_domains = {
                'gmial.com': 'gmail.com', 'gmail.co': 'gmail.com',
                'yaho.com': 'yahoo.com', 'hotmai.com': 'hotmail.com',
                'outloo.com': 'outlook.com', 'protonmal.com': 'protonmail.com'
            }
            
            if domain in FREE_DOMAINS:
                return True, normalized, {'suggestions': []}
            if domain in common_domains:
                corrected = normalized.rsplit('@',1)[0] + '@' + common_domains[domain]
                suggestions.append({
                    "original": email,
                    "suggested": corrected,
                    "type": "domain_typo",
                    "confidence": 0.95
                })
            
            return True, normalized, {"suggestions": suggestions}
            
        except EmailNotValidError as e:
            return False, email, {"error": str(e), "suggestions": []}
    
    def check_smtp(self, email: str, timeout: int = 5):
        logger.debug(f"Checking SMTP for: {email}")
        """Optional encrypted recipient probe, not proof of mailbox existence."""
        cache_key = self._get_cache_key(email, "smtp")
        cached = self._cache_get(cache_key)
        if cached and cached.get("coverage_status") == "checked" and cached.get("probe_version") == 2:
            return cached
        
        domain = email.split('@')[-1]
        result = {
            "valid": None,
            "coverage_status": "unavailable",
            "message": "SMTP verification could not be completed",
            "existence_verified": False,
            "ownership_verified": False,
            "catch_all_checked": False,
            "scope": "One recipient probe over authenticated STARTTLS; no message sent.",
            "probe_version": 2,
            "mx_servers": [],
            "response_code": None,
            "response_message": None
        }
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=3)
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
                    hello = smtp.ehlo('checker.local')
                    if not isinstance(hello, tuple) or hello[0] != 250:
                        continue
                    if smtp.has_extn('starttls') is not True:
                        result['message'] = 'Recipient probe skipped: authenticated STARTTLS was not available.'
                        continue
                    smtp.starttls(context=ssl.create_default_context())
                    result['tls_verified'] = True
                    result['tls_host'] = mx
                    hello = smtp.ehlo('checker.local')
                    if not isinstance(hello, tuple) or hello[0] != 250:
                        continue
                    sender = smtp.mail('')
                    if isinstance(sender, tuple) and sender[0] >= 400:
                        continue
                    code, message = smtp.rcpt(email)
                    
                    result["response_code"] = code
                    result["response_message"] = message.decode() if isinstance(message, bytes) else str(message)
                    
                    if code == 250:
                        result["coverage_status"] = "checked"
                        result["valid"] = True
                        logger.info(f"✅ SMTP check passed for: {email}")
                        result["message"] = "The server accepted this recipient probe; mailbox existence and ownership are not proven."
                    elif code in (550, 551):
                        result["coverage_status"] = "checked"
                        result["valid"] = False
                        logger.warning(f"SMTP check failed for: {email} - {result['message']}")
                        result["message"] = "The server rejected this recipient probe; policy or access restrictions may be responsible."
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
        deadline = time.monotonic() + 20
        result = {"spf":{"exists":False,"record":None,"valid":False,"status":"unavailable"},
                  "dmarc":{"exists":False,"record":None,"policy":None,"status":"unavailable"},
                  "dkim":{"exists":None,"status":"not_checked","records":[]},
                  "mx":{"exists":False,"records":[],"status":"unavailable"},"txt":{"records":[]}}
        def lookup(name, kind):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:return [], 'unavailable'
                return list(dns.resolver.resolve(name,kind,lifetime=min(3,remaining))), 'found'
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
        from services.email_policy_audit import audit_spf, audit_dmarc
        def txt_lookup(name, kind):
            answers,state=lookup(name,kind)
            return [''.join(part.decode('utf-8',errors='replace') for part in r.strings) for r in answers],state
        if result['spf']['status']=='found':
            result['spf']['audit']=audit_spf(domain,result['txt']['records'],txt_lookup)
            result['spf']['valid']=result['spf']['audit']['configuration_valid']
        if result['dmarc']['status']=='found':
            result['dmarc']['audit']=audit_dmarc(texts)
            result['dmarc']['policy']=result['dmarc']['audit']['policy'] if 'policy' in result['dmarc']['audit'] else None
        # Discover public mail infrastructure without opening target connections.
        import ipaddress
        hosts=[r['exchange'] for r in sorted(result['mx']['records'],key=lambda r:r['preference']) if r['exchange']][:3]
        def infrastructure(host):
            item={'host':host,'addresses':[], 'status':'assessed', 'unsafe_addresses':[]}
            for kind in ('A','AAAA'):
                answers,state=lookup(host,kind)
                if state=='unavailable':item['status']='partial'
                for answer in answers:
                    address=str(answer)
                    try:
                        if not ipaddress.ip_address(address).is_global:item['unsafe_addresses'].append(address)
                        else:item['addresses'].append(address)
                    except ValueError:item['status']='partial'
            if not item['addresses']:item['status']='unavailable'
            return item
        with ThreadPoolExecutor(max_workers=3) as pool:
            result['mx']['infrastructure']=list(pool.map(infrastructure,hosts))
        result['mx']['scope']='Up to three preferred MX hosts; IPv4 and IPv6 DNS records. No TLS connection was made.'
        for key,name,prefix in (('mta_sts','_mta-sts.','v=STSv1'),('tls_rpt','_smtp._tls.','v=TLSRPTv1')):
            values,state=txt_lookup(name+domain,'TXT')
            matching=[v for v in values if v.startswith(prefix)]
            result[key]={'records':matching,'status':'found' if matching else 'unavailable' if state=='unavailable' else 'not_found','scope':'TXT discovery only; HTTPS policy, enforcement and reporting destination authorization not verified.'}
        return result

    def check_blacklists(self, domain: str, ip: str = None, mx_records=None):
        import ipaddress
        sources=list(BLACKLISTS)
        result={'is_blacklisted':False,'total_lists':len(sources),'blacklisted_on':[], 'clean_on':[], 'unavailable_on':[], 'coverage_status':'partial','checks':[], 'scope':'Sample of up to four public MX IPv4 addresses; not mailbox reputation or outbound sender reputation.'}
        addresses=[]
        if ip:addresses=[ip]
        elif mx_records is not None:
            addresses=list(dict.fromkeys(address for host in mx_records for address in host.get('addresses',[]) if ':' not in address))[:4]
        else:
            result['unavailable_on']=sources
            return result
        try:
            if not addresses or any(not ipaddress.ip_address(a).is_global or ipaddress.ip_address(a).version!=4 for a in addresses):raise ValueError()
        except ValueError:
            result['unavailable_on']=sources;return result
        result['queried_ips']=addresses
        def classify(name):
            try:
                answers=[str(r) for r in dns.resolver.resolve(name,'A',lifetime=2)]
                if answers and all(a.startswith('127.0.0.') and a.rsplit('.',1)[1].isdigit() and 2<=int(a.rsplit('.',1)[1])<=11 for a in answers):return 'listed',answers
                return 'unavailable',answers
            except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer):return 'not_found',[]
            except Exception:return 'unavailable',[]
        def check_source(source):
            health,codes=classify('2.0.0.127.'+source)
            if health!='listed':
                return source,[{'source':source,'status':'unavailable','reason':'Source control query did not confirm availability','response_codes':codes}]
            checks=[]
            for address in addresses:
                state,codes=classify('.'.join(reversed(address.split('.')))+'.'+source)
                checks.append({'source':source,'ip':address,'status':state,'response_codes':codes})
            return source,checks
        with ThreadPoolExecutor(max_workers=2) as pool:
            for source,checks in pool.map(check_source,sources):
                result['checks'].extend(checks)
                if any(c['status']=='listed' for c in checks):result['blacklisted_on'].append(source)
                if any(c['status']=='unavailable' for c in checks):result['unavailable_on'].append(source)
                if all(c['status']=='not_found' for c in checks):result['clean_on'].append(source)
        result['is_blacklisted']=bool(result['blacklisted_on'])
        result['coverage_status']='completed' if sources and not result['unavailable_on'] else 'partial'
        return result

    def check_domain_info(self, domain: str):
        logger.debug(f"Getting WHOIS info for domain: {domain}")
        """الحصول على معلومات النطاق"""
        cache_key = self._get_cache_key(domain, "domain_info_v2")
        cached = self._cache_get(cache_key)
        if cached and not cached.get("error"):
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
            w = whois.whois(domain, timeout=6)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                result["creation_date"] = creation.strftime("%Y-%m-%d")
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                result['age_days'] = max(0, (datetime.now(timezone.utc) - creation.astimezone(timezone.utc)).days)
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    exp = w.expiration_date[0]
                else:
                    exp = w.expiration_date
                result["expiration_date"] = exp.strftime("%Y-%m-%d")
            
            result["registrar"] = w.registrar or "Unknown"
            result["name_servers"] = w.name_servers or []
            
        except Exception as e:
            result["error"] = "Registration lookup unavailable"
        
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
        blacklist_result = self.check_blacklists(domain, mx_records=dns_result.get("mx",{}).get("infrastructure",[]))
        domain_info = self.check_domain_info(domain)
        
        report = {
            "email": normalized,
            "domain": domain,
            "valid": True,
            "format_suggestions": format_details.get("suggestions", []),
            "address_features": {"internationalized_domain": any(label.startswith("xn--") for label in domain.split(".")), "plus_alias": "+" in normalized.rsplit("@",1)[0], "scope": "Address structure only; aliases and internationalized domains are not inherently malicious."},
            "smtp": smtp_result,
            "dns": dns_result,
            "is_disposable": is_disposable,
            "is_free": is_free,
            "blacklist": blacklist_result,
            "domain_info": domain_info,
            "deliverability": "PROBE_ACCEPTED" if smtp_result.get("valid") is True else "PROBE_REJECTED" if smtp_result.get("valid") is False else "UNKNOWN",
            "checked_at": datetime.now(timezone.utc).isoformat()
        }
        from services.email_assessment import assess_email
        report['assessment'] = assess_email(report)
        report['quality_score'] = report['assessment']['score']
        report['verdict'] = report['assessment']['verdict']
        return report
