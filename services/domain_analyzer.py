# services/domain_analyzer.py
import requests
from urllib.parse import urlparse
import logging
logger = logging.getLogger(__name__)

class DomainAnalyzer:
    """تحليل متقدم للنطاقات"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        logger.info("✅ DomainAnalyzer initialized successfully")
    
    def analyze_domain(self, domain: str) -> dict:
        logger.info(f"🔍 Starting domain analysis for: {domain}")
        """تحليل نطاق شامل"""
        
        # تنظيف النطاق
        domain = domain.replace('https://', '').replace('http://', '').strip('/')
        
        result = {
            "domain": domain,
            "registrar": "N/A",
            "created": "N/A",
            "expires": "N/A",
            "ip": "N/A",
            "country": "N/A",
            "isp": "N/A",
            "nameservers": [],
            "dns": [],
            "whois_updated": "N/A",
            "status": "N/A",
        }
        
        # 1. WHOIS via whoisxmlapi (free)
        result.update(self._get_whois_info(domain))
        
        # 2. IP info via ip-api
        result.update(self._get_ip_info(domain))
        
        # 3. DNS Records
        result["dns"] = self._get_dns_records(domain)
        logger.info(f"✅ Domain analysis completed for: {domain}")
        return result
    
    def _get_whois_info(self, domain: str) -> dict:
        logger.debug(f"Fetching WHOIS info for: {domain}")
        """الحصول على معلومات WHOIS"""
        try:
            resp = self.session.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "domainName": domain,
                    "apiKey": "at_free_demo_key",
                    "outputFormat": "JSON"
                },
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                whois_data = resp.json()
                reg_record = whois_data.get("WhoisRecord", {})
                
                nameservers = reg_record.get("nameServers", {}).get("hostNames", [])
                
                return {
                    "registrar": reg_record.get("registrarName", "N/A"),
                    "created": (reg_record.get("createdDate") or "N/A")[:10],
                    "expires": (reg_record.get("expiresDate") or "N/A")[:10],
                    "whois_updated": (reg_record.get("updatedDate") or "N/A")[:10],
                    "status": reg_record.get("status", "N/A"),
                    "nameservers": nameservers[:5] if nameservers else []
                }
        except Exception as e:
            logger.error(f"Error fetching WHOIS for {domain}: {str(e)}")
        return {}
    
    def _get_ip_info(self, domain: str) -> dict:
        logger.debug(f"Fetching IP info for: {domain}")
        """الحصول على معلومات IP للنطاق"""
        try:
            resp = self.session.get(f"http://ip-api.com/json/{domain}", timeout=self.timeout)
            if resp.status_code == 200:
                r = resp.json()
                if r.get('status') != 'fail':
                    return {
                        "ip": r.get('query', 'N/A'),
                        "country": r.get('country', 'N/A'),
                        "isp": r.get('isp', 'N/A')
                    }
        except Exception as e:
            logger.error(f"Error fetching IP info for {domain}: {str(e)}")
        return {}
    
    def _get_dns_records(self, domain: str) -> list:
        logger.debug(f"Fetching DNS records for: {domain}")
        """الحصول على سجلات DNS"""
        records = []
        
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
            try:
                resp = self.session.get(
                    f"https://dns.google/resolve?name={domain}&type={rtype}",
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    answers = resp.json().get('Answer', [])
                    for ans in answers[:3]:
                        val = ans.get('data', '')
                        if val:
                            records.append({"type": rtype, "value": val})
            except Exception as e:
                logger.error(f"Error fetching DNS records for {domain}: {str(e)}")
        return records