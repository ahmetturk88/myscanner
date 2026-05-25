# services/ip_analyzer.py
import requests
import logging
logger = logging.getLogger(__name__)

class IPAnalyzer:
    """تحليل متقدم لعناوين IP"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        logger.info("✅ IPAnalyzer initialized successfully")
    
    def analyze_ip(self, ip: str, abuseipdb_api_key: str = None) -> dict:
        logger.info(f"🔍 Starting IP analysis for: {ip}")
        """تحليل IP شامل"""
        
        # معلومات أساسية من ip-api
        result = self._get_ip_info(ip)
        
        if not result:
            logger.error(f"Invalid IP address: {ip}")
            return {"error": "Invalid IP address"}
        
        # فحص AbuseIPDB إذا توفر API Key
        if abuseipdb_api_key:
            logger.debug(f"Checking AbuseIPDB for IP: {ip}")
            abuse_result = self._check_abuseipdb(ip, abuseipdb_api_key)
            if abuse_result:
                result.update(abuse_result)
                if abuse_result.get("verdict") == "blacklisted":
                    logger.warning(f"⚠️ IP {ip} found in AbuseIPDB blacklist")
        
        logger.info(f"✅ IP analysis completed for: {ip} | Verdict: {result.get('verdict', 'unknown')}")
        return result
    
    def _get_ip_info(self, ip: str) -> dict:
        logger.debug(f"Fetching IP info for: {ip}")
        """الحصول على معلومات IP من ip-api"""
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query"},
                timeout=self.timeout
            )
            data = resp.json()
            
            if data.get('status') == 'fail':
                logger.warning(f"IP-API returned fail for: {ip}")
                return None
            
            # تحديد verdict
            is_proxy = data.get('proxy', False)
            is_hosting = data.get('hosting', False)
            
            if is_proxy or is_hosting:
                verdict = "suspicious"
                logger.warning(f"IP {ip} is proxy/hosting: Proxy={is_proxy}, Hosting={is_hosting}")
            else:
                verdict = "safe"
            
            return {
                "ip": data.get('query'),
                "verdict": verdict,
                "country": data.get('country'),
                "country_code": data.get('countryCode'),
                "city": data.get('city'),
                "region": data.get('regionName'),
                "timezone": data.get('timezone'),
                "isp": data.get('isp'),
                "org": data.get('org'),
                "lat": data.get('lat'),
                "lon": data.get('lon'),
                "is_proxy": is_proxy,
                "is_hosting": is_hosting,
                "is_mobile": data.get('mobile', False),
                "blacklist_count": 0,
                "blacklist_results": []
            }
        except Exception as e:
            logger.error(f"Error fetching IP info for {ip}: {str(e)}")
            return {"error": str(e)}
    
    def _check_abuseipdb(self, ip: str, api_key: str) -> dict:
        logger.debug(f"Checking AbuseIPDB for: {ip}")
        """فحص IP في AbuseIPDB"""
        try:
            headers = {"Key": api_key, "Accept": "application/json"}
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers,
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                total_reports = data.get("data", {}).get("totalReports", 0)
                
                if abuse_score > 0:
                    logger.warning(f"AbuseIPDB score for {ip}: {abuse_score}% ({total_reports} reports)")
                    return {
                        "blacklist_count": 1,
                        "blacklist_results": [{
                            "name": "AbuseIPDB",
                            "listed": True,
                            "detail": f"Score: {abuse_score}% ({total_reports} reports)"
                        }],
                        "verdict": "blacklisted" if abuse_score >= 50 else "suspicious"
                    }
            else:
                logger.warning(f"AbuseIPDB API returned status {resp.status_code} for {ip}")
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB for {ip}: {str(e)}")
        
        return {}
    # أضف هذه الدالة في نهاية class IPAnalyzer

    def analyze_with_tip(self, ip: str, user_id: int = None) -> dict:
        """
        تحليل IP مع دمج TIP
        """
        from services.ioc_lookup import IoCLookup
        
        result = self.analyze_ip(ip)
        
        try:
            lookup = IoCLookup()
            tip_result = lookup.lookup_ip(ip=ip, context='ip_check', user_id=user_id)
            
            if tip_result.get('found'):
                result['tip'] = tip_result
                result['tip_score'] = tip_result.get('tip_score', 0)
                
                if tip_result.get('highest_severity') == 'critical':
                    result['verdict'] = 'malicious'
                    result['risk_level'] = 'critical'
                elif tip_result.get('highest_severity') == 'high':
                    if result.get('risk_level') != 'critical':
                        result['risk_level'] = 'high'
        except Exception as e:
            result['tip_error'] = str(e)
        
        return result