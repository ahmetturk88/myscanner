# services/ip_analyzer.py
import requests

class IPAnalyzer:
    """تحليل متقدم لعناوين IP"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
    
    def analyze_ip(self, ip: str, abuseipdb_api_key: str = None) -> dict:
        """تحليل IP شامل"""
        
        # معلومات أساسية من ip-api
        result = self._get_ip_info(ip)
        
        if not result:
            return {"error": "Invalid IP address"}
        
        # فحص AbuseIPDB إذا توفر API Key
        if abuseipdb_api_key:
            abuse_result = self._check_abuseipdb(ip, abuseipdb_api_key)
            if abuse_result:
                result.update(abuse_result)
        
        return result
    
    def _get_ip_info(self, ip: str) -> dict:
        """الحصول على معلومات IP من ip-api"""
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile,query"},
                timeout=self.timeout
            )
            data = resp.json()
            
            if data.get('status') == 'fail':
                return None
            
            # تحديد verdict
            is_proxy = data.get('proxy', False)
            is_hosting = data.get('hosting', False)
            
            if is_proxy or is_hosting:
                verdict = "suspicious"
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
            return {"error": str(e)}
    
    def _check_abuseipdb(self, ip: str, api_key: str) -> dict:
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
                    return {
                        "blacklist_count": 1,
                        "blacklist_results": [{
                            "name": "AbuseIPDB",
                            "listed": True,
                            "detail": f"Score: {abuse_score}% ({total_reports} reports)"
                        }],
                        "verdict": "blacklisted" if abuse_score >= 50 else "suspicious"
                    }
        except:
            pass
        
        return {}