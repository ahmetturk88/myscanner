# services/qr_analyzer.py
import requests
import time
import logging
logger = logging.getLogger(__name__)

class QRAnalyzer:
    """تحليل متقدم لرموز QR"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        logger.info("✅ QRAnalyzer initialized successfully")
    
    def scan_url(self, url: str, api_key: str) -> dict:
        logger.info(f"🔍 Starting QR URL scan for: {url[:100]}...")
        """فحص الرابط المستخرج من QR عبر VirusTotal"""
        result = {
            "verdict": "unknown",
            "stats": {}
        }
        
        try:
            headers = {"x-apikey": api_key}
            logger.debug(f"Submitting URL to VirusTotal: {url[:100]}...")
            
            resp = self.session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=30
            )
            
            if resp.status_code not in (200, 201):
                logger.warning(f"VirusTotal submission failed with status {resp.status_code}")
                return result
            
            url_id = resp.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            logger.debug(f"Analysis ID: {url_id}")
            
            for attempt in range(10):
                r = self.session.get(analysis_url, headers=headers, timeout=30)
                if r.status_code == 200:
                    result_data = r.json()
                    if result_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                        stats = result_data["data"]["attributes"].get("stats", {})
                        result["stats"] = stats
                        
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        
                        if malicious > 0:
                            result["verdict"] = "malicious"
                            logger.warning(f"🚨 QR URL is MALICIOUS! Malicious: {malicious}, Suspicious: {suspicious}")
                        elif suspicious > 0:
                            result["verdict"] = "suspicious"
                            logger.warning(f"⚠️ QR URL is SUSPICIOUS! Malicious: {malicious}, Suspicious: {suspicious}")
                        else:
                            result["verdict"] = "clean"
                            logger.info(f"✅ QR URL is clean - Malicious: {malicious}, Suspicious: {suspicious}")
                        break
                time.sleep(2)
            else:
                logger.warning(f"VirusTotal scan timeout for URL: {url[:100]}...")
                
        except Exception as e:
            logger.error(f"Error scanning QR URL: {str(e)}")
            result["error"] = str(e)
        
        logger.info(f"✅ QR URL scan completed | Verdict: {result['verdict']}")
        return result