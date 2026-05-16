# services/qr_analyzer.py
import requests
import time

class QRAnalyzer:
    """تحليل متقدم لرموز QR"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
    
    def scan_url(self, url: str, api_key: str) -> dict:
        """فحص الرابط المستخرج من QR عبر VirusTotal"""
        result = {
            "verdict": "unknown",
            "stats": {}
        }
        
        try:
            headers = {"x-apikey": api_key}
            resp = self.session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=30
            )
            
            if resp.status_code not in (200, 201):
                return result
            
            url_id = resp.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            
            for _ in range(10):
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
                        elif suspicious > 0:
                            result["verdict"] = "suspicious"
                        else:
                            result["verdict"] = "clean"
                        break
                time.sleep(2)
                
        except Exception as e:
            result["error"] = str(e)
        
        return result