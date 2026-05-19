# services/url_deep_analyzer.py
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import hashlib
import json
import os

class URLDeepAnalyzer:
    """تحليل عميق للروابط - محتوى، سلوك، WHOIS، ومصادر OSINT مع تخزين مؤقت"""
    
    def __init__(self, cache_dir='cache', cache_ttl=86400):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 15
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        os.makedirs(cache_dir, exist_ok=True)
        
        self.SUSPICIOUS_KEYWORDS = [
            'verify', 'confirm', 'update', 'account', 'login', 'signin', 
            'password', 'credit', 'card', 'paypal', 'bank', 'secure',
            'authenticate', 'validate', 'unlock', 'suspended', 'limited'
        ]
        
        self.PHISHING_DOMAINS = self._load_phishing_cache()
    
    def _get_cache_key(self, url: str) -> str:
        return hashlib.md5(url.encode()).hexdigest()
    
    def _get_cached_result(self, url: str) -> dict:
        cache_key = self._get_cache_key(url)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['cached_at'])
                if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                    return cached['result']
            except:
                pass
        return None
    
    def _save_cached_result(self, url: str, result: dict):
        cache_key = self._get_cache_key(url)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'url': url,
                    'cached_at': datetime.now().isoformat(),
                    'result': result
                }, f)
        except:
            pass
    
    def _load_phishing_cache(self) -> set:
        cache_file = os.path.join(self.cache_dir, 'phishing_domains.json')
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return set(json.load(f))
            except:
                pass
        return set()
    
    def _save_phishing_cache(self, domain: str):
        cache_file = os.path.join(self.cache_dir, 'phishing_domains.json')
        self.PHISHING_DOMAINS.add(domain)
        with open(cache_file, 'w') as f:
            json.dump(list(self.PHISHING_DOMAINS), f)
    
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
                    result["urlhaus_id"] = data.get('id')
                    result["first_seen"] = data.get('firstseen')
                    result["last_seen"] = data.get('lastseen')
                    result["threat"] = data.get('threat')
                    result["tags"] = data.get('tags', [])
                    result["reporter"] = data.get('reporter')
                    result["details"] = f"Malicious URL detected - Type: {result['threat']}"
                elif data.get('query_status') == 'no_results':
                    result["details"] = "URL not found in URLhaus database"
                else:
                    result["details"] = f"Query status: {data.get('query_status')}"
            else:
                result["details"] = f"API Error: {resp.status_code}"
        except Exception as e:
            result["details"] = f"Error: {str(e)}"
        
        return result
    
    def check_osint_sources(self, url: str) -> Dict[str, Any]:
        """فحص الرابط ضد مصادر OSINT (URLhaus فقط حالياً)"""
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
    
    def analyze_page_content(self, url: str, html: str = None) -> Dict[str, Any]:
        """تحليل محتوى الصفحة"""
        if html is None:
            try:
                response = self.session.get(url, timeout=self.timeout)
                html = response.text
            except:
                return {"error": "Could not fetch page content"}
        
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
            "has_password_field": False
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
                result["internal_links"].append(href[:100])
            elif parsed.netloc:
                result["external_links"].append(href[:100])
        
        for script in soup.find_all('script', src=True):
            result["scripts"].append(script['src'])
        
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
    
    def analyze_behavior(self, url: str) -> Dict[str, Any]:
        """تحليل سلوك الرابط"""
        result = {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "redirect_chain": [],
            "is_shortened": False,
            "status_code": None,
            "behavior_risk_score": 0
        }
        
        short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 't.co', 'short.link']
        parsed = urlparse(url)
        if parsed.netloc in short_domains:
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
                        "url": r.url,
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
            result["error"] = str(e)
        
        return result
    
        def analyze_whois(self, domain: str) -> Dict[str, Any]:
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
                
                # جعل creation timezone-aware إذا كان naive
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
            result["error"] = str(e)
        
        return result
    
    def comprehensive_deep_analysis(self, url: str) -> Dict[str, Any]:
        """التحليل العميق الشامل للرابط مع تخزين مؤقت"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        cached_result = self._get_cached_result(url)
        if cached_result:
            cached_result['from_cache'] = True
            return cached_result
        
        result = {
            "url": url,
            "domain": urlparse(url).netloc,
            "timestamp": datetime.now().isoformat(),
            "page_content": {},
            "behavior": {},
            "whois": {},
            "osint": {},
            "overall_risk_score": 0,
            "verdict": "unknown",
            "summary": {}
        }
        
        result["behavior"] = self.analyze_behavior(url)
        
        if result["behavior"].get("final_url"):
            result["page_content"] = self.analyze_page_content(result["behavior"]["final_url"])
        
        result["whois"] = self.analyze_whois(result["domain"])
        result["osint"] = self.check_osint_sources(url)
        
        risk_score = 0
        risk_score += result["behavior"].get("behavior_risk_score", 0)
        risk_score += result["page_content"].get("content_risk_score", 0) * 0.3
        risk_score += result["whois"].get("whois_risk_score", 0)
        risk_score += result["osint"].get("osint_risk_score", 0)
        result["overall_risk_score"] = min(100, int(risk_score))
        
        if result["overall_risk_score"] >= 70:
            result["verdict"] = "malicious"
            result["summary"] = {"level": "High Risk", "color": "red", "message": "Multiple suspicious indicators detected. Avoid this URL."}
        elif result["overall_risk_score"] >= 40:
            result["verdict"] = "suspicious"
            result["summary"] = {"level": "Medium Risk", "color": "yellow", "message": "Some suspicious indicators found. Proceed with caution."}
        else:
            result["verdict"] = "safe"
            result["summary"] = {"level": "Low Risk", "color": "green", "message": "No significant threats detected."}
        
        result["recommendations"] = []
        if result["behavior"].get("is_shortened"):
            result["recommendations"].append("⚠️ URL shortener detected")
        if result["behavior"].get("redirect_count", 0) > 2:
            result["recommendations"].append("🔄 Multiple redirects detected")
        if result["whois"].get("is_new"):
            result["recommendations"].append("🆕 Domain is very new - typical of phishing sites")
        if result["page_content"].get("has_login_form"):
            result["recommendations"].append("🔐 Login form detected - verify site legitimacy")
        
        self._save_cached_result(url, result)
        result['from_cache'] = False
        
        return result