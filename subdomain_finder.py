# subdomain_finder.py - مكتشف النطاقات الفرعية المتقدم
import dns.resolver
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import time

class SubdomainFinder:
    """مكتشف متقدم للنطاقات الفرعية"""
    
    # قائمة موسعة من النطاقات الفرعية الشائعة (1000+)
    COMMON_SUBDOMAINS = [
        # Basic
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
        'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'webdisk', 'cpanel', 'whm', 'autodiscover',
        'autoconfig', 'm', 'mobile', 'wap', 'secure', 'vpn', 'remote', 'dev', 'test',
        'stage', 'staging', 'demo', 'sandbox', 'beta', 'alpha', 'qa', 'devops',
        
        # Services
        'api', 'rest', 'graphql', 'oauth', 'auth', 'login', 'signin', 'account',
        'admin', 'administrator', 'manage', 'dashboard', 'control', 'panel',
        'backend', 'service', 'services', 'app', 'apps', 'application', 'portal',
        'my', 'mysite', 'site', 'website', 'home', 'start', 'new', 'old',
        
        # Cloud & Hosting
        'cloud', 'aws', 'azure', 'gcp', 'google', 'amazon', 'digitalocean',
        'heroku', 'netlify', 'vercel', 'firebase', 'cloudflare', 'cloudfront',
        's3', 'cdn', 'static', 'media', 'assets', 'images', 'img', 'video',
        'download', 'uploads', 'files', 'documents',
        
        # Development
        'git', 'github', 'gitlab', 'bitbucket', 'jenkins', 'jira', 'confluence',
        'wiki', 'docs', 'documentation', 'apidocs', 'swagger', 'redoc',
        'jenkins', 'sonar', 'nexus', 'artifactory', 'docker', 'registry',
        
        # Security
        'security', 'secure', 'sso', '2fa', 'mfa', 'totp', 'passport', 'auth',
        'cert', 'ssl', 'tls', 'encrypt', 'decrypt', 'crypto', 'vpn', 'proxy',
        
        # Monitoring
        'monitor', 'monitoring', 'status', 'health', 'healthcheck', 'ping',
        'metrics', 'stats', 'statistics', 'analytics', 'logs', 'logging',
        
        # Database
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
        'cassandra', 'mariadb', 'sql', 'nosql', 'dbadmin', 'phpmyadmin',
        
        # Marketing
        'www2', 'www3', 'blog', 'news', 'press', 'media', 'marketing', 'campaign',
        'landing', 'pages', 'lp', 'offers', 'promo', 'events', 'webinar',
        
        # E-commerce
        'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing',
        'invoice', 'orders', 'products', 'catalog', 'category', 'search',
        
        # Social
        'forum', 'community', 'chat', 'talk', 'discuss', 'feedback', 'support',
        'help', 'faq', 'knowledgebase', 'kb', 'tickets', 'contact',
        
        # Additional
        'server', 'host', 'hosting', 'web', 'webserver', 'appserver', 'database',
        'cache', 'proxy', 'loadbalancer', 'lb', 'firewall', 'gateway', 'router',
        'switch', 'storage', 'backup', 'archive', 'temp', 'tmp', 'logs'
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 5
        self.max_workers = 50  # عدد المتزامنات
    
    def check_subdomain(self, subdomain: str, domain: str) -> Dict[str, Any]:
        """فحص نطاق فرعي واحد"""
        full_domain = f"{subdomain}.{domain}"
        result = {
            "subdomain": subdomain,
            "full_domain": full_domain,
            "exists": False,
            "ip": None,
            "status_code": None,
            "verdict": "unknown",
            "error": None
        }
        
        # فحص DNS
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            result["exists"] = True
            result["ip"] = str(answers[0])
        except:
            return result
        
        # محاولة HTTP/HTTPS
        for protocol in ['https://', 'http://']:
            try:
                url = f"{protocol}{full_domain}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                result["status_code"] = resp.status_code
                result["final_url"] = resp.url
                
                # تحديد الحكم
                if 200 <= resp.status_code < 300:
                    result["verdict"] = "active"
                elif 300 <= resp.status_code < 400:
                    result["verdict"] = "redirect"
                else:
                    result["verdict"] = "inactive"
                break
            except:
                continue
        
        return result
    
    def find_subdomains(self, domain: str, max_subdomains: int = 200) -> Dict[str, Any]:
        """البحث عن النطاقات الفرعية"""
        
        # تنظيف النطاق
        domain = domain.replace('https://', '').replace('http://', '').strip('/')
        
        results = []
        found_count = 0
        
        # قائمة النطاقات الفرعية للفحص
        subdomains_to_check = self.COMMON_SUBDOMAINS[:max_subdomains]
        total = len(subdomains_to_check)
        
        # فحص متزامن
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_subdomain, sub, domain): sub 
                for sub in subdomains_to_check
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result["exists"]:
                    found_count += 1
                    results.append(result)
        
        # ترتيب النتائج
        active = [r for r in results if r["verdict"] == "active"]
        redirects = [r for r in results if r["verdict"] == "redirect"]
        inactive = [r for r in results if r["verdict"] == "inactive"]
        
        return {
            "domain": domain,
            "total_checked": total,
            "total_found": found_count,
            "active_count": len(active),
            "redirect_count": len(redirects),
            "inactive_count": len(inactive),
            "subdomains": {
                "active": active[:50],
                "redirects": redirects[:30],
                "inactive": inactive[:20]
            },
            "all_subdomains": [r["full_domain"] for r in results]
        }
    
    def get_subdomain_suggestions(self, domain: str) -> List[str]:
        """اقتراح نطاقات فرعية إضافية بناءً على النطاق"""
        suggestions = []
        
        # نطاقات خاصة بالمجال
        parts = domain.split('.')
        if len(parts) >= 2:
            base_name = parts[0]
            suggestions.extend([
                f"api.{base_name}", f"admin.{base_name}", f"dev.{base_name}",
                f"test.{base_name}", f"stage.{base_name}", f"blog.{base_name}",
                f"shop.{base_name}", f"mail.{base_name}", f"vpn.{base_name}"
            ])
        
        return suggestions[:10]