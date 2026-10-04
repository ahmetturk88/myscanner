# services/urlvet_client.py
# =================================================================
# URLVET CLIENT - عميل التواصل مع url.vet API
# بديل احترافي لـ VirusTotal، مع تحليل مفصّل وقابل للتوسع
# =================================================================

import os
import logging
import traceback
import requests
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class URLVetClient:
    """
    عميل متكامل للتواصل مع url.vet API

    الميزات:
    - تحليل شامل للروابط (18 محلل، 33 إشارة)
    - Trust Score واضح (0-100)
    - Verdict (Safe, Suspicious, Risky, Malicious)
    - Red Flags / Green Flags / Neutral Reasons
    - كشف Phishing (PhishTank)
    - كشف Typosquatting
    - كشف URL Shorteners
    - فحص SSL/TLS
    - فحص WHOIS
    - لقطة شاشة للموقع
    """

    def __init__(self, base_url: str = None, timeout: int = 30):
        """تهيئة العميل"""
        self.base_url = base_url or os.getenv('URLVET_URL', 'http://localhost:8080')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MyScanner/1.0 (url.vet client)',
            'Accept': 'application/json'
        })
        logger.info(f"✅ URLVetClient initialized: {self.base_url}")

    # ================================================================
    # 1. الدالة الرئيسية: تحليل رابط
    # ================================================================

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """تحليل شامل لرابط عبر url.vet"""
        if not url:
            return self._error_response("No URL provided")

        # تأكد من أن الرابط يبدأ بـ http/https
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            logger.info(f"🔍 Analyzing URL via url.vet: {url}")

            response = self.session.get(
                f"{self.base_url}/api/v1/analyze",
                params={'url': url},
                timeout=self.timeout
            )

            if response.status_code != 200:
                logger.error(f"url.vet returned status {response.status_code}")
                return self._error_response(f"API error: {response.status_code}")

            data = response.json()
            logger.info(f"✅ url.vet analysis completed for {url}")

            return self._parse_response(url, data)

        except requests.exceptions.Timeout:
            logger.error(f"url.vet timeout for {url}")
            return self._error_response("Request timeout")
        except requests.exceptions.ConnectionError:
            logger.error(f"url.vet connection error for {url}")
            return self._error_response("Cannot connect to url.vet")
        except Exception as e:
            logger.error(f"url.vet error for {url}: {str(e)}")
            traceback.print_exc()
            return self._error_response(str(e))

    # ================================================================
    # 2. تحويل الاستجابة إلى تنسيق موحد
    # ================================================================

    def _parse_response(self, url: str, data: Dict) -> Dict[str, Any]:
        """تحويل استجابة url.vet إلى تنسيق موحد مع MyScanner"""

        # --- معالجة جميع الحقول التي قد تكون None ---
        result          = data.get('result') or {}
        features        = data.get('features') or {}
        domain_info     = data.get('domain_info') or {}
        ssl_info        = data.get('ssl_info') or {}
        tls_info        = data.get('tls_info') or {}
        content_data    = data.get('content_data') or {}
        infrastructure  = data.get('infrastructure') or {}
        analysis        = data.get('analysis') or {}
        phishing        = data.get('phishing') or {}
        typosquat       = data.get('typosquat_result') or {}
        randomness      = data.get('domain_randomness') or {}

        # --- داخل features ---
        url_features    = features.get('url') or {}
        url_keywords    = url_features.get('keywords') or {}
        tld_features    = features.get('tld') or {}

        # --- داخل result ---
        reasons         = result.get('reasons') or {}
        good_reasons    = reasons.get('good_reasons') or []
        bad_reasons     = reasons.get('bad_reasons') or []
        neutral_reasons = reasons.get('neutral_reasons') or []

        # --- داخل analysis ---
        redirection     = analysis.get('redirection_result') or {}
        http_status     = analysis.get('http_status') or {}

        # --- داخل content_data ---
        brand_check     = content_data.get('brand_check') or {}

        # --- استخراج القيم الأساسية ---
        trust_score = result.get('trust_score', 0)
        final_score = result.get('final_score', 0)
        verdict     = result.get('verdict', 'Unknown')
        risk_score  = result.get('risk_score', 0)

        # --- تحويل الـ verdict إلى تنسيق MyScanner ---
        verdict_lower = str(verdict).lower()
        if verdict_lower == 'safe':
            my_verdict = 'harmless'
        elif verdict_lower in ('risky', 'suspicious'):
            my_verdict = 'suspicious'
        elif verdict_lower in ('malicious', 'high risk'):
            my_verdict = 'malicious'
        else:
            my_verdict = 'unknown'

        return {
            'source': 'url.vet',
            'url': url,
            'verdict': my_verdict,
            'verdict_raw': verdict,
            'trust_score': trust_score,
            'final_score': final_score,
            'risk_score': risk_score,

            # الأسباب (مفصلة)
            'red_flags': bad_reasons,
            'green_flags': good_reasons,
            'neutral_reasons': neutral_reasons,

            # معلومات النطاق
            'domain_info': {
                'registrar': domain_info.get('registrar', 'N/A'),
                'created': domain_info.get('created', 'N/A'),
                'expiry': domain_info.get('expiry', 'N/A'),
                'age_human': domain_info.get('age_human', 'N/A'),
                'age_days': domain_info.get('age_days', 0),
                'dnssec': domain_info.get('dnssec', False),
                'nameservers': domain_info.get('nameservers') or []
            },

            # SSL/TLS
            'ssl_info': {
                'has_tls': ssl_info.get('HasTLS', False),
                'chain_valid': ssl_info.get('ChainValid', False),
                'issuer': ssl_info.get('Issuer', 'N/A'),
                'not_after': ssl_info.get('NotAfter', 'N/A'),
                'is_suspicious': ssl_info.get('IsSuspicious', False),
                'reasons': ssl_info.get('Reasons') or []
            },

            # البنية التحتية
            'infrastructure': {
                'ip_addresses': infrastructure.get('ip_addresses') or [],
                'nameservers_valid': infrastructure.get('nameservers_valid', False),
                'ns_hosts': infrastructure.get('ns_hosts') or []
            },

            # التحليل
            'analysis': {
                'is_redirected': redirection.get('is_redirected', False),
                'chain_length': redirection.get('chain_length', 0),
                'final_url': redirection.get('final_url', url),
                'http_status': http_status.get('code', 0),
                'hsts_supported': analysis.get('is_hsts_supported', False)
            },

            # Phishing (PhishTank)
            'phishing': {
                'in_database': phishing.get('in_database', False),
                'verified': phishing.get('verified', False),
                'target': phishing.get('target', ''),
                'source': phishing.get('source', 'phishtank')
            },

            # Typosquatting
            'typosquatting': {
                'is_suspicious': typosquat.get('is_suspicious', False)
            },

            # تحليل النطاق العشوائي
            'domain_randomness': {
                'entropy': randomness.get('Entropy', 0),
                'is_suspicious': randomness.get('IsSuspicious', False),
                'reasons': randomness.get('Reasons') or []
            },

            # ميزات الرابط
            'url_features': {
                'url_shortener': url_features.get('url_shortener', False),
                'uses_ip': url_features.get('uses_ip', False),
                'contains_punycode': url_features.get('contains_punycode', False),
                'too_long': url_features.get('too_long', False),
                'too_deep': url_features.get('too_deep', False),
                'has_homoglyph': url_features.get('has_homoglyph', False),
                'subdomain_count': url_features.get('subdomain_count', 0),
                'has_keywords': url_keywords.get('has_keywords', False),
                'keywords_found': url_keywords.get('found') or []
            },

            # TLD
            'tld_info': {
                'tld': tld_features.get('tld', ''),
                'is_trusted': tld_features.get('is_trusted_tld', False),
                'is_risky': tld_features.get('is_risky_tld', False),
                'is_icann': tld_features.get('is_icann', False)
            },

            # محتوى الصفحة
            'content': {
                'title': content_data.get('title', ''),
                'has_forms': content_data.get('has_forms', False),
                'has_login_form': content_data.get('has_login_form', False),
                'has_payment_form': content_data.get('has_payment_form', False),
                'has_hidden_iframe': content_data.get('has_hidden_iframe', False),
                'brand_found': brand_check.get('brand_found', ''),
                'brand_mismatch': brand_check.get('is_mismatch', False)
            },

            # لقطة الشاشة
            'screenshot': f"{self.base_url}/api/v1/screenshot?url={url}",

            # معلومات إضافية
            'incomplete': data.get('incomplete', False),
            'errors': data.get('errors') or [],

            # الطابع الزمني
            'analyzed_at': datetime.utcnow().isoformat()
        }

    # ================================================================
    # 3. استجابة الخطأ
    # ================================================================

    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """إنشاء استجابة خطأ موحدة"""
        return {
            'source': 'url.vet',
            'verdict': 'error',
            'error': error_message,
            'trust_score': 0,
            'final_score': 0,
            'red_flags': [],
            'green_flags': [],
            'neutral_reasons': [],
            'analyzed_at': datetime.utcnow().isoformat()
        }

    # ================================================================
    # 4. فحص صحة الاتصال
    # ================================================================

    def is_available(self) -> bool:
        """التحقق من أن url.vet متاح"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/health",
                timeout=5
            )
            return response.status_code == 200
        except Exception:
            return False


# ================================================================
# نسخة وحيدة (Singleton)
# ================================================================

_urlvet_instance: Optional[URLVetClient] = None


def get_urlvet_client() -> URLVetClient:
    """الحصول على نسخة وحيدة من URLVetClient"""
    global _urlvet_instance
    if _urlvet_instance is None:
        _urlvet_instance = URLVetClient()
    return _urlvet_instance


# ================================================================
# اختبار سريع
# ================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = URLVetClient()

    print("=" * 60)
    print("URLVET CLIENT TEST")
    print("=" * 60)

    # اختبار 1: رابط آمن
    print("\n[Test 1] Safe URL: https://example.com")
    result = client.analyze_url("https://example.com")
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Trust Score: {result.get('trust_score')}/100")
    print(f"  Green Flags: {len(result.get('green_flags', []))}")

    # اختبار 2: رابط مشبوه
    print("\n[Test 2] Suspicious URL: http://paypal-login-secure.tk")
    result = client.analyze_url("http://paypal-login-secure.tk")
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Trust Score: {result.get('trust_score')}/100")
    print(f"  Red Flags: {result.get('red_flags', [])}")

    # اختبار 3: فحص الاتصال
    print("\n[Test 3] Health check")
    print(f"  url.vet available: {client.is_available()}")