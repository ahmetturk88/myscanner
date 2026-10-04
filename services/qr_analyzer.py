# services/qr_analyzer.py
# =================================================================
# QR ANALYZER - تحليل متقدم لرموز QR
# يستخدم: url.vet + التحليل المحلي (بدلاً من VirusTotal)
# =================================================================

import logging
from services.safe_http import UnsafeTargetError
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class QRAnalyzer:
    """تحليل متقدم لرموز QR"""

    def __init__(self):
        self.timeout = 15
        logger.info("✅ QRAnalyzer initialized successfully")

    # ================================================================
    # الدالة الرئيسية: فحص رابط QR
    # ================================================================
    
    def scan_url(self, url: str, api_key: str = None) -> Dict[str, Any]:
        """
        فحص الرابط المستخرج من QR عبر url.vet + التحليل المحلي
        
        Args:
            url: الرابط المستخرج من QR
            api_key: (غير مستخدم - متروك للتوافق مع الكود القديم)
        
        Returns:
            Dict يحتوي على نتائج الفحص
        """
        logger.info(f"🔍 Starting QR URL scan for: {url[:100]}...")

        # ─────────────────────────────────────────────────────────────
        # 1. التحقق من الرابط
        # ─────────────────────────────────────────────────────────────
        if not url or not isinstance(url, str):
            return {
                "verdict": "unknown",
                "error": "Invalid URL",
                "source": "qr_analyzer"
            }

        # ─────────────────────────────────────────────────────────────
        # 2. استخدام url.vet + التحليل المحلي
        # ─────────────────────────────────────────────────────────────
        try:
            from services.url_analyzer import URLDeepAnalyzer
            
            analyzer = URLDeepAnalyzer()
            analysis = analyzer.comprehensive_analysis(url)
            
            # استخراج البيانات من url.vet
            urlvet = analysis.get('urlvet', {}) or {}
            
            trust_score = urlvet.get('trust_score', 0)
            verdict_raw = urlvet.get('verdict', 'unknown')
            red_flags = urlvet.get('red_flags', []) or []
            green_flags = urlvet.get('green_flags', []) or []
            
            # ─────────────────────────────────────────────────────────
            # تحويل الحكم إلى التنسيق القديم (للتوافق)
            # ─────────────────────────────────────────────────────────
            if verdict_raw == 'harmless':
                verdict = 'clean'
            elif verdict_raw == 'suspicious':
                verdict = 'suspicious'
            elif verdict_raw == 'malicious':
                verdict = 'malicious'
            else:
                verdict = 'unknown'
            
            # ─────────────────────────────────────────────────────────
            # بناء النتيجة
            # ─────────────────────────────────────────────────────────
            result = {
                "verdict": verdict,
                "verdict_raw": verdict_raw,
                "trust_score": trust_score,
                "red_flags": red_flags,
                "green_flags": green_flags,
                "stats": {
                    "trust_score": trust_score,
                    "red_flags_count": len(red_flags),
                    "green_flags_count": len(green_flags)
                },
                "source": "url.vet + local_analysis",
                "url": url
            }
            
            # إضافة معلومات محلية
            local_verdict = analysis.get('verdict', 'unknown')
            local_score = analysis.get('security_score', 0)
            
            result["local_verdict"] = local_verdict
            result["local_security_score"] = local_score
            
            # ─────────────────────────────────────────────────────────
            # تسجيل النتائج
            # ─────────────────────────────────────────────────────────
            if verdict == 'malicious':
                logger.warning(f"🚨 QR URL is MALICIOUS! Trust Score: {trust_score}")
            elif verdict == 'suspicious':
                logger.warning(f"⚠️ QR URL is SUSPICIOUS! Trust Score: {trust_score}")
            elif verdict == 'clean':
                logger.info(f"✅ QR URL is clean - Trust Score: {trust_score}")
            else:
                logger.warning(f"❓ QR URL verdict unknown - Trust Score: {trust_score}")
            
            logger.info(f"✅ QR URL scan completed | Verdict: {verdict}")
            return result
            
        except UnsafeTargetError:
            raise
        except Exception as e:
            logger.error(f"❌ Error scanning QR URL: {str(e)}")
            import traceback
            traceback.print_exc()
            
            return {
                "verdict": "unknown",
                "error": str(e),
                "source": "qr_analyzer"
            }
    
    # ================================================================
    # دالة مساعدة: فحص batch
    # ================================================================
    
    def scan_urls_batch(self, urls: list) -> list:
        """
        فحص مجموعة من روابط QR دفعة واحدة
        
        Args:
            urls: قائمة الروابط
        
        Returns:
            قائمة بالنتائج
        """
        results = []
        for url in urls:
            results.append(self.scan_url(url))
        return results