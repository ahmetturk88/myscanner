# services/file_threat_intel.py
# =================================================================
# FILE THREAT INTEL - توحيد مصادر فحص الملفات
# يدمج: MalwareBazaar + FileDeepAnalyzer + (لاحقاً ClamAV)
# بديل احترافي لـ VirusTotal
# =================================================================

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from services.malwarebazaar_client import get_malwarebazaar_client
from services.file_deep_analyzer import FileDeepAnalyzer

logger = logging.getLogger(__name__)


class FileThreatIntel:
    """
    خدمة توحيد مصادر فحص الملفات
    
    المصادر:
    1. FileDeepAnalyzer (تحليل محلي عميق)
    2. MalwareBazaar (فحص hash عبر abuse.ch)
    3. (مستقبلاً) ClamAV (ماسح فيروسات محلي)
    
    يعطي:
    - verdict موحد (safe/suspicious/malicious/high_risk)
    - security_score (0-100)
    - threats (قائمة التهديدات)
    - details (تفاصيل كل مصدر)
    """
    
    def __init__(self, use_exiftool: bool = True):
        """
        تهيئة الخدمة
        
        Args:
            use_exiftool: استخدام exiftool في التحليل المحلي
        """
        self.local_analyzer = FileDeepAnalyzer(use_exiftool=use_exiftool)
        self.mb_client = None
        
        # تهيئة MalwareBazaar (Lazy)
        try:
            self.mb_client = get_malwarebazaar_client()
        except Exception as e:
            logger.warning(f"⚠️ MalwareBazaar not available: {e}")
        
        logger.info("✅ FileThreatIntel initialized")

    # ================================================================
    # الدالة الرئيسية: فحص شامل
    # ================================================================
    
    def comprehensive_file_scan(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        فحص شامل للملف عبر كل المصادر المتاحة
        
        Args:
            file_content: محتوى الملف (bytes)
            filename: اسم الملف
        
        Returns:
            Dict يحتوي على نتيجة موحدة
        """
        logger.info(f"🔍 Starting comprehensive file scan: {filename} ({len(file_content)} bytes)")
        
        # ─────────────────────────────────────────────────────────────
        # 1. التحليل المحلي العميق
        # ─────────────────────────────────────────────────────────────
        local_result = self._run_local_analysis(file_content, filename)
        
        # ─────────────────────────────────────────────────────────────
        # 2. فحص MalwareBazaar (عبر hash)
        # ─────────────────────────────────────────────────────────────
        mb_result = local_result.get('hash_reputation',{}).get('provider') or self._run_malwarebazaar_scan(file_content, filename)
        
        # ─────────────────────────────────────────────────────────────
        # 3. دمج النتائج
        # ─────────────────────────────────────────────────────────────
        merged = self._merge_results(local_result, mb_result, filename, file_content)
        
        logger.info(f"✅ File scan completed: {filename} | "
                   f"Verdict: {merged['verdict']} | "
                   f"Score: {merged['security_score']}/100")
        
        return merged

    # ================================================================
    # 1. التحليل المحلي
    # ================================================================
    
    def _run_local_analysis(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تشغيل التحليل المحلي العميق"""
        try:
            result = self.local_analyzer.comprehensive_analysis(file_content, filename)
            logger.info(f"✅ Local analysis completed for {filename}")
            return result
        except Exception as e:
            logger.error(f"❌ Local analysis failed: {e}")
            return {
                'error': 'Local file evidence unavailable',
                'security_score': None,
                'verdict': 'unknown'
            }

    # ================================================================
    # 2. فحص MalwareBazaar
    # ================================================================
    
    def _run_malwarebazaar_scan(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تشغيل فحص MalwareBazaar"""
        if self.mb_client is None:
            return {
                'source': 'malwarebazaar',
                'error': 'MalwareBazaar client not available',
                'is_malicious': None,
                'status': 'unavailable',
                'found': False
            }
        
        try:
            result = self.mb_client.scan_file(file_content, filename)
            logger.info(f"✅ MalwareBazaar scan completed for {filename} | "
                       f"Malicious: {result['is_malicious']}")
            return result
        except Exception as e:
            logger.error(f"❌ MalwareBazaar scan failed: {e}")
            return {
                'source': 'malwarebazaar',
                'error': 'Reputation lookup unavailable',
                'is_malicious': None,
                'status': 'unavailable',
                'found': False
            }

    # ================================================================
    # 3. دمج النتائج
    # ================================================================
    
    def _merge_results(self, local_result: Dict, mb_result: Dict, 
                       filename: str, file_content: bytes) -> Dict[str, Any]:
        """
        دمج نتائج المصادر في نتيجة موحدة
        """
        matched = mb_result.get('status') == 'matched' and mb_result.get('is_malicious') is True
        negative = mb_result.get('status') == 'not_found' and mb_result.get('is_malicious') is False
        # ─────────────────────────────────────────────────────────────
        # security_score (0-100)
        # ─────────────────────────────────────────────────────────────
        # نبدأ من الدرجة المحلية
        security_score = local_result.get('security_score')
        score_known = type(security_score) in (int, float) and 0 <= security_score <= 100
        security_score = security_score if score_known else None
        
        # إذا كان الملف خبيثاً في MalwareBazaar، نخفض الدرجة بشكل كبير
        if matched:
            security_score = 0
        elif mb_result.get('error'):
            # إذا فشل MalwareBazaar، لا نغير الدرجة
            pass
        
        # ─────────────────────────────────────────────────────────────
        # verdict النهائي
        # ─────────────────────────────────────────────────────────────
        if matched:
            verdict = 'malicious'
            verdict_icon = '🚨'
        elif not score_known:
            verdict = 'unknown'
            verdict_icon = '⚠️'
        elif security_score >= 80:
            verdict = 'safe'
            verdict_icon = '✅'
        elif security_score >= 60:
            verdict = 'suspicious'
            verdict_icon = '⚠️'
        elif security_score >= 30:
            verdict = 'high_risk'
            verdict_icon = '🔴'
        else:
            verdict = 'malicious'
            verdict_icon = '🚨'
        
        missing_checks=list(local_result.get('missing_checks',[]))
        if local_result.get('error') or not score_known:missing_checks.append('Local file analysis unavailable')
        if not (matched or negative):missing_checks.append('MalwareBazaar reputation unavailable')
        if not matched and local_result.get('verdict') in ('malicious','high_risk','suspicious'):
            verdict=local_result['verdict']
        elif not matched and (local_result.get('error') or verdict=='safe'):
            verdict='unknown' if missing_checks else 'not_found'
            verdict_icon='⚠️' if missing_checks else 'ℹ️'
        # ─────────────────────────────────────────────────────────────
        # قائمة التهديدات الموحدة
        # ─────────────────────────────────────────────────────────────
        threats = []
        
        # من MalwareBazaar
        if matched:
            threats.append({
                'source': 'malwarebazaar',
                'signature': mb_result.get('signature'),
                'file_type': mb_result.get('file_type'),
                'tags': mb_result.get('tags', []),
                'first_seen': mb_result.get('first_seen'),
                'severity': 'critical'
            })
        
        # من التحليل المحلي
        local_threats = local_result.get('threats', [])
        if isinstance(local_threats, list):
            threats.extend(local_threats)
        
        # ─────────────────────────────────────────────────────────────
        # التوصيات
        # ─────────────────────────────────────────────────────────────
        recommendations = []
        
        if matched:
            recommendations.append(
                f"🚨 CRITICAL: File is a known malware "
                f"({mb_result.get('signature', 'Unknown family')}). "
                f"DO NOT execute!"
            )
            recommendations.append(
                "📁 Quarantine this file immediately."
            )
            recommendations.append(
                "🔍 Scan your system for other infected files."
            )
        elif verdict == 'safe':
            recommendations.append(
                "✅ File appears safe. Still, always be cautious "
                "when executing files from untrusted sources."
            )
        else:
            recommendations.append(
                f"⚠️ File risk level: {verdict.upper()}. "
                f"Consider scanning with additional tools."
            )
        
        # إضافة توصيات التحليل المحلي
        local_recs = local_result.get('recommendations', [])
        if isinstance(local_recs, list):
            recommendations.extend(local_recs[:3])
        
        # ─────────────────────────────────────────────────────────────
        # النتيجة النهائية
        # ─────────────────────────────────────────────────────────────
        report = {
            **{key:local_result[key] for key in ('file_size_mb','file_type','hashes','metadata','exiftool_data','iocs','yara','hash_reputation','warnings','benign_reasons','is_likely_benign') if key in local_result},
            'malwarebazaar': mb_result,
            # معلومات أساسية
            'filename': filename,
            'file_size': len(file_content),
            'file_hash_sha256': mb_result.get('hash') or self._calculate_sha256(file_content),
            
            # الحكم
            'verdict': verdict,
            'coverage_status': 'partial' if missing_checks else 'completed',
            'missing_checks': list(dict.fromkeys(missing_checks)),
            'scope': 'Available static observations and a hash dataset; no guarantee of safety.',
            'verdict_icon': verdict_icon,
            'security_score': security_score,
            
            # التهديدات
            'threats': threats,
            'threats_count': len(threats),
            
            # التوصيات
            'recommendations': recommendations[:8],
            
            # تفاصيل المصادر (للمطورين)
            'sources': {
                'local_analysis': local_result,
                'malwarebazaar': mb_result
            },
            
            # معلومات إضافية
            'scan_sources': self._get_active_sources(),
            'scanned_at': datetime.now(timezone.utc).isoformat()
        }

        from services.file_assessment import assess_file
        report['assessment'] = assess_file(report)
        return report

    # ================================================================
    # دوال مساعدة
    # ================================================================
    
    @staticmethod
    def _calculate_sha256(file_content: bytes) -> str:
        """حساب SHA256 للملف"""
        import hashlib
        return hashlib.sha256(file_content).hexdigest()
    
    def _get_active_sources(self) -> list:
        """إرجاع قائمة المصادر النشطة"""
        sources = ['local_deep_analysis']
        if self.mb_client is not None:
            sources.append('malwarebazaar')
        return sources


# ================================================================
# نسخة وحيدة (Singleton)
# ================================================================

_fti_instance = None


def get_file_threat_intel() -> FileThreatIntel:
    """الحصول على نسخة وحيدة من FileThreatIntel"""
    global _fti_instance
    if _fti_instance is None:
        _fti_instance = FileThreatIntel()
    return _fti_instance