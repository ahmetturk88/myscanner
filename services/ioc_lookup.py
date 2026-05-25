# services/ioc_lookup.py
# ================================================================
# IoC Lookup — البحث السريع في قاعدة بيانات IoCs
#
# يُستخدم من:
#   - URL Analyzer   → للتحقق من URLs والنطاقات
#   - IP Analyzer    → للتحقق من IPs
#   - Domain Lookup  → للتحقق من النطاقات
#   - QR Scanner     → للتحقق من URLs
#   - Email Checker  → للتحقق من نطاقات البريد
#   - File Scanner   → للتحقق من الهاشات
# ================================================================

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger('services')


def _now():
    return datetime.now(timezone.utc)


class IoCLookup:
    """
    واجهة موحدة للبحث في IoCs.
    مُحسّنة للسرعة مع دعم Redis cache.
    """

    # درجة الخطورة بالأرقام للمقارنة
    SEVERITY_WEIGHTS = {
        'critical': 100,
        'high':     75,
        'medium':   50,
        'low':      25,
        'info':     10,
        'clean':    0,
    }

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.cache_ttl = 300   # 5 دقائق cache

    # ── البحث الرئيسي ────────────────────────────────────────

    def lookup(self, value: str, ioc_type: str = None, context: str = 'manual',
               user_id: int = None) -> dict:
        """
        البحث عن قيمة واحدة في قاعدة IoCs.

        المعاملات:
            value    : القيمة للبحث (IP / domain / URL / hash)
            ioc_type : نوع البحث (اختياري — يُفسَّر تلقائياً إن لم يُعطَ)
            context  : من أين جاء الطلب ('url_analyzer' | 'ip_check' | ...)
            user_id  : لتسجيل الـ match

        يعود بـ:
            {
                'found': bool,
                'iocs': [...],        ← IoCs المطابقة
                'highest_severity': str,
                'max_confidence': int,
                'threat_types': [...],
                'summary': str,
                'tip_score': int,     ← 0-100 — يُضاف لدرجة الأمان
            }
        """
        value = value.strip().lower()
        if not value:
            return self._empty_result()

        # اكتشاف النوع تلقائياً إن لم يُعطَ
        if not ioc_type:
            ioc_type = self._detect_type(value)

        # التحقق من الـ Cache أولاً
        cache_key = f'ioc:{ioc_type}:{value[:200]}'
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        # البحث في قاعدة البيانات
        result = self._db_lookup(value, ioc_type)

        # تسجيل المطابقات
        if result['found'] and user_id:
            self._log_matches(result['iocs'], value, ioc_type, context, user_id)

        # تخزين في الـ Cache
        self._cache_set(cache_key, result)

        return result

    def lookup_url(self, url: str, context: str = 'url_analyzer', user_id: int = None) -> dict:
        """
        بحث شامل عن URL: يفحص الـ URL كاملاً + النطاق + IP.
        يُستدعى من url_analyzer و qr_scanner.
        """
        from urllib.parse import urlparse
        import socket

        results = []
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]   # بدون port

        # 1. فحص URL الكامل
        url_result = self.lookup(url, 'url', context, user_id)
        url_result['checked_value'] = url
        url_result['checked_type']  = 'url'
        results.append(url_result)

        # 2. فحص النطاق
        if domain:
            domain_result = self.lookup(domain, 'domain', context, user_id)
            domain_result['checked_value'] = domain
            domain_result['checked_type']  = 'domain'
            results.append(domain_result)

        # 3. فحص IP (حل الـ domain)
        try:
            ip = socket.gethostbyname(domain)
            ip_result = self.lookup(ip, 'ip', context, user_id)
            ip_result['checked_value'] = ip
            ip_result['checked_type']  = 'ip'
            results.append(ip_result)
        except Exception:
            pass

        return self._merge_results(results)

    def lookup_ip(self, ip: str, context: str = 'ip_check', user_id: int = None) -> dict:
        """بحث مباشر عن IP"""
        return self.lookup(ip, 'ip', context, user_id)

    def lookup_domain(self, domain: str, context: str = 'domain_lookup', user_id: int = None) -> dict:
        """بحث مباشر عن نطاق"""
        return self.lookup(domain.lower(), 'domain', context, user_id)

    def lookup_hash(self, file_hash: str, context: str = 'file_scan', user_id: int = None) -> dict:
        """بحث عن hash ملف (md5/sha1/sha256)"""
        hash_type = self._detect_hash_type(file_hash)
        return self.lookup(file_hash.lower(), hash_type or 'sha256', context, user_id)

    def bulk_lookup(self, values: list, context: str = 'bulk', user_id: int = None) -> list:
        """بحث دفعي — لفحص عدة قيم دفعة واحدة"""
        return [self.lookup(v, context=context, user_id=user_id) for v in values[:100]]

    # ── البحث في قاعدة البيانات ──────────────────────────────

    def _db_lookup(self, value: str, ioc_type: str) -> dict:
        from models import IoCEntry

        # بناء الاستعلام
        query = IoCEntry.query.filter(
            IoCEntry.is_active == True,
            IoCEntry.value     == value,
        )

        # تصفية بالنوع إن كان محدداً ومنطقياً
        if ioc_type in ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'):
            query = query.filter(IoCEntry.ioc_type == ioc_type)

        iocs = query.order_by(IoCEntry.confidence.desc()).limit(10).all()

        # تصفية المنتهية
        active_iocs = [ioc for ioc in iocs if not ioc.is_expired]

        if not active_iocs:
            return self._empty_result()

        # تجميع النتائج
        ioc_dicts = [ioc.to_dict() for ioc in active_iocs]

        highest_severity = max(active_iocs, key=lambda x: self.SEVERITY_WEIGHTS.get(x.severity, 0)).severity
        max_confidence   = max(ioc.confidence for ioc in active_iocs)
        threat_types     = list(set(i.threat_type for i in active_iocs if i.threat_type))
        all_tags         = []
        for ioc in active_iocs:
            all_tags.extend(ioc.tags_list)
        tags = list(set(all_tags))

        tip_score = self._calculate_tip_score(active_iocs)
        summary   = self._build_summary(active_iocs, highest_severity)

        return {
            'found':            True,
            'iocs':             ioc_dicts,
            'count':            len(active_iocs),
            'highest_severity': highest_severity,
            'max_confidence':   max_confidence,
            'threat_types':     threat_types,
            'tags':             tags,
            'summary':          summary,
            'tip_score':        tip_score,
        }

    # ── دمج نتائج متعددة (للـ URL الشامل) ───────────────────

    def _merge_results(self, results: list) -> dict:
        """دمج نتائج البحث عن URL + domain + IP"""
        found_results = [r for r in results if r.get('found')]

        if not found_results:
            return {
                **self._empty_result(),
                'checks': results,
                'url_analysis': True,
            }

        all_iocs        = []
        all_threats     = []
        all_tags        = []
        max_tip_score   = 0
        highest_sev_rank = 0
        highest_sev     = 'clean'

        for r in found_results:
            all_iocs.extend(r.get('iocs', []))
            all_threats.extend(r.get('threat_types', []))
            all_tags.extend(r.get('tags', []))
            if r.get('tip_score', 0) > max_tip_score:
                max_tip_score = r['tip_score']
            sev_rank = self.SEVERITY_WEIGHTS.get(r.get('highest_severity', 'clean'), 0)
            if sev_rank > highest_sev_rank:
                highest_sev_rank = sev_rank
                highest_sev = r['highest_severity']

        return {
            'found':            True,
            'iocs':             all_iocs[:20],
            'count':            len(all_iocs),
            'highest_severity': highest_sev,
            'max_confidence':   max(r.get('max_confidence', 0) for r in found_results),
            'threat_types':     list(set(all_threats)),
            'tags':             list(set(all_tags)),
            'summary':          f'Found {len(all_iocs)} IoC matches across URL, domain, and IP checks',
            'tip_score':        max_tip_score,
            'checks':           results,
            'url_analysis':     True,
        }

    # ── حساب درجة الخطر (tip_score) ─────────────────────────

    def _calculate_tip_score(self, iocs: list) -> int:
        """
        حساب درجة خطر مجمّعة من 0 إلى 100.
        تُطرح من security_score في المحللات الأخرى.
        """
        if not iocs:
            return 0

        base = max(self.SEVERITY_WEIGHTS.get(ioc.severity, 0) for ioc in iocs)

        # مكافأة تعدد المصادر
        max_source_count = max(ioc.source_count or 1 for ioc in iocs)
        multi_bonus = min((max_source_count - 1) * 5, 20)

        # مكافأة الثقة العالية
        max_conf = max(ioc.confidence for ioc in iocs)
        conf_bonus = (max_conf - 50) // 10 if max_conf > 50 else 0

        return min(100, base + multi_bonus + conf_bonus)

    # ── إنشاء ملخص قابل للقراءة ──────────────────────────────

    def _build_summary(self, iocs: list, severity: str) -> str:
        count   = len(iocs)
        threats = list(set(i.threat_type for i in iocs if i.threat_type))
        sources = list(set(i.source.name if i.source else 'unknown' for i in iocs))[:3]

        threat_str = ', '.join(threats[:3]) if threats else 'suspicious activity'
        source_str = ', '.join(sources)

        return (f'Found in {count} IoC {"record" if count == 1 else "records"} — '
                f'{threat_str} — severity: {severity} — '
                f'sources: {source_str}')

    # ── تسجيل المطابقات ──────────────────────────────────────

    def _log_matches(self, ioc_dicts: list, target: str, ioc_type: str,
                     context: str, user_id: int):
        try:
            from models import IoCMatch, IoCEntry
            from extensions import db

            for ioc_dict in ioc_dicts[:5]:  # سجّل أول 5 فقط
                match = IoCMatch(
                    ioc_id    = ioc_dict.get('id'),
                    ioc_value = ioc_dict.get('value', '')[:512],
                    ioc_type  = ioc_dict.get('type', ioc_type),
                    severity  = ioc_dict.get('severity', 'medium'),
                    context   = context,
                    target    = target[:512],
                    user_id   = user_id,
                )
                db.session.add(match)
            db.session.commit()
        except Exception as e:
            logger.warning(f'[TIP] Failed to log IoC match: {e}')

    # ── Cache helpers ─────────────────────────────────────────

    def _cache_get(self, key: str):
        if not self.redis:
            return None
        try:
            import json
            val = self.redis.get(key)
            return json.loads(val) if val else None
        except Exception:
            return None

    def _cache_set(self, key: str, value: dict):
        if not self.redis:
            return
        try:
            import json
            self.redis.setex(key, self.cache_ttl, json.dumps(value))
        except Exception:
            pass

    # ── دوال مساعدة ──────────────────────────────────────────

    def _detect_type(self, value: str) -> str:
        """اكتشاف نوع الـ IoC من شكل القيمة"""
        import re
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', value):    return 'ip'
        if value.startswith(('http://', 'https://')):          return 'url'
        if re.match(r'^[0-9a-f]{64}$', value):                return 'sha256'
        if re.match(r'^[0-9a-f]{40}$', value):                return 'sha1'
        if re.match(r'^[0-9a-f]{32}$', value):                return 'md5'
        if '@' in value:                                       return 'email'
        if '.' in value:                                       return 'domain'
        return 'unknown'

    def _detect_hash_type(self, h: str) -> Optional[str]:
        h = h.strip().lower()
        if len(h) == 64: return 'sha256'
        if len(h) == 40: return 'sha1'
        if len(h) == 32: return 'md5'
        return None

    def _empty_result(self) -> dict:
        return {
            'found':            False,
            'iocs':             [],
            'count':            0,
            'highest_severity': 'clean',
            'max_confidence':   0,
            'threat_types':     [],
            'tags':             [],
            'summary':          'No IoC matches found — appears clean',
            'tip_score':        0,
        }

    # ── إحصاءات TIP ───────────────────────────────────────────

    def get_statistics(self) -> dict:
        """إحصاءات عامة عن قاعدة IoCs"""
        try:
            from models import IoCEntry, IoCSource, IoCMatch
            total         = IoCEntry.query.filter_by(is_active=True).count()
            by_type       = {}
            by_severity   = {}
            for ioc_type in ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256'):
                by_type[ioc_type] = IoCEntry.query.filter_by(
                    ioc_type=ioc_type, is_active=True).count()
            for sev in ('critical', 'high', 'medium', 'low'):
                by_severity[sev] = IoCEntry.query.filter_by(
                    severity=sev, is_active=True).count()
            sources       = IoCSource.query.filter_by(is_active=True).count()
            total_matches = IoCMatch.query.count()
            return {
                'total_iocs':     total,
                'by_type':        by_type,
                'by_severity':    by_severity,
                'active_sources': sources,
                'total_matches':  total_matches,
            }
        except Exception as e:
            logger.error(f'[TIP] Stats error: {e}')
            return {}