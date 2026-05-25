# services/tip_collector.py
# ================================================================
# TIP Collector — جمع IoCs من المصادر المفتوحة تلقائياً
#
# المصادر المدعومة:
#   - Abuse.ch URLhaus  (URLs خبيثة)
#   - Abuse.ch MalwareBazaar (hashes)
#   - Emerging Threats  (IPs)
#   - PhishTank         (phishing URLs)
#   - OpenPhish         (phishing URLs)
#   - Feodo Tracker     (botnet C2 IPs)
#   - MISP Community Feeds
# ================================================================

import requests
import json
import csv
import io
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger('services')


def _now():
    return datetime.now(timezone.utc)


# ── المصادر الافتراضية لتهيئة قاعدة البيانات ────────────────
DEFAULT_SOURCES = [
    {
        'name':           'Abuse.ch URLhaus - Active URLs',
        'url':            'https://urlhaus.abuse.ch/downloads/text/',
        'feed_type':      'url_list',
        'trust_score':    90,
        'fetch_interval': 3600,         # كل ساعة
        'notes':          'قائمة URLs الخبيثة النشطة من Abuse.ch',
    },
    {
        'name':           'Abuse.ch URLhaus - Recent URLs (CSV)',
        'url':            'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'feed_type':      'csv',
        'trust_score':    90,
        'fetch_interval': 3600,
        'notes':          'URLs خبيثة حديثة مع بيانات إضافية (CSV)',
    },
    {
        'name':           'Abuse.ch MalwareBazaar - SHA256',
        'url':            'https://bazaar.abuse.ch/export/txt/sha256/recent/',
        'feed_type':      'hash_list',
        'trust_score':    95,
        'fetch_interval': 7200,
        'notes':          'هاشات ملفات البرامج الضارة الحديثة',
    },
    {
        'name':           'Emerging Threats - Compromised IPs',
        'url':            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'feed_type':      'ip_list',
        'trust_score':    85,
        'fetch_interval': 86400,        # يومياً
        'notes':          'قائمة IPs المخترقة من Emerging Threats',
    },
    {
        'name':           'Feodo Tracker - Botnet C2 IPs',
        'url':            'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'feed_type':      'ip_list',
        'trust_score':    92,
        'fetch_interval': 3600,
        'notes':          'IPs خوادم C&C لبرامج الـ Botnet',
    },
    {
        'name':           'PhishTank - Verified Phishing',
        'url':            'https://data.phishtank.com/data/online-valid.json',
        'feed_type':      'json',
        'trust_score':    88,
        'fetch_interval': 3600,
        'notes':          'مواقع التصيد الاحتيالي المتحقق منها',
    },
    {
        'name':           'OpenPhish - Active Phishing URLs',
        'url':            'https://openphish.com/feed.txt',
        'feed_type':      'url_list',
        'trust_score':    82,
        'fetch_interval': 3600,
        'notes':          'URLs التصيد النشطة من OpenPhish',
    },
    {
        'name':           'MISP - CIRCL Feed',
        'url':            'https://www.circl.lu/doc/misp/feed-osint/',
        'feed_type':      'misp_feed',
        'trust_score':    88,
        'fetch_interval': 86400,
        'notes':          'بيانات تهديدات OSINT من مركز CIRCL',
    },
    {
        'name':           'Blocklist.de - All IPs',
        'url':            'https://lists.blocklist.de/lists/all.txt',
        'feed_type':      'ip_list',
        'trust_score':    75,
        'fetch_interval': 86400,
        'notes':          'IPs من الإبلاغات اليومية عن الهجمات',
    },
    {
        'name':           'C2 Intel Feeds - Domain List',
        'url':            'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithpaths.csv',
        'feed_type':      'csv',
        'trust_score':    80,
        'fetch_interval': 86400,
        'notes':          'نطاقات خوادم C2 من مشروع C2IntelFeeds',
    },
]


class TIPCollector:
    """
    جمع IoCs من المصادر المفتوحة وتخزينها في قاعدة البيانات.
    يعمل من Celery tasks أو مباشرة.
    """

    SEVERITY_MAP = {
        'critical': ['ransomware', 'cryptolocker', 'wiper', 'apt', 'zero-day'],
        'high':     ['malware', 'trojan', 'rat', 'stealer', 'c2', 'botnet', 'exploit'],
        'medium':   ['phishing', 'spam', 'scan', 'bruteforce', 'fraud'],
        'low':      ['suspicious', 'unknown', 'adware', 'pup'],
    }

    THREAT_KEYWORDS = {
        'malware':   ['malware', 'trojan', 'virus', 'worm', 'backdoor', 'rat'],
        'phishing':  ['phish', 'credential', 'login', 'banking'],
        'botnet':    ['botnet', 'c2', 'c&c', 'command', 'control', 'feodo', 'emotet'],
        'ransomware':['ransom', 'cryptolocker', 'locker'],
        'spam':      ['spam', 'bulk', 'mailer'],
        'scanner':   ['scan', 'probe', 'shodan'],
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'MyScanner-TIP/1.0 (security research)'

    # ── تهيئة المصادر الافتراضية ────────────────────────────
    def initialize_default_sources(self):
        """
        أضف المصادر الافتراضية لقاعدة البيانات إن لم تكن موجودة.
        استدعي هذه الدالة مرة واحدة عند تشغيل التطبيق.
        """
        from models import IoCSource
        from extensions import db

        added = 0
        for src_data in DEFAULT_SOURCES:
            exists = IoCSource.query.filter_by(name=src_data['name']).first()
            if not exists:
                source = IoCSource(**src_data)
                db.session.add(source)
                added += 1

        if added:
            db.session.commit()
            logger.info(f'[TIP] Initialized {added} default IoC sources')
        return added

    # ── جلب مصدر واحد ───────────────────────────────────────
    def fetch_source(self, source_id: int) -> dict:
        """
        جلب IoCs من مصدر واحد وتخزينها.
        يُستدعى من Celery task.
        يعود بإحصاءات العملية.
        """
        from models import IoCSource, TIPFeedLog
        from extensions import db

        source = IoCSource.query.get(source_id)
        if not source:
            return {'error': f'Source {source_id} not found'}

        # إنشاء سجل عملية الجلب
        feed_log = TIPFeedLog(source_id=source_id, status='running')
        db.session.add(feed_log)
        db.session.commit()

        logger.info(f'[TIP] Fetching source: {source.name}')

        try:
            stats = self._fetch_and_parse(source, feed_log)

            # تحديث المصدر
            source.last_fetched = _now()
            source.last_count   = stats['added'] + stats['updated']
            source.error_count  = 0

            # تحديث سجل العملية
            feed_log.ended_at     = _now()
            feed_log.status       = 'success'
            feed_log.added_count   = stats['added']
            feed_log.updated_count = stats['updated']
            feed_log.skipped_count = stats['skipped']

            db.session.commit()
            logger.info(f'[TIP] {source.name}: +{stats["added"]} new, ~{stats["updated"]} updated, {stats["skipped"]} skipped')
            return stats

        except Exception as e:
            source.error_count += 1
            feed_log.ended_at     = _now()
            feed_log.status       = 'failed'
            feed_log.error_message = str(e)
            db.session.commit()
            logger.error(f'[TIP] Failed fetching {source.name}: {e}')
            return {'error': str(e), 'source': source.name}

    # ── التوزيع حسب نوع الـ Feed ────────────────────────────
    def _fetch_and_parse(self, source, feed_log) -> dict:
        stats = {'added': 0, 'updated': 0, 'skipped': 0}

        resp = self.session.get(source.url, timeout=self.timeout)
        resp.raise_for_status()

        if source.feed_type == 'ip_list':
            iocs = self._parse_ip_list(resp.text, source)
        elif source.feed_type == 'domain_list':
            iocs = self._parse_domain_list(resp.text, source)
        elif source.feed_type == 'url_list':
            iocs = self._parse_url_list(resp.text, source)
        elif source.feed_type == 'hash_list':
            iocs = self._parse_hash_list(resp.text, source)
        elif source.feed_type == 'csv':
            iocs = self._parse_csv(resp.text, source)
        elif source.feed_type == 'json':
            iocs = self._parse_json(resp.json() if resp.headers.get('content-type','').startswith('application/json') else json.loads(resp.text), source)
        elif source.feed_type == 'misp_feed':
            iocs = self._parse_misp_feed(resp.text, source)
        else:
            iocs = []

        # تخزين دفعي
        for ioc_data in iocs:
            result = self._upsert_ioc(ioc_data, source)
            stats[result] += 1

        return stats

    # ── محللات الأنواع المختلفة ──────────────────────────────

    def _parse_ip_list(self, text: str, source) -> list:
        """قائمة IPs نصية — سطر واحد لكل IP"""
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            ip = line.split()[0]  # بعض القوائم تضع تعليق بعد الـ IP
            if self._is_valid_ip(ip):
                iocs.append({
                    'value':       ip,
                    'ioc_type':    'ip',
                    'severity':    'high',
                    'threat_type': self._detect_threat_type(source.name + ' ' + source.notes),
                    'description': f'Reported by {source.name}',
                    'tags':        self._generate_tags(source.name, 'ip'),
                })
        return iocs

    def _parse_domain_list(self, text: str, source) -> list:
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            domain = line.split()[0].strip('.')
            if '.' in domain and len(domain) > 3:
                iocs.append({
                    'value':       domain.lower(),
                    'ioc_type':    'domain',
                    'severity':    'high',
                    'threat_type': self._detect_threat_type(source.name),
                    'description': f'Reported by {source.name}',
                    'tags':        self._generate_tags(source.name, 'domain'),
                })
        return iocs

    def _parse_url_list(self, text: str, source) -> list:
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('http://') or line.startswith('https://'):
                iocs.append({
                    'value':       line[:512],
                    'ioc_type':    'url',
                    'severity':    self._severity_from_source(source.name),
                    'threat_type': self._detect_threat_type(source.name),
                    'description': f'Reported by {source.name}',
                    'tags':        self._generate_tags(source.name, 'url'),
                })
        return iocs

    def _parse_hash_list(self, text: str, source) -> list:
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            h = line.split()[0]
            hash_type = self._detect_hash_type(h)
            if hash_type:
                iocs.append({
                    'value':       h.lower(),
                    'ioc_type':    hash_type,
                    'severity':    'high',
                    'threat_type': 'malware',
                    'description': f'Malware hash from {source.name}',
                    'tags':        'malware,hash',
                })
        return iocs

    def _parse_csv(self, text: str, source) -> list:
        """
        CSV عام — يحاول اكتشاف الأعمدة تلقائياً.
        يدعم: URLhaus CSV, C2IntelFeeds CSV
        """
        iocs = []
        try:
            reader = csv.DictReader(io.StringIO(text), skipinitialspace=True)
            for row in reader:
                # تجاهل أسطر التعليق
                first_val = list(row.values())[0] if row else ''
                if str(first_val).startswith('#'):
                    continue

                # اكتشاف نوع الـ IoC من أسماء الأعمدة
                ioc = self._extract_ioc_from_csv_row(row, source)
                if ioc:
                    iocs.append(ioc)
        except Exception as e:
            logger.warning(f'[TIP] CSV parse error for {source.name}: {e}')
        return iocs

    def _extract_ioc_from_csv_row(self, row: dict, source) -> Optional[dict]:
        """اكتشاف وتحويل صف CSV لـ IoC"""
        lower_keys = {k.lower(): v for k, v in row.items() if k}

        # URL
        for col in ['url', 'url_full', 'uri']:
            val = lower_keys.get(col, '')
            if val and (val.startswith('http://') or val.startswith('https://')):
                threat = lower_keys.get('threat', '') or lower_keys.get('tags', '')
                return {
                    'value':       val[:512],
                    'ioc_type':    'url',
                    'severity':    self._severity_from_keywords(str(threat)),
                    'threat_type': self._detect_threat_type(str(threat)),
                    'description': str(threat),
                    'tags':        self._generate_tags(source.name, 'url') + ',' + str(threat)[:100],
                }
        # IP
        for col in ['ip', 'ip_address', 'dst_ip', 'src_ip']:
            val = lower_keys.get(col, '')
            if val and self._is_valid_ip(val):
                return {
                    'value':       val,
                    'ioc_type':    'ip',
                    'severity':    'high',
                    'threat_type': self._detect_threat_type(source.name),
                    'description': f'From {source.name}',
                    'tags':        self._generate_tags(source.name, 'ip'),
                }
        # Domain
        for col in ['domain', 'host', 'hostname', 'fqdn']:
            val = lower_keys.get(col, '').strip()
            if val and '.' in val:
                return {
                    'value':       val.lower()[:253],
                    'ioc_type':    'domain',
                    'severity':    'medium',
                    'threat_type': self._detect_threat_type(source.name),
                    'description': f'From {source.name}',
                    'tags':        self._generate_tags(source.name, 'domain'),
                }
        return None

    def _parse_json(self, data, source) -> list:
        """JSON feeds — يدعم PhishTank وغيره"""
        iocs = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                # PhishTank format
                url = item.get('url') or item.get('phish_url') or ''
                if url:
                    iocs.append({
                        'value':       url[:512],
                        'ioc_type':    'url',
                        'severity':    'high',
                        'threat_type': 'phishing',
                        'description': item.get('details', [{}])[0].get('brand', '') if isinstance(item.get('details'), list) else '',
                        'tags':        'phishing,verified',
                        'raw_data':    json.dumps(item)[:1000],
                    })
        return iocs

    def _parse_misp_feed(self, text: str, source) -> list:
        """MISP feed manifest — يجلب أسماء الملفات ثم يعالجها"""
        iocs = []
        try:
            manifest = json.loads(text) if text.strip().startswith('{') else {}
            # معالجة بسيطة لصفحة المانيفست — نستخرج ما يمكن
            for event_uuid, event_data in list(manifest.items())[:50]:
                if isinstance(event_data, dict):
                    info = event_data.get('info', '')
                    iocs.extend(self._extract_iocs_from_text(info, source))
        except Exception as e:
            logger.warning(f'[TIP] MISP feed parse error: {e}')
        return iocs

    def _extract_iocs_from_text(self, text: str, source) -> list:
        """استخراج IPs ونطاقات من نص حر"""
        import re
        iocs = []
        ip_pattern     = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

        for ip in re.findall(ip_pattern, text):
            if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                iocs.append({'value': ip, 'ioc_type': 'ip', 'severity': 'medium',
                             'threat_type': 'suspicious', 'tags': 'extracted', 'description': ''})
        return iocs

    # ── تخزين IoC في قاعدة البيانات ─────────────────────────
    def _upsert_ioc(self, ioc_data: dict, source) -> str:
        """
        أضف IoC جديدة أو حدّث الموجودة.
        يعود بـ 'added' | 'updated' | 'skipped'
        """
        from models import IoCEntry
        from extensions import db

        value    = ioc_data.get('value', '').strip()
        ioc_type = ioc_data.get('ioc_type', '')

        if not value or not ioc_type:
            return 'skipped'

        existing = IoCEntry.query.filter_by(value=value, ioc_type=ioc_type).first()

        if existing:
            # تحديث الموجود
            existing.last_seen    = _now()
            existing.source_count = (existing.source_count or 1) + 1
            existing.is_active    = True
            # رفع مستوى الخطورة إن كان الجديد أعلى
            if self._severity_rank(ioc_data.get('severity', 'low')) > self._severity_rank(existing.severity):
                existing.severity = ioc_data['severity']
            existing.update_confidence()
            return 'updated'
        else:
            # إضافة جديدة
            expires_at = self._default_expiry(ioc_type)
            entry = IoCEntry(
                value       = value,
                ioc_type    = ioc_type,
                severity    = ioc_data.get('severity', 'medium'),
                threat_type = ioc_data.get('threat_type'),
                tags        = ioc_data.get('tags', ''),
                description = ioc_data.get('description', '')[:500] if ioc_data.get('description') else '',
                source_id   = source.id,
                expires_at  = expires_at,
                raw_data    = ioc_data.get('raw_data', '')[:2000] if ioc_data.get('raw_data') else None,
                confidence  = source.trust_score,
                source_count= 1,
            )
            db.session.add(entry)
            try:
                db.session.flush()  # للكشف عن الـ unique constraint مبكراً
            except Exception:
                db.session.rollback()
                return 'skipped'
            return 'added'

    # ── دوال مساعدة ─────────────────────────────────────────

    def _is_valid_ip(self, ip: str) -> bool:
        import re
        pattern = r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
        return bool(re.match(pattern, ip))

    def _is_private_ip(self, ip: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    def _detect_hash_type(self, h: str) -> Optional[str]:
        h = h.strip()
        if len(h) == 32  and all(c in '0123456789abcdefABCDEF' for c in h): return 'md5'
        if len(h) == 40  and all(c in '0123456789abcdefABCDEF' for c in h): return 'sha1'
        if len(h) == 64  and all(c in '0123456789abcdefABCDEF' for c in h): return 'sha256'
        return None

    def _detect_threat_type(self, text: str) -> str:
        text_lower = text.lower()
        for threat, keywords in self.THREAT_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return threat
        return 'suspicious'

    def _severity_from_source(self, source_name: str) -> str:
        name_lower = source_name.lower()
        if any(k in name_lower for k in ['ransom', 'apt', 'critical']): return 'critical'
        if any(k in name_lower for k in ['malware', 'c2', 'botnet', 'feodo']): return 'high'
        if any(k in name_lower for k in ['phish', 'fraud']): return 'medium'
        return 'medium'

    def _severity_from_keywords(self, text: str) -> str:
        text_lower = text.lower()
        for severity, keywords in self.SEVERITY_MAP.items():
            if any(kw in text_lower for kw in keywords):
                return severity
        return 'medium'

    def _generate_tags(self, source_name: str, ioc_type: str) -> str:
        tags = [ioc_type]
        name_lower = source_name.lower()
        if 'abuse' in name_lower:  tags.append('abuse.ch')
        if 'phish' in name_lower:  tags.append('phishing')
        if 'malware' in name_lower or 'bazaar' in name_lower: tags.append('malware')
        if 'feodo' in name_lower or 'botnet' in name_lower: tags.append('botnet')
        if 'emerging' in name_lower: tags.append('emerging-threats')
        if 'misp' in name_lower: tags.append('misp')
        return ','.join(tags)

    def _severity_rank(self, severity: str) -> int:
        return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(severity, 0)

    def _default_expiry(self, ioc_type: str) -> datetime:
        """
        مدة انتهاء صلاحية IoC حسب النوع:
        - IP: 30 يوم (IPs تتغير أصحابها)
        - URL: 14 يوم
        - Domain: 90 يوم
        - Hash: لا تنتهي (الـ hash ثابت)
        """
        now = _now()
        if ioc_type == 'ip':       return now + timedelta(days=30)
        if ioc_type == 'url':      return now + timedelta(days=14)
        if ioc_type == 'domain':   return now + timedelta(days=90)
        if ioc_type == 'email':    return now + timedelta(days=30)
        return None   # hashes لا تنتهي

    # ── جلب كل المصادر المستحقة ──────────────────────────────
    def fetch_all_due(self) -> dict:
        """
        يُستدعى من Celery Beat.
        يجلب كل المصادر التي حان وقت تحديثها.
        """
        from models import IoCSource
        stats = {'sources_fetched': 0, 'total_added': 0, 'total_updated': 0, 'errors': 0}

        sources = IoCSource.query.filter_by(is_active=True).all()
        for source in sources:
            if source.is_due:
                result = self.fetch_source(source.id)
                if 'error' in result:
                    stats['errors'] += 1
                else:
                    stats['sources_fetched'] += 1
                    stats['total_added']   += result.get('added', 0)
                    stats['total_updated'] += result.get('updated', 0)

        logger.info(f'[TIP] Fetch all complete: {stats}')
        return stats

    # ── تنظيف IoCs المنتهية ───────────────────────────────────
    def cleanup_expired(self) -> int:
        """
        يُعطّل IoCs المنتهية الصلاحية.
        يُستدعى من Celery Beat يومياً.
        """
        from models import IoCEntry
        from extensions import db

        expired = IoCEntry.query.filter(
            IoCEntry.expires_at <= _now(),
            IoCEntry.is_active == True
        ).all()

        for ioc in expired:
            ioc.is_active = False

        if expired:
            db.session.commit()
            logger.info(f'[TIP] Deactivated {len(expired)} expired IoCs')

        return len(expired)