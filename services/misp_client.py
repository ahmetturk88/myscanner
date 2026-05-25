# services/misp_client.py
# ================================================================
# MISP Client — التكامل مع منصة MISP
#
# يدعم:
#   - Pull: استيراد Events وAttributes من MISP
#   - Push: تصدير IoCs المكتشفة إلى MISP
#   - Sync: مزامنة دورية عبر Celery
#
# إعداد متغيرات البيئة المطلوبة:
#   MISP_URL     = https://your-misp-instance.com
#   MISP_API_KEY = your-api-key-here
#   MISP_VERIFY_SSL = true  (اختياري)
# ================================================================

import requests
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict

logger = logging.getLogger('services')


def _now():
    return datetime.now(timezone.utc)


class MISPClient:
    """
    عميل للتواصل مع منصة MISP.
    يعمل بدون مكتبة PyMISP لتجنب التبعيات الإضافية.
    يستخدم REST API مباشرة.
    """

    # خريطة تحويل أنواع MISP لأنواع IoC الداخلية
    MISP_TO_IOC_TYPE = {
        'ip-src':        'ip',
        'ip-dst':        'ip',
        'domain':        'domain',
        'hostname':      'domain',
        'url':           'url',
        'md5':           'md5',
        'sha1':          'sha1',
        'sha256':        'sha256',
        'email-src':     'email',
        'email-dst':     'email',
        'domain|ip':     'domain',  # سنعالج الـ IP بشكل منفصل
    }

    # خريطة أنواع IoC الداخلية إلى أنواع MISP
    IOC_TO_MISP_TYPE = {
        'ip':     'ip-dst',
        'domain': 'domain',
        'url':    'url',
        'md5':    'md5',
        'sha1':   'sha1',
        'sha256': 'sha256',
        'email':  'email-src',
    }

    # خريطة درجات الخطورة
    MISP_THREAT_LEVELS = {
        1: 'critical',   # High threat
        2: 'high',       # Medium threat
        3: 'medium',     # Low threat
        4: 'low',        # Undefined
    }

    def __init__(self, misp_url: str = None, api_key: str = None, verify_ssl: bool = True):
        self.misp_url  = (misp_url or os.getenv('MISP_URL', '')).rstrip('/')
        self.api_key   = api_key or os.getenv('MISP_API_KEY', '')
        self.verify_ssl = verify_ssl if verify_ssl is not None else os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'

        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.api_key,
            'Accept':        'application/json',
            'Content-Type':  'application/json',
        })

    @property
    def is_configured(self) -> bool:
        return bool(self.misp_url and self.api_key)

    # ── اتصال وفحص ───────────────────────────────────────────

    def test_connection(self) -> dict:
        """اختبار الاتصال بـ MISP"""
        if not self.is_configured:
            return {'success': False, 'error': 'MISP_URL or MISP_API_KEY not configured'}
        try:
            resp = self._get('/servers/getPyMISPVersion.json')
            version = resp.get('version', 'unknown')
            logger.info(f'[MISP] Connected — version {version}')
            return {'success': True, 'version': version, 'url': self.misp_url}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ── استيراد Events من MISP ────────────────────────────────

    def pull_events(self, days_back: int = 7, limit: int = 100) -> dict:
        """
        استيراد Events من MISP وتحويلها لـ IoCs في قاعدة البيانات.

        المعاملات:
            days_back : كم يوم تاريخ لاسترجاعه
            limit     : الحد الأقصى للـ Events
        """
        if not self.is_configured:
            return {'success': False, 'error': 'MISP not configured'}

        from_date = (_now() - timedelta(days=days_back)).strftime('%Y-%m-%d')

        try:
            # جلب Events
            payload = {
                'returnFormat': 'json',
                'limit':        limit,
                'page':         1,
                'date_from':    from_date,
                'published':    True,
            }
            data = self._post('/events/restSearch', payload)
            events = data.get('response', [])

            stats = {'events': len(events), 'iocs_added': 0, 'iocs_updated': 0, 'errors': 0}

            for event_wrapper in events:
                event = event_wrapper.get('Event', {})
                try:
                    result = self._process_event(event)
                    stats['iocs_added']   += result.get('added', 0)
                    stats['iocs_updated'] += result.get('updated', 0)
                except Exception as e:
                    stats['errors'] += 1
                    logger.warning(f'[MISP] Error processing event {event.get("id")}: {e}')

            logger.info(f'[MISP] Pull complete: {stats}')
            return {'success': True, **stats}

        except Exception as e:
            logger.error(f'[MISP] Pull failed: {e}')
            return {'success': False, 'error': str(e)}

    def _process_event(self, event: dict) -> dict:
        """معالجة MISP Event واستخراج IoCs منه"""
        from models import IoCEntry, IoCSource
        from extensions import db
        from services.tip_collector import TIPCollector

        collector = TIPCollector()

        # الحصول على مصدر MISP أو إنشاؤه
        misp_source = IoCSource.query.filter_by(name='MISP - Manual Import').first()

        event_id    = str(event.get('id', ''))
        event_info  = event.get('info', '')
        threat_level = self.MISP_THREAT_LEVELS.get(event.get('threat_level_id', 3), 'medium')
        attributes  = event.get('Attribute', [])

        stats = {'added': 0, 'updated': 0}

        for attr in attributes:
            ioc_type = self.MISP_TO_IOC_TYPE.get(attr.get('type', ''))
            if not ioc_type:
                continue

            value = attr.get('value', '').strip()
            if not value:
                continue

            # معالجة الـ domain|ip (نوع مركب)
            if '|' in str(attr.get('type', '')):
                parts = value.split('|')
                value = parts[0].strip()

            ioc_data = {
                'value':         value[:512],
                'ioc_type':      ioc_type,
                'severity':      threat_level,
                'threat_type':   self._misp_category_to_threat(attr.get('category', '')),
                'description':   f'{event_info[:200]} (MISP Event #{event_id})',
                'tags':          'misp,' + ','.join([t.get('name', '') for t in attr.get('Tag', [])])[:200],
                'misp_event_id': event_id,
                'misp_attribute': attr.get('uuid', '')[:100],
            }

            if misp_source:
                result = collector._upsert_ioc(ioc_data, misp_source)
            else:
                # تخزين بدون مصدر
                self._upsert_ioc_direct(ioc_data)
                result = 'added'

            stats[result] = stats.get(result, 0) + 1

        try:
            from extensions import db
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f'[MISP] DB commit failed: {e}')

        return stats

    # ── تصدير IoCs إلى MISP ──────────────────────────────────

    def push_ioc(self, ioc_value: str, ioc_type: str, threat_type: str = 'suspicious',
                 severity: str = 'medium', description: str = '') -> dict:
        """
        تصدير IoC واحدة إلى MISP كـ Event جديد.
        """
        if not self.is_configured:
            return {'success': False, 'error': 'MISP not configured'}

        misp_type = self.IOC_TO_MISP_TYPE.get(ioc_type, 'other')
        threat_level_id = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}.get(severity, 3)

        event_payload = {
            'Event': {
                'info':             f'MyScanner IoC: {ioc_value[:100]}',
                'threat_level_id':  str(threat_level_id),
                'analysis':         '2',    # completed
                'distribution':     '1',    # community
                'Attribute': [
                    {
                        'type':       misp_type,
                        'category':   self._threat_to_misp_category(threat_type),
                        'value':      ioc_value,
                        'comment':    description[:500] if description else f'Detected by MyScanner — {threat_type}',
                        'to_ids':     True,
                        'distribution': '1',
                    }
                ]
            }
        }

        try:
            result = self._post('/events/add', event_payload)
            event_id = result.get('Event', {}).get('id', '')
            logger.info(f'[MISP] Pushed IoC {ioc_value} → Event #{event_id}')
            return {'success': True, 'event_id': event_id}
        except Exception as e:
            logger.error(f'[MISP] Push failed for {ioc_value}: {e}')
            return {'success': False, 'error': str(e)}

    def push_bulk_iocs(self, iocs: list) -> dict:
        """
        تصدير عدة IoCs كـ Event واحد.
        iocs: [{value, ioc_type, severity, threat_type, description}, ...]
        """
        if not self.is_configured:
            return {'success': False, 'error': 'MISP not configured'}

        if not iocs:
            return {'success': True, 'pushed': 0}

        attributes = []
        for ioc in iocs[:100]:
            misp_type = self.IOC_TO_MISP_TYPE.get(ioc.get('ioc_type', ''), 'other')
            attributes.append({
                'type':     misp_type,
                'category': self._threat_to_misp_category(ioc.get('threat_type', 'suspicious')),
                'value':    ioc.get('value', '')[:512],
                'comment':  ioc.get('description', '')[:200],
                'to_ids':   True,
                'distribution': '1',
            })

        severity = max(iocs, key=lambda x: {'critical':4,'high':3,'medium':2,'low':1}.get(x.get('severity','low'), 0)).get('severity', 'medium')
        threat_level_id = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}.get(severity, 3)

        event_payload = {
            'Event': {
                'info':            f'MyScanner Bulk IoCs — {len(iocs)} indicators',
                'threat_level_id': str(threat_level_id),
                'analysis':        '2',
                'distribution':    '1',
                'Attribute':       attributes,
            }
        }

        try:
            result = self._post('/events/add', event_payload)
            event_id = result.get('Event', {}).get('id', '')
            logger.info(f'[MISP] Pushed {len(iocs)} IoCs → Event #{event_id}')
            return {'success': True, 'event_id': event_id, 'pushed': len(iocs)}
        except Exception as e:
            logger.error(f'[MISP] Bulk push failed: {e}')
            return {'success': False, 'error': str(e)}

    # ── Community MISP Feeds (بدون مصادقة) ───────────────────

    def fetch_community_feeds(self) -> list:
        """
        جلب Feeds مفتوحة من مجتمع MISP (لا تحتاج API Key).
        تُعيد قائمة بـ IoCs من مصادر عامة.
        """
        COMMUNITY_FEEDS = [
            'https://www.circl.lu/doc/misp/feed-osint/manifest.json',
            'https://raw.githubusercontent.com/MISP/MISP/2.4/app/files/feeds/defaultfeeds.json',
        ]

        all_iocs = []
        for feed_url in COMMUNITY_FEEDS:
            try:
                resp = requests.get(feed_url, timeout=15,
                                    headers={'User-Agent': 'MyScanner-TIP/1.0'})
                if resp.status_code == 200:
                    iocs = self._parse_community_feed(resp.text, feed_url)
                    all_iocs.extend(iocs)
                    logger.info(f'[MISP] Community feed {feed_url}: {len(iocs)} IoCs')
            except Exception as e:
                logger.warning(f'[MISP] Community feed error {feed_url}: {e}')

        return all_iocs

    def _parse_community_feed(self, text: str, source_url: str) -> list:
        """تحليل بسيط لـ manifest JSON من MISP"""
        iocs = []
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for event_uuid, event_info in list(data.items())[:20]:
                    info_text = event_info.get('info', '') if isinstance(event_info, dict) else ''
                    # استخراج IoCs من نص الحدث
                    import re
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    for ip in re.findall(ip_pattern, info_text):
                        iocs.append({
                            'value': ip, 'ioc_type': 'ip',
                            'severity': 'medium', 'threat_type': 'suspicious',
                            'tags': 'misp,community',
                            'description': f'MISP community feed: {info_text[:100]}'
                        })
        except Exception:
            pass
        return iocs

    # ── HTTP helpers ──────────────────────────────────────────

    def _get(self, endpoint: str) -> dict:
        url = f'{self.misp_url}{endpoint}'
        resp = self.session.get(url, timeout=30, verify=self.verify_ssl)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, payload: dict) -> dict:
        url = f'{self.misp_url}{endpoint}'
        resp = self.session.post(url, json=payload, timeout=30, verify=self.verify_ssl)
        resp.raise_for_status()
        return resp.json()

    # ── تحويل الفئات ─────────────────────────────────────────

    def _misp_category_to_threat(self, category: str) -> str:
        mapping = {
            'Network activity':        'network',
            'Payload delivery':        'malware',
            'Payload installation':    'malware',
            'External analysis':       'suspicious',
            'Antivirus detection':     'malware',
            'Financial fraud':         'fraud',
            'Social network':          'phishing',
        }
        return mapping.get(category, 'suspicious')

    def _threat_to_misp_category(self, threat_type: str) -> str:
        mapping = {
            'malware':    'Payload delivery',
            'phishing':   'Social network',
            'botnet':     'Network activity',
            'network':    'Network activity',
            'fraud':      'Financial fraud',
            'spam':       'Payload delivery',
            'scanner':    'Network activity',
        }
        return mapping.get(threat_type, 'External analysis')

    # ── IoC direct insert (fallback بدون مصدر) ───────────────

    def _upsert_ioc_direct(self, ioc_data: dict):
        from models import IoCEntry
        from extensions import db
        from datetime import timedelta

        value    = ioc_data.get('value', '').strip()
        ioc_type = ioc_data.get('ioc_type', '')

        if not value or not ioc_type:
            return

        existing = IoCEntry.query.filter_by(value=value, ioc_type=ioc_type).first()
        if existing:
            existing.last_seen  = _now()
            existing.source_count = (existing.source_count or 1) + 1
        else:
            expires_map = {'ip': 30, 'url': 14, 'domain': 90}
            days = expires_map.get(ioc_type, 30)
            entry = IoCEntry(
                value        = value,
                ioc_type     = ioc_type,
                severity     = ioc_data.get('severity', 'medium'),
                threat_type  = ioc_data.get('threat_type'),
                tags         = ioc_data.get('tags', 'misp'),
                description  = (ioc_data.get('description') or '')[:500],
                misp_event_id = ioc_data.get('misp_event_id'),
                confidence   = 75,
                source_count = 1,
                expires_at   = _now() + timedelta(days=days),
            )
            db.session.add(entry)