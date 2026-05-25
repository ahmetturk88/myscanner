# tasks.py
import sys
import os

# أضف مسار المشروع إلى sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from celery import Celery
from datetime import datetime
import json

# إعداد Celery
celery = Celery(
    'myscanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
)


@celery.task(bind=True, name='scan_site_task')
def scan_site_task(self, domain, user_id, scan_id):
    """فحص موقع في الخلفية"""
    try:
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': 'Starting site scan...'})
        
        from services.site_analyzer import SiteAnalyzer
        
        analyzer = SiteAnalyzer()
        result = analyzer.comprehensive_analysis(domain)
        
        self.update_state(state='RUNNING', meta={'progress': 80, 'status': 'Saving results...'})
        
        # حفظ النتيجة في قاعدة البيانات
        from models import Scan
        from extensions import db
        from app import app
        
        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = 'completed'
                scan.verdict = result.get('verdict', 'unknown')
                scan.security_score = result.get('security_score', 0)
                scan.result = json.dumps(result)
                scan.completed_at = datetime.utcnow()
                db.session.commit()
        
        return {
            'status': 'completed',
            'result': result,
            'message': 'Site scan completed successfully'
        }
        
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='scan_file_task')
def scan_file_task(self, file_path, filename, user_id):
    """فحص ملف في الخلفية"""
    try:
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': 'Starting file scan...'})
        
        from services.file_deep_analyzer import FileDeepAnalyzer
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        analyzer = FileDeepAnalyzer(use_exiftool=True)
        result = analyzer.comprehensive_analysis(file_content, filename)
        
        os.remove(file_path)
        
        return {
            'status': 'completed',
            'result': result,
            'message': 'File scan completed successfully'
        }
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='batch_scan_task')
def batch_scan_task(self, urls, user_id):
    """فحص مجموعة روابط دفعة واحدة"""
    results = []
    total = len(urls)
    
    for i, url in enumerate(urls):
        self.update_state(state='RUNNING', meta={'progress': int((i/total)*100), 'status': f'Scanning {i+1}/{total}...'})
        
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = URLDeepAnalyzer()
        result = analyzer.comprehensive_analysis(url)
        results.append(result)
    
    return {'status': 'completed', 'results': results, 'total': total}


@celery.task(bind=True, name='scan_large_file_task')
def scan_large_file_task(self, file_path, filename, user_id):
    """فحص ملف كبير في الخلفية"""
    try:
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': 'Starting large file scan...'})
        
        from services.file_deep_analyzer import FileDeepAnalyzer
        
        analyzer = FileDeepAnalyzer()
        result = analyzer.analyze_large_file(file_path)
        
        os.remove(file_path)
        
        return {
            'status': 'completed',
            'result': result,
            'message': 'Large file scan completed'
        }
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}
    

# ================================================================
# TIP Celery Tasks — أضف هذا الكود في نهاية ملف tasks.py
# ================================================================
#
# المهام المضافة:
#   fetch_ioc_source_task   — جلب مصدر IoC واحد
#   fetch_all_ioc_sources   — جلب كل المصادر المستحقة (يومي)
#   cleanup_expired_iocs    — تنظيف IoCs المنتهية (يومي)
#   misp_pull_task          — مزامنة من MISP
#   misp_push_task          — تصدير IoC إلى MISP
#   initialize_tip_sources  — تهيئة المصادر الافتراضية (مرة واحدة)
# ================================================================


@celery.task(bind=True, name='fetch_ioc_source_task', max_retries=3, default_retry_delay=300)
def fetch_ioc_source_task(self, source_id: int):
    """
    جلب IoCs من مصدر واحد محدد.
    يُستدعى يدوياً أو من fetch_all_ioc_sources.
    """
    try:
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': f'Fetching source {source_id}...'})

        from services.tip_collector import TIPCollector
        from app import app

        with app.app_context():
            collector = TIPCollector()
            result = collector.fetch_source(source_id)

        self.update_state(state='RUNNING', meta={'progress': 100, 'status': 'Done'})
        return {'status': 'completed', **result}

    except Exception as e:
        try:
            self.retry(exc=e)
        except self.MaxRetriesExceededError:
            return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='fetch_all_ioc_sources')
def fetch_all_ioc_sources(self):
    """
    جلب كل المصادر النشطة التي حان وقتها.
    يُجدوَل بواسطة Celery Beat كل ساعة.
    """
    try:
        from services.tip_collector import TIPCollector
        from app import app

        with app.app_context():
            collector = TIPCollector()
            result = collector.fetch_all_due()

        return {'status': 'completed', **result}

    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='cleanup_expired_iocs')
def cleanup_expired_iocs(self):
    """
    تعطيل IoCs المنتهية الصلاحية.
    يُجدوَل يومياً في Celery Beat.
    """
    try:
        from services.tip_collector import TIPCollector
        from app import app

        with app.app_context():
            collector = TIPCollector()
            deactivated = collector.cleanup_expired()

        return {'status': 'completed', 'deactivated': deactivated}

    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='misp_pull_task')
def misp_pull_task(self, days_back: int = 7):
    """
    استيراد Events من MISP.
    يُجدوَل يومياً في Celery Beat.
    """
    try:
        from services.misp_client import MISPClient
        from app import app

        with app.app_context():
            client = MISPClient()
            if not client.is_configured:
                return {'status': 'skipped', 'reason': 'MISP not configured'}
            result = client.pull_events(days_back=days_back)

        return {'status': 'completed', **result}

    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='misp_push_task')
def misp_push_task(self, ioc_value: str, ioc_type: str, severity: str = 'medium',
                   threat_type: str = 'suspicious', description: str = ''):
    """
    تصدير IoC واحدة إلى MISP.
    يُستدعى يدوياً عند اكتشاف IoC جديدة ذات أهمية.
    """
    try:
        from services.misp_client import MISPClient
        from app import app

        with app.app_context():
            client = MISPClient()
            if not client.is_configured:
                return {'status': 'skipped', 'reason': 'MISP not configured'}
            result = client.push_ioc(
                ioc_value   = ioc_value,
                ioc_type    = ioc_type,
                severity    = severity,
                threat_type = threat_type,
                description = description,
            )

        return {'status': 'completed', **result}

    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


@celery.task(bind=True, name='initialize_tip_sources')
def initialize_tip_sources(self):
    """
    تهيئة المصادر الافتراضية في قاعدة البيانات.
    استدع مرة واحدة بعد النشر الأول.
    """
    try:
        from services.tip_collector import TIPCollector
        from app import app

        with app.app_context():
            collector = TIPCollector()
            added = collector.initialize_default_sources()

        return {'status': 'completed', 'sources_added': added}

    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


# ================================================================
# Celery Beat Schedule — أضف هذا لملف celery_config.py أو app.py
# ================================================================
#
# celery.conf.beat_schedule = {
#     'fetch-ioc-sources-hourly': {
#         'task':     'fetch_all_ioc_sources',
#         'schedule': 3600,    # كل ساعة
#     },
#     'cleanup-expired-iocs-daily': {
#         'task':     'cleanup_expired_iocs',
#         'schedule': 86400,   # يومياً
#     },
#     'misp-pull-daily': {
#         'task':     'misp_pull_task',
#         'schedule': 86400,   # يومياً
#         'kwargs':   {'days_back': 7},
#     },
# }