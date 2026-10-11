# tasks.py
import sys
import os

# أضف مسار المشروع إلى sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from celery_app import celery
from datetime import datetime
import json
from services.upload_validation import FILE_MAX_SIZE, remove_temporary_upload

# Network phases are budgeted (services.url_analyzer); this is the hard stop.
@celery.task(bind=True, name='scan_url_task', soft_time_limit=300, time_limit=330)
def scan_url_task(self, url, user_id, scan_id, task_id):
    from app import app
    from services.url_scan_storage import claim_url_scan, save_url_scan, fail_url_scan
    claimed = False
    analyzer = None
    stage = 'claim'
    try:
        with app.app_context():
            claimed = claim_url_scan(scan_id, user_id, url, task_id)
        if not claimed:
            return {'status': 'failed', 'error': 'URL scan is not eligible for processing.'}
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = URLDeepAnalyzer()
        stage = 'local_analysis'
        local = analyzer.comprehensive_analysis(url)
        stage = 'deep_analysis'
        deep = analyzer.comprehensive_deep_analysis(url)
        stage = 'save_report'
        with app.app_context():
            return save_url_scan(scan_id, user_id, url, local, deep)
    except Exception as error:
        from services.url_failure_diagnostic import failure_diagnostic
        diagnostic = failure_diagnostic(error, stage)
        app.logger.error('URL scan failed; scan_id=%s; diagnostic=%s', scan_id, diagnostic)
        if claimed:
            try:
                with app.app_context():
                    fail_url_scan(scan_id, user_id, url)
            except Exception:
                app.logger.error('URL failure could not be persisted; scan_id=%s', scan_id)
        return {'status': 'failed', 'error': 'URL analysis could not finish. Please start a new scan.'}
    finally:
        if analyzer is not None:
            try:
                analyzer.session.close()
            except Exception:
                app.logger.warning('URL analyzer cleanup failed; scan_id=%s', scan_id)


@celery.task(name='expire_url_scan_jobs')
def expire_url_scan_jobs():
    from app import app
    from services.url_scan_storage import expire_url_scans
    with app.app_context():
        return {'expired': expire_url_scans()}


@celery.task(bind=True, name='scan_site_task')
def scan_site_task(self, domain, user_id, scan_id):
    """Persist the complete site report before returning a success state."""
    from app import app
    from services.site_scan_storage import claim_site_scan, save_site_scan, fail_site_scan
    claimed = False
    try:
        with app.app_context():
            claimed = claim_site_scan(scan_id, user_id, domain)
        if not claimed:
            return {'status': 'failed', 'error': 'Site scan is not eligible for processing.'}
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': 'Starting site scan...'})
        from services.site_analyzer import SiteAnalyzer
        result = SiteAnalyzer().comprehensive_analysis(domain)
        self.update_state(state='RUNNING', meta={'progress': 80, 'status': 'Saving results...'})
        with app.app_context():
            stored = save_site_scan(scan_id, user_id, domain, result)
        return {'status': stored['status'], 'result': stored,
                'message': 'Site analysis report saved'}
    except Exception:
        app.logger.error('Site scan failed; scan_id=%s', scan_id)
        if claimed:
            try:
                with app.app_context():
                    fail_site_scan(scan_id, user_id, domain)
            except Exception:
                app.logger.error('Site scan failure could not be persisted; scan_id=%s', scan_id)
        return {'status': 'failed', 'error': 'Site analysis failed. Please retry.'}


@celery.task(bind=True, name='scan_file_task')
def scan_file_task(self, file_path, filename, user_id):
    """فحص ملف في الخلفية"""
    try:
        self.update_state(state='RUNNING', meta={'progress': 0, 'status': 'Starting file scan...'})
        
        from services.file_deep_analyzer import FileDeepAnalyzer
        
        with open(file_path, 'rb') as f:
            file_content = f.read(FILE_MAX_SIZE + 1)
        if len(file_content) > FILE_MAX_SIZE:
            raise ValueError('File too large for file scan')
        
        analyzer = FileDeepAnalyzer(use_exiftool=True)
        result = analyzer.comprehensive_analysis(file_content, filename)
        
        
        return {
            'status': 'completed',
            'result': result,
            'message': 'File scan completed successfully'
        }
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}
    finally:
        remove_temporary_upload(file_path)


@celery.task(bind=True, name='evidence_job_task', soft_time_limit=300, time_limit=330)
def evidence_job_task(self, kind, params, user_id):
    """Site, subdomain and file evidence collected outside the web process."""
    from app import app
    from services.evidence_jobs import run_evidence_job
    with app.app_context():
        return run_evidence_job(kind, params, user_id)


@celery.task(bind=True, name='bulk_email_task', soft_time_limit=600, time_limit=630)
def bulk_email_task(self, emails, user_id):
    """Check up to 20 addresses; each accepted item was charged before queuing."""
    from services.email_checker import AdvancedEmailChecker
    checker = AdvancedEmailChecker(None)
    results = []
    for index, email in enumerate(emails[:20]):
        self.update_state(state='RUNNING', meta={'progress': int(index / len(emails) * 100),
                                                 'status': f'Checking {index + 1}/{len(emails)}...'})
        try:
            result = checker.check_all(email)
        except Exception:
            result = {'email': email, 'valid': False, 'verdict': 'unknown', 'error': 'Check unavailable'}
        results.append({
            "email": result.get("email", email),
            "valid": result.get("valid", False),
            "verdict": result.get("verdict", "unknown"),
            "quality_score": result.get("quality_score", 0),
            "is_disposable": result.get("is_disposable", False),
            "deliverability": result.get("deliverability", "unknown"),
        })
    stats = {
        "total": len(results),
        "valid": sum(1 for r in results if r["valid"]),
        "invalid": sum(1 for r in results if not r["valid"]),
        "disposable": sum(1 for r in results if r.get("is_disposable", False)),
        "safe": sum(1 for r in results if r.get("verdict") == "safe"),
        "average_score": sum(r.get("quality_score", 0) for r in results) / len(results) if results else 0,
    }
    return {'status': 'completed', 'stats': stats, 'results': results}


@celery.task(bind=True, name='sandbox_file_task', soft_time_limit=600, time_limit=630)
def sandbox_file_task(self, file_path, filename, user_id, environment_id):
    """Static analysis plus hash reputation for one uploaded Sandbox file."""
    from routes.sandbox_routes import MAX_SIZE, sandbox_file_report
    try:
        self.update_state(state='RUNNING', meta={'progress': 10, 'status': 'Analyzing file...'})
        with open(file_path, 'rb') as handle:
            content = handle.read(MAX_SIZE + 1)
        if len(content) > MAX_SIZE:
            raise ValueError('File too large for Sandbox analysis')
        return {'status': 'completed', 'result': sandbox_file_report(content, filename, environment_id)}
    except Exception:
        return {'status': 'failed', 'error': 'Sandbox analysis failed. Please retry.'}
    finally:
        remove_temporary_upload(file_path)


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
        
        
        return {
            'status': 'completed',
            'result': result,
            'message': 'Large file scan completed'
        }
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}
    finally:
        remove_temporary_upload(file_path)
    

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

