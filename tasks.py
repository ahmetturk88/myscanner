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