# routes/vuln_routes.py
"""
مسارات API لميزة فحص الثغرات المتقدم
"""

from flask import Blueprint, render_template, request, jsonify, session, send_file
from flask_login import login_required, current_user
from functools import wraps
import logging
from io import BytesIO

from models.vulnerability import VulnerabilityScan, ScanConfig
from extensions import db
from services.vulnerability_scanner.scan_orchestrator import get_orchestrator
from services.vulnerability_scanner.report_generator import get_report_generator
import json
logger = logging.getLogger(__name__)

# إنشاء Blueprint
vuln_bp = Blueprint('vuln', __name__, url_prefix='/vulnerability')


def admin_required(f):
    """ديكوراتور للتحقق من صلاحيات المشرف"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        # افترض أن لديك حقل is_admin في نموذج User
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@vuln_bp.route('/')
@login_required
def vuln_dashboard():
    """لوحة تحكم فحص الثغرات"""
    # الحصول على المسحات السابقة للمستخدم
    recent_scans = VulnerabilityScan.query.filter_by(
        user_id=current_user.id
    ).order_by(VulnerabilityScan.created_at.desc()).limit(10).all()
    
    # الحصول على حالة الماسحات
    orchestrator = get_orchestrator()
    scanners_status = orchestrator.get_available_scanners()
    
    # الحصول على الإحصائيات
    stats = {
        'total_scans': VulnerabilityScan.query.filter_by(user_id=current_user.id).count(),
        'total_vulnerabilities': db.session.query(db.func.sum(VulnerabilityScan.total_vulnerabilities))
            .filter_by(user_id=current_user.id).scalar() or 0,
        'critical_count': db.session.query(db.func.sum(VulnerabilityScan.critical_count))
            .filter_by(user_id=current_user.id).scalar() or 0
    }
    
    return render_template('vuln_scan.html',
                          title='Advanced Vulnerability Scanner',
                          recent_scans=recent_scans,
                          scanners_status=scanners_status,
                          stats=stats)


@vuln_bp.route('/start', methods=['POST'])
@login_required
def start_scan():
    """بدء مسح جديد"""
    try:
        data = request.get_json()
        
        target = data.get('target')
        scan_type = data.get('scan_type', 'web_application')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # التحقق من صحة الهدف
        if scan_type in ['web_application', 'full']:
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
        
        # إعدادات إضافية
        config = {
            'active_scan': data.get('active_scan', True),
            'depth': data.get('depth', 5),
            'timeout': data.get('timeout', 3600)
        }
        
        # بدء المسح
        orchestrator = get_orchestrator()
        scan = orchestrator.start_scan(
            target=target,
            scan_type=scan_type,
            user_id=current_user.id,
            config=config
        )
        
        return jsonify({
            'success': True,
            'scan_uuid': scan.scan_uuid,
            'message': f'Scan started successfully for {target}'
        }), 202
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({'error': str(e)}), 500


@vuln_bp.route('/status/<scan_uuid>')
@login_required
def get_scan_status(scan_uuid):
    """الحصول على حالة المسح"""
    scan = VulnerabilityScan.query.filter_by(scan_uuid=scan_uuid).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # التحقق من صلاحيات المستخدم
    if scan.user_id != current_user.id and not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    orchestrator = get_orchestrator()
    status = orchestrator.get_scan_status(scan_uuid)
    
    return jsonify(status)


@vuln_bp.route('/results/<scan_uuid>')
@login_required
def get_scan_results(scan_uuid):
    """الحصول على نتائج المسح"""
    scan = VulnerabilityScan.query.filter_by(scan_uuid=scan_uuid).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # التحقق من صلاحيات المستخدم
    if scan.user_id != current_user.id and not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    orchestrator = get_orchestrator()
    results = orchestrator.get_scan_results(scan_uuid)
    
    return jsonify(results)


@vuln_bp.route('/results/<scan_uuid>/view')
@login_required
def view_results(scan_uuid):
    """عرض نتائج المسح في صفحة HTML"""
    scan = VulnerabilityScan.query.filter_by(scan_uuid=scan_uuid).first()
    
    if not scan:
        return render_template('error.html', error='Scan not found'), 404
    
    if scan.user_id != current_user.id and not getattr(current_user, 'is_admin', False):
        return render_template('error.html', error='Unauthorized'), 403
    
    orchestrator = get_orchestrator()
    results = orchestrator.get_scan_results(scan_uuid)
    
    return render_template('vuln_results.html',
                          title=f'Scan Results - {scan.target}',
                          scan=scan,
                          results=results)


@vuln_bp.route('/report/<scan_uuid>')
@login_required
def download_report(scan_uuid):
    """تحميل تقرير المسح"""
    format = request.args.get('format', 'html')
    
    if format not in ['html', 'json', 'csv', 'pdf']:
        format = 'html'
    
    # التحقق من صلاحيات المسح
    scan = VulnerabilityScan.query.filter_by(scan_uuid=scan_uuid).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan.user_id != current_user.id and not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    # توليد التقرير
    report_gen = get_report_generator()
    report_content = report_gen.generate_report(scan_uuid, format=format)
    
    if not report_content:
        return jsonify({'error': 'Failed to generate report'}), 500
    
    # تحديد نوع المحتوى واسم الملف
    mime_types = {
        'html': 'text/html',
        'json': 'application/json',
        'csv': 'text/csv',
        'pdf': 'application/pdf'
    }
    
    filename = f"vulnerability_report_{scan_uuid[:8]}.{format}"
    
    return send_file(
        BytesIO(report_content),
        mimetype=mime_types.get(format, 'text/plain'),
        as_attachment=True,
        download_name=filename
    )


@vuln_bp.route('/stop/<scan_uuid>', methods=['POST'])
@login_required
def stop_scan(scan_uuid):
    """إيقاف مسح قيد التشغيل"""
    orchestrator = get_orchestrator()
    
    if orchestrator.stop_scan(scan_uuid):
        return jsonify({'success': True, 'message': 'Scan stopped successfully'})
    
    return jsonify({'error': 'Failed to stop scan'}), 400


@vuln_bp.route('/scanners/status')
@login_required
@admin_required
def scanners_status():
    """الحصول على حالة الماسحات (للمشرفين فقط)"""
    orchestrator = get_orchestrator()
    status = orchestrator.get_available_scanners()
    return jsonify(status)


@vuln_bp.route('/history')
@login_required
def scan_history():
    """الحصول على تاريخ المسحات (API)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    scans = VulnerabilityScan.query.filter_by(
        user_id=current_user.id
    ).order_by(VulnerabilityScan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'scans': [s.to_dict() for s in scans.items],
        'total': scans.total,
        'page': scans.page,
        'pages': scans.pages
    })


@vuln_bp.route('/configs', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def manage_configs():
    """إدارة تكوينات المسح المحفوظة"""
    
    if request.method == 'GET':
        # الحصول على التكوينات
        configs = ScanConfig.query.filter_by(user_id=current_user.id).all()
        return jsonify([c.to_dict() for c in configs])
    
    elif request.method == 'POST':
        # إنشاء تكوين جديد
        data = request.get_json()
        
        config = ScanConfig(
            name=data.get('name'),
            description=data.get('description'),
            scan_type=data.get('scan_type', 'web_application'),
            config_data=json.dumps(data.get('config', {})),
            user_id=current_user.id
        )
        
        db.session.add(config)
        db.session.commit()
        
        return jsonify(config.to_dict()), 201
    
    elif request.method == 'PUT':
        # تحديث تكوين
        data = request.get_json()
        config_id = data.get('id')
        
        config = ScanConfig.query.filter_by(id=config_id, user_id=current_user.id).first()
        if not config:
            return jsonify({'error': 'Config not found'}), 404
        
        config.name = data.get('name', config.name)
        config.description = data.get('description', config.description)
        config.config_data = json.dumps(data.get('config', {}))
        
        db.session.commit()
        
        return jsonify(config.to_dict())
    
    elif request.method == 'DELETE':
        # حذف تكوين
        config_id = request.args.get('id')
        
        config = ScanConfig.query.filter_by(id=config_id, user_id=current_user.id).first()
        if not config:
            return jsonify({'error': 'Config not found'}), 404
        
        db.session.delete(config)
        db.session.commit()
        
        return jsonify({'success': True})


@vuln_bp.route('/stats')
@login_required
def get_stats():
    """الحصول على إحصائيات المستخدم"""
    
    scans = VulnerabilityScan.query.filter_by(user_id=current_user.id).all()
    
    # إحصائيات بمرور الوقت (آخر 30 يوم)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    recent_scans = VulnerabilityScan.query.filter(
        VulnerabilityScan.user_id == current_user.id,
        VulnerabilityScan.created_at >= thirty_days_ago
    ).all()
    
    daily_stats = {}
    for scan in recent_scans:
        day = scan.created_at.strftime('%Y-%m-%d')
        if day not in daily_stats:
            daily_stats[day] = {'scans': 0, 'vulns': 0}
        daily_stats[day]['scans'] += 1
        daily_stats[day]['vulns'] += scan.total_vulnerabilities
    
    return jsonify({
        'total_scans': len(scans),
        'total_vulnerabilities': sum(s.total_vulnerabilities for s in scans),
        'average_risk_score': sum(s.risk_score for s in scans) / len(scans) if scans else 0,
        'daily_stats': daily_stats,
        'by_severity': {
            'critical': sum(s.critical_count for s in scans),
            'high': sum(s.high_count for s in scans),
            'medium': sum(s.medium_count for s in scans),
            'low': sum(s.low_count for s in scans)
        }
    })