# routes/tip_routes.py
# ================================================================
# TIP API Routes — نقاط النهاية لإدارة منصة TIP
#
# Endpoints:
#   GET  /tip/dashboard           ← صفحة لوحة TIP
#   GET  /api/tip/stats           ← إحصاءات IoCs
#   GET  /api/tip/iocs            ← قائمة IoCs مع فلترة
#   POST /api/tip/lookup          ← البحث عن IoC واحدة
#   POST /api/tip/lookup/url      ← بحث شامل عن URL
#   POST /api/tip/lookup/bulk     ← بحث دفعي
#   GET  /api/tip/sources         ← قائمة المصادر
#   POST /api/tip/sources/fetch/<id>  ← جلب مصدر يدوياً
#   POST /api/tip/sources/fetch-all  ← جلب كل المصادر
#   POST /api/tip/misp/pull       ← مزامنة من MISP (Admin)
#   POST /api/tip/misp/push       ← تصدير إلى MISP (Admin)
#   GET  /api/tip/matches         ← سجل المطابقات (Admin)
#   POST /api/tip/iocs/add        ← إضافة IoC يدوياً (Admin)
#   DELETE /api/tip/iocs/<id>     ← حذف IoC (Admin)
# ================================================================

from flask import Blueprint, jsonify, request, render_template, current_app
from flask_login import login_required, current_user
from datetime import datetime, timezone

tip_bp = Blueprint('tip', __name__)


def _now():
    return datetime.now(timezone.utc)


# ── Helper: فحص صلاحيات Admin ────────────────────────────────

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════
#  صفحات HTML
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/tip/dashboard')
@login_required
def tip_dashboard():
    """لوحة تحكم TIP"""
    return render_template('tip_dashboard.html')


# ══════════════════════════════════════════════════════════════
#  إحصاءات
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/stats')
@login_required
def api_tip_stats():
    """إحصاءات عامة عن قاعدة IoCs"""
    try:
        from services.ioc_lookup import IoCLookup
        lookup = IoCLookup()
        stats = lookup.get_statistics()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  البحث (Lookup)
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/lookup', methods=['POST'])
@login_required
def api_tip_lookup():
    """
    البحث عن IoC واحدة (IP / domain / URL / hash).
    ---
    body: { "value": "...", "type": "ip|domain|url|sha256|..." }
    """
    data = request.get_json() or {}
    value    = data.get('value', '').strip()
    ioc_type = data.get('type', None)

    if not value:
        return jsonify({'error': 'value is required'}), 400

    try:
        from services.ioc_lookup import IoCLookup
        lookup = IoCLookup()
        result = lookup.lookup(
            value    = value,
            ioc_type = ioc_type,
            context  = 'tip_dashboard',
            user_id  = current_user.id,
        )
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        current_app.logger.error(f'[TIP] Lookup error: {e}')
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/lookup/url', methods=['POST'])
@login_required
def api_tip_lookup_url():
    """
    بحث شامل عن URL (يفحص URL + domain + IP).
    ---
    body: { "url": "https://..." }
    """
    data = request.get_json() or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'url is required'}), 400

    try:
        from services.ioc_lookup import IoCLookup
        lookup = IoCLookup()
        result = lookup.lookup_url(url=url, context='tip_lookup', user_id=current_user.id)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/lookup/bulk', methods=['POST'])
@login_required
def api_tip_lookup_bulk():
    """
    بحث دفعي عن عدة قيم.
    ---
    body: { "values": ["1.2.3.4", "evil.com", ...] }
    """
    data = request.get_json() or {}
    values = data.get('values', [])

    if not values or not isinstance(values, list):
        return jsonify({'error': 'values list is required'}), 400

    if len(values) > 100:
        return jsonify({'error': 'Maximum 100 values per request'}), 400

    try:
        from services.ioc_lookup import IoCLookup
        lookup = IoCLookup()
        results = lookup.bulk_lookup(values, context='bulk_lookup', user_id=current_user.id)

        found_count = sum(1 for r in results if r.get('found'))
        return jsonify({
            'success': True,
            'total':   len(results),
            'found':   found_count,
            'clean':   len(results) - found_count,
            'results': results,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  قائمة IoCs
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/iocs')
@login_required
def api_tip_iocs():
    """
    قائمة IoCs مع فلترة وترقيم صفحات.
    Query params: type, severity, threat_type, search, page, per_page
    """
    try:
        from models import IoCEntry

        ioc_type    = request.args.get('type', '').strip()
        severity    = request.args.get('severity', '').strip()
        threat_type = request.args.get('threat_type', '').strip()
        search      = request.args.get('search', '').strip()
        page        = request.args.get('page', 1, type=int)
        per_page    = min(request.args.get('per_page', 50, type=int), 200)

        query = IoCEntry.query.filter_by(is_active=True)

        if ioc_type:    query = query.filter(IoCEntry.ioc_type    == ioc_type)
        if severity:    query = query.filter(IoCEntry.severity     == severity)
        if threat_type: query = query.filter(IoCEntry.threat_type  == threat_type)
        if search:      query = query.filter(IoCEntry.value.ilike(f'%{search}%'))

        # ترتيب حسب الخطورة ثم الثقة
        query = query.order_by(IoCEntry.confidence.desc(), IoCEntry.last_seen.desc())

        paginated = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'success':   True,
            'total':     paginated.total,
            'page':      page,
            'per_page':  per_page,
            'pages':     paginated.pages,
            'iocs':      [ioc.to_dict() for ioc in paginated.items],
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  إدارة المصادر (Admin)
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/sources')
@login_required
def api_tip_sources():
    """قائمة مصادر IoC"""
    try:
        from models import IoCSource
        sources = IoCSource.query.order_by(IoCSource.trust_score.desc()).all()
        return jsonify({
            'success': True,
            'sources': [
                {
                    'id':             s.id,
                    'name':           s.name,
                    'url':            s.url,
                    'feed_type':      s.feed_type,
                    'trust_score':    s.trust_score,
                    'is_active':      s.is_active,
                    'last_fetched':   s.last_fetched.isoformat() if s.last_fetched else None,
                    'last_count':     s.last_count,
                    'error_count':    s.error_count,
                    'fetch_interval': s.fetch_interval,
                    'is_due':         s.is_due,
                    'notes':          s.notes,
                }
                for s in sources
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/sources/fetch/<int:source_id>', methods=['POST'])
@login_required
@admin_required
def api_tip_fetch_source(source_id):
    """جلب مصدر IoC يدوياً (Admin)"""
    try:
        from tasks import fetch_ioc_source_task
        task = fetch_ioc_source_task.delay(source_id)
        return jsonify({'success': True, 'task_id': task.id, 'message': f'Fetching source {source_id} in background'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/sources/fetch-all', methods=['POST'])
@login_required
@admin_required
def api_tip_fetch_all():
    """جلب كل المصادر المستحقة (Admin)"""
    try:
        from tasks import fetch_all_ioc_sources
        task = fetch_all_ioc_sources.delay()
        return jsonify({'success': True, 'task_id': task.id, 'message': 'Fetching all due sources in background'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/sources/initialize', methods=['POST'])
@login_required
@admin_required
def api_tip_initialize():
    """تهيئة المصادر الافتراضية (Admin — مرة واحدة)"""
    try:
        from tasks import initialize_tip_sources
        task = initialize_tip_sources.delay()
        return jsonify({'success': True, 'task_id': task.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  MISP (Admin)
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/misp/status')
@login_required
@admin_required
def api_misp_status():
    """حالة الاتصال بـ MISP"""
    try:
        from services.misp_client import MISPClient
        client = MISPClient()
        result = client.test_connection()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@tip_bp.route('/api/tip/misp/pull', methods=['POST'])
@login_required
@admin_required
def api_misp_pull():
    """استيراد Events من MISP (Admin)"""
    try:
        data = request.get_json() or {}
        days_back = data.get('days_back', 7)
        from tasks import misp_pull_task
        task = misp_pull_task.delay(days_back=days_back)
        return jsonify({'success': True, 'task_id': task.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/misp/push', methods=['POST'])
@login_required
@admin_required
def api_misp_push():
    """تصدير IoC إلى MISP (Admin)"""
    data = request.get_json() or {}
    value    = data.get('value', '').strip()
    ioc_type = data.get('type', '').strip()

    if not value or not ioc_type:
        return jsonify({'error': 'value and type are required'}), 400

    try:
        from tasks import misp_push_task
        task = misp_push_task.delay(
            ioc_value   = value,
            ioc_type    = ioc_type,
            severity    = data.get('severity', 'medium'),
            threat_type = data.get('threat_type', 'suspicious'),
            description = data.get('description', ''),
        )
        return jsonify({'success': True, 'task_id': task.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  إدارة IoCs (Admin)
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/iocs/add', methods=['POST'])
@login_required
@admin_required
def api_tip_add_ioc():
    """إضافة IoC يدوياً (Admin)"""
    data = request.get_json() or {}
    value    = data.get('value', '').strip()
    ioc_type = data.get('type', '').strip()
    severity = data.get('severity', 'medium')

    if not value or not ioc_type:
        return jsonify({'error': 'value and type are required'}), 400

    try:
        from models import IoCEntry
        from extensions import db
        from datetime import timedelta

        expires_map = {'ip': 30, 'url': 14, 'domain': 90}
        days = expires_map.get(ioc_type)
        expires_at = _now() + timedelta(days=days) if days else None

        existing = IoCEntry.query.filter_by(value=value, ioc_type=ioc_type).first()
        if existing:
            return jsonify({'error': 'IoC already exists', 'id': existing.id}), 409

        ioc = IoCEntry(
            value       = value[:512],
            ioc_type    = ioc_type,
            severity    = severity,
            threat_type = data.get('threat_type', 'suspicious'),
            description = data.get('description', '')[:500],
            tags        = data.get('tags', 'manual'),
            confidence  = data.get('confidence', 80),
            expires_at  = expires_at,
            is_active   = True,
        )
        db.session.add(ioc)
        db.session.commit()
        return jsonify({'success': True, 'ioc': ioc.to_dict()}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@tip_bp.route('/api/tip/iocs/<int:ioc_id>', methods=['DELETE'])
@login_required
@admin_required
def api_tip_delete_ioc(ioc_id):
    """حذف (تعطيل) IoC (Admin)"""
    try:
        from models import IoCEntry
        from extensions import db
        ioc = IoCEntry.query.get_or_404(ioc_id)
        ioc.is_active = False
        db.session.commit()
        return jsonify({'success': True, 'message': f'IoC {ioc_id} deactivated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════
#  سجل المطابقات (Admin)
# ══════════════════════════════════════════════════════════════

@tip_bp.route('/api/tip/matches')
@login_required
@admin_required
def api_tip_matches():
    """سجل مطابقات IoC (Admin)"""
    try:
        from models import IoCMatch
        page     = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)

        paginated = IoCMatch.query.order_by(
            IoCMatch.matched_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'success':  True,
            'total':    paginated.total,
            'page':     page,
            'matches':  [
                {
                    'id':         m.id,
                    'ioc_value':  m.ioc_value,
                    'ioc_type':   m.ioc_type,
                    'severity':   m.severity,
                    'context':    m.context,
                    'target':     m.target,
                    'user':       m.user.username if m.user else 'unknown',
                    'matched_at': m.matched_at.isoformat(),
                }
                for m in paginated.items
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500