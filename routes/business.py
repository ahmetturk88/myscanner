"""MyScanner İşletme (Business): the public page with pilot pre-registration, and the company workspace.

The workspace is website-only (never in the mobile app) and open to pilot
accounts. Every change is a CSRF-protected POST; domains are scoped to the
owner's workspace, so nobody can see or change another company's records.
"""
from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from services import business, business_page
from services.site_i18n import current_language

business_bp = Blueprint('business', __name__)
NOTICE = 'business_notice'


def _text():
    lang = current_language()
    return lang, business_page.CONTENT[lang]


@business_bp.route('/isletme', methods=['GET', 'POST'])
def landing():
    from services import pro_page
    lang, text = _text()
    if 'business_source' not in session:
        session['business_source'] = pro_page.visit_source(request.args, request.referrer, request.host.split(':')[0])
    panel = business.pilot_allowed(current_user)
    if request.method == 'GET':
        return render_template('business.html', t=text, lang=lang, outcome=None, panel=panel, form={})
    form = {'email': request.form.get('email', ''), 'website': request.form.get('website', ''),
            'sector': request.form.get('sector', 'other')}
    if request.form.get('company_url'):  # honeypot: people never see this field
        return render_template('business.html', t=text, lang=lang, outcome='added', panel=panel, form={})
    email = business.normalize_email(form['email'])
    if email is None or request.form.get('consent') != 'yes':
        return render_template('business.html', t=text, lang=lang, outcome='invalid', panel=panel, form=form), 400
    outcome = business.pre_register(email, business.normalize_website(form['website']), form['sector'],
                                    session.get('business_source', 'direct'), lang,
                                    current_user.id if current_user.is_authenticated else None)
    return render_template('business.html', t=text, lang=lang, outcome=outcome, panel=panel, form={})


@business_bp.route('/business')
def english_alias():
    return redirect(url_for('business.landing', lang='en'))


def _access(owner_only=False):
    """(workspace, role, None) or (None, None, response). Members may look; only the owner changes things."""
    workspace, role = business.access(current_user)
    if workspace is None:
        session[NOTICE] = 'not_pilot'
        return None, None, redirect(url_for('business.landing') + '#notify')
    if owner_only and role != 'owner':
        abort(403)
    return workspace, role, None


@business_bp.route('/isletme/panel')
@login_required
def panel():
    lang, text = _text()
    workspace, role, blocked = _access()
    if blocked:
        return blocked
    from models import BusinessDomain, User
    from services.business_monitor import domain_view
    domains = BusinessDomain.query.filter_by(workspace_id=workspace.id).order_by(BusinessDomain.created_at).all()
    notice = session.pop(NOTICE, None)
    from services.business_lookalike import is_new, mine_lookalikes, open_lookalikes
    from services.business_uptime import view as uptime_view
    from services.business_compliance import view as kvkk_view
    from services.business_exposure import view as exposure_view
    from services.business_telegram import bot_username, chat_for
    views = [dict(business.serialize(d), monitor=domain_view(d, text) if d.verified_at else None,
                  lookalikes=open_lookalikes(d.id) if d.verified_at else [], lookalike_ran=d.lookalike_at is not None,
                  mine=mine_lookalikes(d.id) if d.verified_at else [],
                  uptime=uptime_view(d, text) if d.verified_at else None,
                  kvkk=kvkk_view(d.id, text) if d.verified_at else None,
                  exposure=exposure_view(d.id, text) if d.verified_at else None)
             for d in domains]
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).replace(tzinfo=None)
    new_names = {row.id for view in views for row in view['lookalikes'] if is_new(row, today)}
    from extensions import db
    owner = db.session.get(User, workspace.owner_id)
    response = render_template('business_panel.html', t=text, lang=lang, workspace=workspace, role=role,
                               domains=views, notice=notice, limit=business.DOMAINS_PER_WORKSPACE,
                               team=business.members(workspace), owner_email=getattr(owner, 'email', ''),
                               team_limit=business.MEMBERS_PER_WORKSPACE, new_names=new_names, today=today.date(),
                               telegram_bot=bot_username(), telegram_chat=chat_for(current_user.id))
    return response, 200, {'Cache-Control': 'private, no-store'}


def _back(notice):
    session[NOTICE] = notice
    return redirect(url_for('business.panel'))


@business_bp.route('/isletme/panel/domains', methods=['POST'])
@login_required
def add_domain():
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('business-domain-add', str(current_user.id), 20, 3600)
        business.add_domain(workspace, request.form.get('domain', ''))
    except AuthRateLimited:
        return _back('error:rate_limited')
    except business.BusinessError as error:
        return _back('error:' + str(error))
    return _back('added_flash')


@business_bp.route('/isletme/panel/domains/<int:domain_id>/verify', methods=['POST'])
@login_required
def verify_domain(domain_id):
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    domain = business.owned_domain(workspace, domain_id)
    if domain is None:
        abort(404)
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('business-verify-hour', str(current_user.id), 20, 3600)
        consume_limit('business-verify-minute', str(current_user.id), 5, 60)
        business.verify_domain(domain)
    except AuthRateLimited:
        return _back('error:rate_limited')
    except business.BusinessError as error:
        return _back('error:' + str(error))
    return _back('verified_flash')


@business_bp.route('/isletme/panel/domains/<int:domain_id>/check', methods=['POST'])
@login_required
def check_now(domain_id):
    workspace, _, blocked = _access()
    if blocked:
        return blocked
    domain = business.owned_domain(workspace, domain_id)
    if domain is None or domain.verified_at is None:
        abort(404)
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('business-check-day', str(current_user.id), 5, 86400)
    except AuthRateLimited:
        return _back('error:check_limit')
    try:
        from celery_app import celery, require_broker
        require_broker(celery)
        celery.send_task('business_check_now', args=[domain.id])
    except Exception:
        current_app.logger.exception('Business check could not be queued')
        return _back('error:check_unavailable')
    return _back('check_queued')


@business_bp.route('/isletme/panel/lookalikes/<int:lookalike_id>/dismiss', methods=['POST'])
@login_required
def dismiss_lookalike(lookalike_id):
    return _mark_lookalike(lookalike_id, 'dismissed', 'look_dismissed_flash')


@business_bp.route('/isletme/panel/lookalikes/<int:lookalike_id>/mine', methods=['POST'])
@login_required
def mine_lookalike(lookalike_id):
    return _mark_lookalike(lookalike_id, 'mine', 'look_mine_flash')


def _workspace_lookalike(workspace, lookalike_id):
    from models import BusinessDomain, BusinessLookalike
    return (BusinessLookalike.query.join(BusinessDomain, BusinessDomain.id == BusinessLookalike.domain_id)
            .filter(BusinessLookalike.id == lookalike_id, BusinessDomain.workspace_id == workspace.id).first())


@business_bp.route('/isletme/panel/lookalikes/<int:lookalike_id>/takedown')
@login_required
def takedown(lookalike_id):
    """Evidence and ready-to-send reports for one look-alike (owner and members may look; the fake is never opened)."""
    lang, text = _text()
    workspace, role, blocked = _access()
    if blocked:
        return blocked
    row = _workspace_lookalike(workspace, lookalike_id)
    if row is None:
        abort(404)
    from extensions import db
    from models import BusinessDomain, User
    from services import business_takedown
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('business-takedown-hour', str(current_user.id), 30, 3600)
    except AuthRateLimited:
        return _back('error:rate_limited')
    records = business_takedown.gather(row)
    domain = db.session.get(BusinessDomain, row.domain_id)
    owner = db.session.get(User, workspace.owner_id)
    items = business_takedown.reports(row, domain.domain, workspace.name, getattr(owner, 'email', ''), records, lang)
    page = render_template('business_takedown.html', t=text, lang=lang, row=row, domain=domain, role=role, items=items,
                           url='https://' + row.name + '/')
    return page, 200, {'Cache-Control': 'private, no-store', 'Referrer-Policy': 'no-referrer'}


@business_bp.route('/isletme/panel/lookalikes/<int:lookalike_id>/reported', methods=['POST'])
@login_required
def lookalike_reported(lookalike_id):
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    row = _workspace_lookalike(workspace, lookalike_id)
    if row is None:
        abort(404)
    from datetime import datetime, timezone
    from extensions import db
    row.reported_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    return _back('td_reported_flash')


def _mark_lookalike(lookalike_id, status, notice):
    """Owner only; the name must belong to one of this workspace's domains (404 otherwise)."""
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    from extensions import db
    from models import BusinessDomain, BusinessLookalike
    row = (BusinessLookalike.query.join(BusinessDomain, BusinessDomain.id == BusinessLookalike.domain_id)
           .filter(BusinessLookalike.id == lookalike_id, BusinessDomain.workspace_id == workspace.id).first())
    if row is None:
        abort(404)
    row.status = status
    db.session.commit()
    return _back(notice)


@business_bp.route('/isletme/panel/settings', methods=['POST'])
@login_required
def save_settings():
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    lang = request.form.get('alert_lang')
    workspace.alert_lang = lang if lang in ('tr', 'en') else 'tr'
    workspace.instant_alerts = request.form.get('instant_alerts') == 'on'
    workspace.daily_digest = request.form.get('daily_digest') == 'on'
    from extensions import db
    db.session.commit()
    return _back('saved_flash')


@business_bp.route('/isletme/panel/domains/<int:domain_id>/remove', methods=['POST'])
@login_required
def remove_domain(domain_id):
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    domain = business.owned_domain(workspace, domain_id)
    if domain is None:
        abort(404)
    business.remove_domain(domain)
    return _back('removed_flash')


# ------------------------------------------------------------------ team

@business_bp.route('/isletme/panel/members', methods=['POST'])
@login_required
def invite_member():
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    try:
        consume_limit('business-invite-day', str(current_user.id), 20, 86400)
        member = business.invite(workspace, current_user, request.form.get('email', ''))
    except AuthRateLimited:
        return _back('error:invite_limit')
    except business.BusinessError as error:
        return _back('error:' + str(error))
    if member.accepted_at is not None:
        return _back('invited_flash')
    return _back('invited_flash' if _send_invitation(workspace, member) else 'invite_mail_failed')


def _send_invitation(workspace, member):
    import os
    from services.email_templates import action_email
    words = (business_page.CONTENT.get(workspace.alert_lang) or business_page.CONTENT['tr'])['invite_mail']
    owner = current_user.email or current_user.username
    paragraphs = [p.format(owner=owner, workspace=workspace.name) for p in words['paragraphs']]
    link = os.getenv('BASE_URL', 'https://myscanners.com').rstrip('/') + url_for('business.accept_invitation', token=member.token)
    html, plain = action_email(words['title'], words['greeting'], paragraphs, words['button'], link, words['note'])
    try:
        from app import send_email
        return bool(send_email(member.email, words['subject'], plain, html))
    except Exception:
        current_app.logger.exception('Business invitation email failed')
        return False


@business_bp.route('/isletme/davet/<token>')
@login_required
def accept_invitation(token):
    lang, text = _text()
    outcome = business.accept(token, current_user)
    if outcome == 'accepted':
        response = _back('joined_flash')
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response
    page = render_template('business_invite.html', t=text, lang=lang, message=text['invite_outcomes'][outcome])
    # The token is in the address: keep it out of caches and Referer headers.
    return page, 404 if outcome == 'invalid' else 403, {'Cache-Control': 'private, no-store', 'Referrer-Policy': 'no-referrer'}


@business_bp.route('/isletme/panel/members/<int:member_id>/remove', methods=['POST'])
@login_required
def remove_member(member_id):
    workspace, _, blocked = _access(owner_only=True)
    if blocked:
        return blocked
    from extensions import db
    from models import BusinessMember
    member = BusinessMember.query.filter_by(id=member_id, workspace_id=workspace.id).first()
    if member is None:
        abort(404)
    db.session.delete(member)
    db.session.commit()
    return _back('member_removed_flash')


# ------------------------------------------------------------------ Telegram

@business_bp.route('/isletme/panel/telegram/link', methods=['POST'])
@login_required
def telegram_link():
    """Owner or member: a one-time code, then straight to the bot (each person links their own chat)."""
    _, _, blocked = _access()
    if blocked:
        return blocked
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    from services.business_telegram import start_link
    try:
        consume_limit('business-telegram-link', str(current_user.id), 10, 3600)
    except AuthRateLimited:
        return _back('error:rate_limited')
    link = start_link(current_user)
    if link is None:
        abort(404)
    return redirect(link)


@business_bp.route('/isletme/panel/telegram/unlink', methods=['POST'])
@login_required
def telegram_unlink():
    _, _, blocked = _access()
    if blocked:
        return blocked
    from services.business_telegram import unlink
    unlink(current_user.id)
    return _back('telegram_unlinked_flash')


# ------------------------------------------------------------------ monthly report

@business_bp.route('/isletme/panel/report.pdf')
@login_required
def monthly_report():
    workspace, _, blocked = _access()
    if blocked:
        return blocked
    from flask import send_file
    from services.auth_rate_limit import AuthRateLimited, consume_limit
    from services.business_report import generate_business_report
    try:
        consume_limit('business-report-hour', str(current_user.id), 10, 3600)
    except AuthRateLimited:
        return _back('error:report_limit')
    lang = current_language()
    pdf = generate_business_report(workspace, lang)
    response = send_file(pdf, mimetype='application/pdf', as_attachment=True,
                         download_name=f'myscanner-isletme-{workspace.id}.pdf')
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@business_bp.route('/admin/business-leads')
@login_required
def admin_leads():
    if not current_user.is_admin:
        abort(404)
    lang, text = _text()
    return render_template('admin_business_leads.html', stats=business.lead_stats(), sectors=text['sectors'])
