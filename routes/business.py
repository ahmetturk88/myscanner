"""MyScanner İşletme (Business): the public page with pilot pre-registration, and the company workspace.

The workspace is website-only (never in the mobile app) and open to pilot
accounts. Every change is a CSRF-protected POST; domains are scoped to the
owner's workspace, so nobody can see or change another company's records.
"""
from flask import Blueprint, abort, redirect, render_template, request, session, url_for
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


def _workspace_or_redirect():
    if not business.pilot_allowed(current_user):
        session[NOTICE] = 'not_pilot'
        return None, redirect(url_for('business.landing') + '#notify')
    return business.workspace_for(current_user, create=True), None


@business_bp.route('/isletme/panel')
@login_required
def panel():
    lang, text = _text()
    workspace, blocked = _workspace_or_redirect()
    if blocked:
        return blocked
    from models import BusinessDomain
    domains = BusinessDomain.query.filter_by(workspace_id=workspace.id).order_by(BusinessDomain.created_at).all()
    notice = session.pop(NOTICE, None)
    response = render_template('business_panel.html', t=text, lang=lang, workspace=workspace,
                               domains=[business.serialize(d) for d in domains], notice=notice,
                               limit=business.DOMAINS_PER_WORKSPACE)
    return response, 200, {'Cache-Control': 'private, no-store'}


def _back(notice):
    session[NOTICE] = notice
    return redirect(url_for('business.panel'))


@business_bp.route('/isletme/panel/domains', methods=['POST'])
@login_required
def add_domain():
    workspace, blocked = _workspace_or_redirect()
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
    workspace, blocked = _workspace_or_redirect()
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


@business_bp.route('/isletme/panel/domains/<int:domain_id>/remove', methods=['POST'])
@login_required
def remove_domain(domain_id):
    workspace, blocked = _workspace_or_redirect()
    if blocked:
        return blocked
    domain = business.owned_domain(workspace, domain_id)
    if domain is None:
        abort(404)
    business.remove_domain(domain)
    return _back('removed_flash')


@business_bp.route('/admin/business-leads')
@login_required
def admin_leads():
    if not current_user.is_admin:
        abort(404)
    lang, text = _text()
    return render_template('admin_business_leads.html', stats=business.lead_stats(), sectors=text['sectors'])
