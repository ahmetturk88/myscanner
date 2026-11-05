"""MyScanner Business alerts: an email right after a serious change, and one daily digest of everything else.

An event is emailed once (notified_at). Serious changes (anything "bad", and the
quiet ones attackers cause: changed DNS, registrar or email settings, a missing
ownership record) go out right after the run that found them, if the workspace
wants instant alerts. Everything else waits for the daily digest, sent between
09:00 and 21:00 Turkish time, only when something happened. Alerts go to the
owner and the accepted team members who want them (verified emails only), in the
workspace's language.
"""
import json
import os
from datetime import datetime, timedelta, timezone
from html import escape

from extensions import db

URGENT_CODES = {'dns_changed', 'registrar_changed', 'mail_changed', 'proof_missing', 'proof_lost',
                'lookalike_found', 'lookalike_live', 'site_down', 'site_up'}
DIGEST_EVERY = timedelta(hours=23)
DIGEST_HOURS_UTC = range(6, 18)  # 09:00 to 20:59 in Türkiye (UTC+3)
TONES = {'bad': '#fb7185', 'warn': '#fbbf24', 'good': '#4ade80', 'info': '#77dcff'}
ORDER = {'bad': 0, 'warn': 1, 'good': 2, 'info': 3}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_urgent(event):
    return event.severity == 'bad' or event.code in URGENT_CODES


def _recipients(workspace):
    """The owner and the teammates who accepted and want alerts; verified addresses only."""
    from models import BusinessMember, User
    people = [db.session.get(User, workspace.owner_id)]
    for member in BusinessMember.query.filter(BusinessMember.workspace_id == workspace.id, BusinessMember.alerts.is_(True),
                                              BusinessMember.accepted_at.isnot(None)).all():
        people.append(db.session.get(User, member.user_id) if member.user_id else None)
    seen, emails = set(), []
    for person in people:
        email = (getattr(person, 'email', '') or '').strip()
        if email and getattr(person, 'is_verified', False) is True and email.lower() not in seen:
            seen.add(email.lower())
            emails.append(email)
    return emails


def _send_all(recipients, subject, plain, html, sender):
    return sum(1 for to in recipients if _send(to, subject, plain, html, sender))


def _send(to, subject, text, html, sender=None):
    if sender is None:
        from app import send_email as sender
    return sender(to, subject, text, html)


def _panel_url():
    return os.getenv('BASE_URL', 'https://myscanners.com').rstrip('/') + '/isletme/panel'


def build_email(text, workspace_name, groups, kind):
    """(subject, plain text, html) for [(domain, score, [(severity, line, when)])]."""
    from services.business_page import CONTENT  # noqa: F401  (text is one of its languages)
    words = text['alert_mail']
    count = sum(len(items) for _, _, items in groups)
    if kind == 'instant':
        subject = words['instant_subject'].format(domain=groups[0][0])
        heading = words['instant_heading']
    else:
        subject = words['digest_subject'].format(count=count)
        heading = words['digest_heading']
    safe = lambda value: escape(str(value), quote=True)
    blocks, lines = [], [heading, '']
    for domain, score, items in groups:
        rows = ''.join(
            f'<tr><td style="padding:10px 12px;border-left:3px solid {TONES.get(sev, "#77dcff")};background:#0b1626;'
            f'color:#dbe8f6;font-size:14.5px;line-height:1.55">{safe(line)}'
            f'<div style="margin-top:4px;color:#6f86a0;font:12px Consolas,monospace">{safe(when.strftime("%d.%m.%Y %H:%M"))} UTC</div></td></tr>'
            f'<tr><td style="height:8px"></td></tr>'
            for sev, line, when in items)
        score_text = words['score'].format(score=score) if score is not None else ''
        blocks.append(f'<h2 style="margin:22px 0 10px;font:700 18px Arial,sans-serif;color:#eef6ff">{safe(domain)}'
                      f'<span style="margin-left:10px;font:600 13px Arial,sans-serif;color:#8ea6c0">{safe(score_text)}</span></h2>'
                      f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{rows}</table>')
        lines += [f'{domain} {score_text}'.strip()] + [f'- {line}' for _, line, _ in items] + ['']
    link = _panel_url()
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#070d18">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#070d18;padding:32px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#0e1828;border:1px solid #213650;border-radius:20px;overflow:hidden;font-family:Arial,Helvetica,sans-serif">
<tr><td style="padding:24px 30px;background:linear-gradient(135deg,#123a55,#1a1240);border-bottom:1px solid #213650">
<span style="font:800 22px Arial,sans-serif;color:#eef6ff">My<span style="color:#77dcff">Scanner</span></span>
<span style="display:block;margin-top:4px;font:11px Consolas,monospace;letter-spacing:2px;color:#8ea6c0">{safe(words['brand'])} · {safe(workspace_name)}</span></td></tr>
<tr><td style="padding:30px 30px 26px">
<h1 style="margin:0 0 8px;font:700 22px Arial,sans-serif;color:#eef6ff">{safe(heading)}</h1>
<p style="margin:0;color:#a9bbd2;font-size:15px;line-height:1.7">{safe(words['lead'])}</p>
{''.join(blocks)}
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:26px 0 6px"><tr><td style="border-radius:12px;background:#77dcff">
<a href="{safe(link)}" style="display:inline-block;padding:13px 26px;font:700 15px Arial,sans-serif;color:#05202d;text-decoration:none;border-radius:12px">{safe(words['button'])}</a></td></tr></table>
</td></tr>
<tr><td style="padding:16px 30px;border-top:1px solid #1b2d42;color:#6f86a0;font-size:12px;line-height:1.6">{safe(words['footer'])}<br>
MyScanner · <a href="mailto:info@myscanners.com" style="color:#8fd9f2">info@myscanners.com</a></td></tr>
</table></td></tr></table></body></html>"""
    lines += [f"{words['button']}: {link}", '', words['footer'], '— MyScanner']
    return subject, '\n'.join(lines), html


def defang(name):
    """magazam-giris[.]com: mail apps turn bare domain names into links; an imitation must never become one."""
    return str(name).replace('.', '[.]')


def _groups(events, text):
    from models import BusinessDomain
    from services.business_monitor import event_line, latest_snapshot
    by_domain = {}
    for event in sorted(events, key=lambda e: (ORDER.get(e.severity, 9), e.created_at)):
        params = json.loads(event.params or '{}')
        if event.code.startswith('lookalike') and isinstance(params.get('name'), str):
            params['name'] = defang(params['name'])
        line = event_line({'code': event.code, 'params': params}, text)
        if line:
            by_domain.setdefault(event.domain_id, []).append((event.severity, line, event.created_at))
    groups = []
    for domain_id, items in by_domain.items():
        domain = db.session.get(BusinessDomain, domain_id)
        snapshot = latest_snapshot(domain_id)
        groups.append((domain.domain, snapshot.score if snapshot else None, items))
    return groups


def send_instant(domain_row, sender=None, now=None):
    """Email the not-yet-sent urgent events of one domain. Returns how many events were sent."""
    from models import BusinessEvent, BusinessWorkspace
    from services.business_page import CONTENT
    workspace = db.session.get(BusinessWorkspace, domain_row.workspace_id)
    if workspace is None or not workspace.instant_alerts:
        return 0
    to = _recipients(workspace)
    pending = [e for e in BusinessEvent.query.filter_by(domain_id=domain_row.id, notified_at=None).all() if is_urgent(e)]
    if not to or not pending:
        return 0
    text = CONTENT.get(workspace.alert_lang) or CONTENT['tr']
    groups = _groups(pending, text)
    if not groups:
        return 0
    subject, plain, html = build_email(text, workspace.name, groups, 'instant')
    if not _send_all(to, subject, plain, html, sender):
        return 0  # left unsent: the digest or the next run tries again
    stamp = now or _now()
    for event in pending:
        event.notified_at = stamp
    db.session.commit()
    return len(pending)


def digests_due(now=None):
    from models import BusinessWorkspace
    now = now or _now()
    if now.hour not in DIGEST_HOURS_UTC:
        return []
    return BusinessWorkspace.query.filter(BusinessWorkspace.daily_digest.is_(True)).filter(
        (BusinessWorkspace.last_digest_at.is_(None)) | (BusinessWorkspace.last_digest_at <= now - DIGEST_EVERY)).all()


def send_digest(workspace, sender=None, now=None):
    """One email with every event not sent yet (last 7 days). Nothing to say means no email."""
    from models import BusinessDomain, BusinessEvent
    from services.business_page import CONTENT
    now = now or _now()
    to = _recipients(workspace)
    domain_ids = [d.id for d in BusinessDomain.query.filter_by(workspace_id=workspace.id).all()]
    if not to or not domain_ids:
        return 0
    pending = BusinessEvent.query.filter(BusinessEvent.domain_id.in_(domain_ids), BusinessEvent.notified_at.is_(None),
                                         BusinessEvent.created_at >= now - timedelta(days=7)).all()
    if not pending:
        return 0
    text = CONTENT.get(workspace.alert_lang) or CONTENT['tr']
    groups = _groups(pending, text)
    if not groups:
        return 0
    subject, plain, html = build_email(text, workspace.name, groups, 'digest')
    if not _send_all(to, subject, plain, html, sender):
        return 0
    for event in pending:
        event.notified_at = now
    workspace.last_digest_at = now
    db.session.commit()
    return len(pending)
