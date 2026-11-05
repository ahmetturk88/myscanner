"""MyScanner Business: the monthly PDF report of a workspace (last 30 days).

For the manager: the average security status, what changed, look-alike names,
and a short list of what to do, then one section per verified domain with its
checks, its score week by week, its changes and its look-alikes. Everything
comes from data already stored by the monitoring runs; nothing is scanned here.
"""
import json
from datetime import datetime, timedelta, timezone

from reportlab.lib.units import cm
from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer

from services.pdf_report_generator import (COLORS, TONE_COLORS, SectionHeader, StatCards, SubHeader, checks_table, esc,
                                           get_styles, numbered_table)
from services.business_alerts import defang
from services.report_pdf import _closing, _document, _rows_table, _t

PERIOD = timedelta(days=30)

# What to do about each check state, worded for a manager. {domain} is filled in.
ACTIONS = {
    ('tls', 'bad'): 'Fix or renew the SSL certificate of {domain} now: visitors see a security warning.',
    ('tls', 'warn'): 'The SSL certificate of {domain} expires soon: make sure automatic renewal works.',
    ('registration', 'bad'): 'Renew the domain {domain} at your registrar today and turn on automatic renewal.',
    ('registration', 'warn'): 'The domain {domain} expires within a month: renew it and turn on automatic renewal.',
    ('dns', 'bad'): '{domain} has no address in DNS: check the DNS settings with your hosting company.',
    ('mail', 'bad'): 'Add SPF and DMARC records for {domain}, so nobody can send email in your name.',
    ('mail', 'warn'): 'Set the DMARC policy of {domain} to quarantine or reject, so fake emails are stopped.',
    ('blocklist', 'bad'): 'The server of {domain} is on an email blocklist: ask your hosting company to request removal.',
    ('reputation', 'bad'): '{domain} is on a threat list: have the site checked for malware and ask your hosting company for help.',
    ('ownership', 'warn'): 'Keep the _myscanner TXT record of {domain}: without it, monitoring pauses.',
}
UPTIME_GOAL = 99.0
UPTIME_ACTION = '{domain} was reachable only {percent}% of the time this month: ask your hosting company about the outages.'
UPTIME_ACTION_TR = '{domain} bu ay zamanın yalnızca %{percent} kadarında erişilebilirdi: kesintileri barındırma firmanıza sorun.'
LOOKALIKE_ACTION = 'Review the look-alike name {name}: warn your customers and report it to USOM and its registrar.'

WORDS_TR = {
    'MONTHLY SECURITY REPORT': 'AYLIK GÜVENLİK RAPORU',
    'Your domains and brand, last 30 days': 'Alan adlarınız ve markanız, son 30 gün',
    'AVERAGE STATUS': 'ORTALAMA DURUM', 'OUT OF 100': '100 ÜZERİNDEN', 'WORKSPACE': 'ÇALIŞMA ALANI',
    'GOOD': 'İYİ', 'NEEDS ATTENTION': 'DİKKAT GEREKİYOR', 'AT RISK': 'RİSKLİ', 'NOT ENOUGH DATA': 'YETERLİ VERİ YOK',
    'SUMMARY': 'ÖZET', 'The month at a glance': 'Bir bakışta bu ay',
    'CHANGES': 'DEĞİŞİKLİK', 'LOOK-ALIKES': 'TAKLİT AD', 'DOMAINS': 'ALAN ADI', 'average': 'ortalama',
    'in 30 days': '30 günde', 'open': 'açık', 'verified': 'doğrulandı',
    'What to do': 'Yapılacaklar', 'Nothing needs your attention this month.': 'Bu ay dikkat gerektiren bir şey yok.',
    'Current checks': 'Güncel kontroller', 'Status week by week': 'Hafta hafta durum',
    'WEEK': 'HAFTA', 'AVERAGE': 'ORTALAMA', 'LOWEST': 'EN DÜŞÜK', 'RUNS': 'KONTROL',
    'Changes': 'Değişiklikler', 'DATE': 'TARİH', 'CHANGE': 'DEĞİŞİKLİK',
    'Look-alike domains': 'Taklit alan adları', 'NAME': 'AD', 'RISK': 'RİSK', 'WEBSITE': 'WEB SİTESİ', 'FIRST SEEN': 'İLK GÖRÜLME',
    'Yes': 'Evet', 'No': 'Hayır', 'No changes in this period.': 'Bu dönemde değişiklik yok.',
    'No look-alike names are open.': 'Açık taklit alan adı yok.',
    'No monitoring run in this period yet.': 'Bu dönemde henüz kontrol yapılmadı.',
    'Daily automatic checks of a verified domain': 'Doğrulanmış bir alan adının günlük otomatik kontrolleri',
    'No verified domain yet': 'Henüz doğrulanmış alan adı yok',
    'Add a domain in the workspace and prove ownership; the next report then covers it.':
        'Panelde bir alan adı ekleyip sahipliğini kanıtlayın; sonraki rapor onu da kapsar.',
    'The status (0–100) starts at 100 and loses fixed points for each warning or problem in the daily checks of the domain: SSL certificate, domain expiry, DNS, email protection, blocklists and threat lists. It is withheld when fewer than three checks answered.':
        'Durum puanı (0–100) 100\'den başlar ve alan adının günlük kontrollerindeki her uyarı veya sorun için sabit puan kaybeder: SSL sertifikası, alan adı süresi, DNS, e-posta koruması, kara listeler ve tehdit listeleri. Üçten az kontrol yanıt verdiyse puan verilmez.',
    'This report is made only from public information collected by the daily checks; no attack test was run. A good status does not prove that a site has no weaknesses.':
        'Bu rapor yalnızca günlük kontrollerin topladığı herkese açık bilgilerden hazırlanır; saldırı testi yapılmadı. İyi bir durum, sitede hiç zayıflık olmadığını kanıtlamaz.',
    '80–100: the checks found no important problem.': '80–100: kontrollerde önemli bir sorun bulunmadı.',
    '50–79: something should be fixed soon.': '50–79: yakında düzeltilmesi gereken bir şey var.',
    'Below 50: a serious problem needs action now.': '50 altı: hemen ilgilenilmesi gereken ciddi bir sorun var.',
    'PERIOD': 'DÖNEM', 'STATUS': 'DURUM',
    'Availability (last 30 days)': 'Erişilebilirlik (son 30 gün)', 'average response': 'ortalama yanıt',
}
ACTIONS_TR = {
    ('tls', 'bad'): '{domain} SSL sertifikasını hemen düzeltin veya yenileyin: ziyaretçiler güvenlik uyarısı görüyor.',
    ('tls', 'warn'): '{domain} SSL sertifikasının süresi yakında doluyor: otomatik yenilemenin çalıştığından emin olun.',
    ('registration', 'bad'): '{domain} alan adını bugün kayıt firmanızdan yenileyin ve otomatik yenilemeyi açın.',
    ('registration', 'warn'): '{domain} alan adının süresi bir ay içinde doluyor: yenileyin ve otomatik yenilemeyi açın.',
    ('dns', 'bad'): '{domain} için DNS\'te adres yok: DNS ayarlarını hosting firmanızla kontrol edin.',
    ('mail', 'bad'): '{domain} için SPF ve DMARC kayıtları ekleyin; kimse sizin adınıza e-posta gönderemesin.',
    ('mail', 'warn'): '{domain} DMARC politikasını quarantine veya reject yapın; sahte e-postalar durdurulsun.',
    ('blocklist', 'bad'): '{domain} sunucusu bir e-posta kara listesinde: hosting firmanızdan listeden çıkarma talebi isteyin.',
    ('reputation', 'bad'): '{domain} bir tehdit listesinde: siteyi zararlı yazılım için kontrol ettirin ve hosting firmanızdan yardım isteyin.',
    ('ownership', 'warn'): '{domain} için _myscanner TXT kaydını silmeyin: kayıt olmadan izleme durur.',
}
LOOKALIKE_ACTION_TR = '{name} taklit adını inceleyin: müşterilerinizi uyarın, USOM\'a ve kayıt firmasına bildirin.'


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _words(lang):
    base = _t(lang)
    if lang != 'tr':
        return base
    return lambda text: WORDS_TR.get(text) or base(text) if isinstance(text, str) else text


def verdict(score):
    """(tone, label) for an average status."""
    if score is None:
        return 'unknown', 'NOT ENOUGH DATA'
    if score >= 80:
        return 'safe', 'GOOD'
    return ('caution', 'NEEDS ATTENTION') if score >= 50 else ('danger', 'AT RISK')


def domain_data(domain_row, text, since, until):
    """What the report shows for one verified domain within [since, until]."""
    from models import BusinessEvent, BusinessLookalike, BusinessSnapshot
    from services.business_monitor import check_rows, event_line
    snapshots = (BusinessSnapshot.query.filter(BusinessSnapshot.domain_id == domain_row.id, BusinessSnapshot.kind == 'daily',
                                               BusinessSnapshot.created_at >= since, BusinessSnapshot.created_at <= until)
                 .order_by(BusinessSnapshot.created_at, BusinessSnapshot.id).all())
    latest = snapshots[-1] if snapshots else None
    results = json.loads(latest.results) if latest else {}
    weeks = {}
    for snap in snapshots:
        start = (snap.created_at - timedelta(days=snap.created_at.weekday())).date()
        weeks.setdefault(start, []).append(snap.score)
    events = (BusinessEvent.query.filter(BusinessEvent.domain_id == domain_row.id, BusinessEvent.created_at >= since,
                                         BusinessEvent.created_at <= until)
              .order_by(BusinessEvent.created_at.desc(), BusinessEvent.id.desc()).all())
    lines = []
    for event in events:
        params = json.loads(event.params or '{}')
        if event.code.startswith('lookalike') and isinstance(params.get('name'), str):
            params['name'] = defang(params['name'])  # PDF viewers turn bare domain names into links
        line = event_line({'code': event.code, 'params': params}, text)
        if line:
            lines.append((event.created_at, event.severity, line))
    order = {'high': 0, 'medium': 1, 'low': 2}
    looks = BusinessLookalike.query.filter_by(domain_id=domain_row.id, status='open', resolves=True).all()
    looks.sort(key=lambda r: (order.get(r.risk, 3), r.name))
    scores = [s.score for s in snapshots if s.score is not None]
    from services.business_uptime import summary as uptime_summary
    return {'domain': domain_row.domain, 'results': results, 'rows': check_rows(results, text) if latest else [],
            'average': round(sum(scores) / len(scores)) if scores else None, 'runs': len(snapshots),
            'weeks': sorted(weeks.items()), 'events': lines, 'lookalikes': looks,
            'uptime': uptime_summary(domain_row.id, days=(until - since).days or 30, now=until)}


def actions_for(domains, lang):
    """The to-do list: one line per warning or problem, high-risk look-alikes after them."""
    table, look = (ACTIONS_TR, LOOKALIKE_ACTION_TR) if lang == 'tr' else (ACTIONS, LOOKALIKE_ACTION)
    todo = []
    for severity in ('bad', 'warn'):
        for data in domains:
            for check, item in data['results'].items():
                template = table.get((check, (item or {}).get('state')))
                if template and item.get('state') == severity:
                    todo.append(template.format(domain=data['domain']))
    uptime = UPTIME_ACTION_TR if lang == 'tr' else UPTIME_ACTION
    for data in domains:
        percent = (data.get('uptime') or {}).get('percent')
        if percent is not None and percent < UPTIME_GOAL:
            todo.append(uptime.format(domain=data['domain'], percent=_percent(percent, lang)))
    for data in domains:
        todo += [look.format(name=defang(row.name)) for row in data['lookalikes'] if row.risk == 'high']
    return todo[:12]


def _percent(value, lang):
    shown = f'{value:.2f}'.rstrip('0').rstrip('.')
    return shown.replace('.', ',') if lang == 'tr' else shown


def generate_business_report(workspace, lang='tr', now=None):
    """The monthly report of a workspace as a PDF (BytesIO)."""
    from models import BusinessDomain
    from services.business_page import CONTENT
    lang = 'tr' if lang == 'tr' else 'en'
    text, t = CONTENT[lang], _words(lang)
    now = now or _now()
    since = now - PERIOD
    rows = (BusinessDomain.query.filter(BusinessDomain.workspace_id == workspace.id, BusinessDomain.verified_at.isnot(None))
            .order_by(BusinessDomain.created_at).all())
    domains = [domain_data(row, text, since, now) for row in rows]
    averages = [d['average'] for d in domains if d['average'] is not None]
    average = round(sum(averages) / len(averages)) if averages else None
    tone, label = verdict(average)
    vcol = TONE_COLORS[tone]
    changes = sum(len(d['events']) for d in domains)
    looks = sum(len(d['lookalikes']) for d in domains)
    period = f'{since:%d.%m}–{now:%d.%m.%Y}'
    report_id = f'MYS-B-{now:%y%m%d}-{workspace.id}'
    ctx = {'t': t, 'title': 'MONTHLY SECURITY REPORT', 'subtitle': 'Your domains and brand, last 30 days',
           'meter': 'STATUS', 'meter_unit': 'OUT OF 100', 'scanned_label': 'PERIOD', 'target_label': 'WORKSPACE', 'incomplete': average is None,
           'trust': average or 0, 'score_display': str(average) if average is not None else 'N/A', 'vcolor': vcol,
           'vlabel': t(label), 'url': ', '.join(d['domain'] for d in domains) or str(workspace.name),
           'scanned': period, 'report_id': report_id, 'username': str(workspace.name)}
    st = get_styles()

    story = [SectionHeader(1, t('SUMMARY'), t('The month at a glance')), Spacer(1, 12),
             StatCards([(t('AVERAGE STATUS'), str(average) if average is not None else 'N/A', t('average'), vcol),
                        (t('CHANGES'), changes, t('in 30 days'), COLORS['accent']),
                        (t('LOOK-ALIKES'), looks, t('open'), COLORS['red'] if looks else COLORS['green']),
                        (t('DOMAINS'), len(domains), t('verified'), COLORS['accent'])]), Spacer(1, 16)]
    todo = actions_for(domains, lang)
    if todo:
        story += [SubHeader(t('What to do'), COLORS['accent'], len(todo)), numbered_table(todo), Spacer(1, 10)]
    else:
        story += [Paragraph(esc(t('Nothing needs your attention this month.')), st['body'])]
    if not domains:
        story += [Spacer(1, 10), Paragraph(esc(t('No verified domain yet')), st['body']),
                  Paragraph(esc(t('Add a domain in the workspace and prove ownership; the next report then covers it.')), st['muted'])]

    for number, data in enumerate(domains, start=2):
        story += [CondPageBreak(9 * cm), Spacer(1, 22),
                  SectionHeader(number, data['domain'].upper(), t('Daily automatic checks of a verified domain')), Spacer(1, 12)]
        up = data.get('uptime') or {}
        if up.get('percent') is not None:
            line = t('Availability (last 30 days)') + ': ' + ('%' + _percent(up['percent'], lang) if lang == 'tr' else _percent(up['percent'], lang) + '%')
            if up.get('avg_ms') is not None:
                line += f" · {t('average response')} {up['avg_ms']} ms"
            story += [Paragraph(esc(line), st['body']), Spacer(1, 10)]
        if data['rows']:
            checks = [{'name': name, 'state': state, 'result': value} for name, state, value in data['rows']]
            story += [KeepTogether([SubHeader(t('Current checks'), COLORS['accent']), checks_table(checks, t)]), Spacer(1, 16)]
        else:
            story += [Paragraph(esc(t('No monitoring run in this period yet.')), st['muted']), Spacer(1, 12)]
        if data['weeks']:
            weekly = []
            for start, scores in data['weeks']:
                known = [s for s in scores if s is not None]
                weekly.append((start.strftime('%d.%m.%Y'), str(round(sum(known) / len(known))) if known else '—',
                               str(min(known)) if known else '—', str(len(scores))))
            story += [KeepTogether([SubHeader(t('Status week by week'), COLORS['accent']),
                                    _rows_table(('WEEK', 'AVERAGE', 'LOWEST', 'RUNS'), weekly, (0.34, 0.22, 0.22, 0.22), t)]),
                      Spacer(1, 16)]
        story.append(SubHeader(t('Changes'), COLORS['accent'], len(data['events']) or None))
        if data['events']:
            story += [_rows_table(('DATE', 'CHANGE'), [(when.strftime('%d.%m.%Y'), line) for when, _, line in data['events'][:25]],
                                  (0.2, 0.8), t), Spacer(1, 16)]
        else:
            story += [Paragraph(esc(t('No changes in this period.')), st['muted']), Spacer(1, 16)]
        story.append(SubHeader(t('Look-alike domains'), COLORS['red'] if data['lookalikes'] else COLORS['accent'],
                               len(data['lookalikes']) or None))
        if data['lookalikes']:
            story.append(_rows_table(('NAME', 'RISK', 'WEBSITE', 'FIRST SEEN'),
                                     [(defang(row.name), text['risk_names'].get(row.risk, row.risk), t('Yes') if row.live else t('No'),
                                       row.first_seen.strftime('%d.%m.%Y')) for row in data['lookalikes'][:15]],
                                     (0.44, 0.18, 0.16, 0.22), t))
        else:
            story.append(Paragraph(esc(t('No look-alike names are open.')), st['muted']))

    legend = [('safe', 'GOOD', '80–100: the checks found no important problem.'),
              ('caution', 'NEEDS ATTENTION', '50–79: something should be fixed soon.'),
              ('danger', 'AT RISK', 'Below 50: a serious problem needs action now.')]
    story += _closing(len(domains) + 2, t,
                      'The status (0–100) starts at 100 and loses fixed points for each warning or problem in the daily checks of the domain: SSL certificate, domain expiry, DNS, email protection, blocklists and threat lists. It is withheld when fewer than three checks answered.',
                      'This report is made only from public information collected by the daily checks; no attack test was run. A good status does not prove that a site has no weaknesses.',
                      legend, now)
    return _document(ctx, story, f'MyScanner {t("MONTHLY SECURITY REPORT")} {report_id}')


def reports_due(now=None):
    """Workspaces whose monthly report email is due: days 1–3 of the month, in daytime, once a month."""
    from models import BusinessWorkspace
    from services.business_alerts import DIGEST_HOURS_UTC
    now = now or _now()
    if now.day > 3 or now.hour not in DIGEST_HOURS_UTC:
        return []
    month = now.strftime('%Y-%m')
    return BusinessWorkspace.query.filter((BusinessWorkspace.last_report_month.is_(None))
                                          | (BusinessWorkspace.last_report_month != month)).all()


def send_monthly(workspace, sender=None, now=None):
    """Tell the team the monthly report is ready (a link, no attachment). Returns how many emails went out."""
    from extensions import db
    from models import BusinessDomain
    from services.business_alerts import _panel_url, _recipients, _send_all
    from services.business_page import CONTENT
    from services.email_templates import action_email
    now = now or _now()
    month = now.strftime('%Y-%m')
    if not BusinessDomain.query.filter(BusinessDomain.workspace_id == workspace.id, BusinessDomain.verified_at.isnot(None)).count():
        workspace.last_report_month = month  # nothing to report on: try again next month
        db.session.commit()
        return 0
    words = (CONTENT.get(workspace.alert_lang) or CONTENT['tr'])['report_mail']
    link = _panel_url() + '#report'
    html, plain = action_email(words['title'], words['greeting'], words['paragraphs'], words['button'], link, words['note'])
    sent = _send_all(_recipients(workspace), words['subject'], plain, html, sender)
    if sent:
        workspace.last_report_month = month
        db.session.commit()
    return sent
