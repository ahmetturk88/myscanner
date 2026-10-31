"""Website and email reports as PDFs, in the URL report's design.

Both start from the plain summary the page showed (same verdict, sentences, actions
and checks, translated the same way), then give the technical evidence behind it.
Nothing is looked up again: the input is the signed result from report_receipts.
"""
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlsplit

from reportlab.lib.units import cm
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)

from services.pdf_report_generator import (COLORS, CW, MARGIN, PAGE_H, TONE_COLORS, A4, ScoreBars, SectionHeader,
                                           StatCards, SubHeader, checks_table, draw_content_page, draw_cover, esc,
                                           flag_table, get_styles, hx, kv_table, mix, numbered_table, reasons_table,
                                           translator, verdict_banner)

# How each kind of check result counts in an area score. Descriptive rows (where it is hosted,
# how many pages were read) say what was seen, not how good it is, so they don't count.
STATE_POINTS = {'ok': 100, 'info': 75, 'warn': 35, 'bad': 0}
DESCRIPTIVE = {'Hosted in', 'Pages read', 'Redirects'}
SITE_AREAS = [
    ('Reputation and trust', ('Threat lists', 'Copies a brand’s name', 'Domain age', 'Page content', 'Links to other sites',
                              'Downloads', 'Online shop')),
    ('Connection security', ('Secure connection', 'Password forms', 'Redirects')),
    ('Site setup', ('Email in its name', 'Software', 'Scripts from other sites', 'Hosted in')),
    ('Privacy', ('Privacy notice',)),
]
SITE_LEGEND = [
    ('danger', 'DANGEROUS', 'Google lists the site or its pages, or a download on it carries malware.'),
    ('caution', 'BE CAREFUL', 'Warning signs on the site, its links or its setup. Don’t enter passwords or card details until you are sure.'),
    ('unknown', 'NOT SURE', 'Some checks couldn’t run, so we can’t call it safe.'),
    ('safe', 'NO WARNING SIGNS', 'No warning signs in the checks we ran. This is not a guarantee of safety.'),
]
EMAIL_LEGEND = [
    ('danger', 'DANGEROUS', 'A threat source flags the domain, or it is a new domain made to look like a known company.'),
    ('danger', 'NOT A REAL ADDRESS', 'The domain doesn’t exist or can’t receive email.'),
    ('caution', 'BE CAREFUL', 'Signs that need care: a copied name, weak sender protection or a blocklist entry.'),
    ('unknown', 'NOT SURE', 'Some checks couldn’t run, so we can’t call it safe.'),
    ('safe', 'NO WARNING SIGNS', 'No warning signs found. This doesn’t prove who is behind the address.'),
]
HEADER_STATES = {'present': ('Present', 'good'), 'alternative_present': ('Covered by CSP', 'good'), 'missing': ('Not set', 'info'),
                 'not_applicable': ('Not applicable', None), 'unavailable': ('Not checked', None)}

PDF_TR = {
    'WEBSITE SECURITY REPORT': 'WEB SİTESİ GÜVENLİK RAPORU',
    'Hidden behind a CDN': 'Bir CDN arkasında gizli', 'Pages that didn’t answer': 'Yanıt vermeyen sayfalar',
    'A read-only check of a whole website': 'Bir web sitesinin tamamının salt okunur kontrolü',
    'EMAIL ADDRESS REPORT': 'E-POSTA ADRESİ RAPORU',
    'An evidence-based check of one email address': 'Tek bir e-posta adresinin kanıta dayalı kontrolü',
    'CHECKED WEBSITE': 'KONTROL EDİLEN WEB SİTESİ', 'CHECKED ADDRESS': 'KONTROL EDİLEN ADRES',
    'CHECKS PASSED': 'GEÇEN KONTROLLER', 'PERCENT': 'YÜZDE', 'passed': 'geçti',
    'SCORE BY AREA': 'ALANLARA GÖRE PUAN', 'How each part of the site did': 'Sitenin her bölümü nasıl çıktı',
    'Reputation and trust': 'İtibar ve güven', 'Connection security': 'Bağlantı güvenliği', 'Site setup': 'Site kurulumu',
    'Privacy': 'Gizlilik', 'checks': 'kontrol', 'No checks in this area': 'Bu alanda kontrol yok',
    'Area scores summarise the checks above: a fine check counts fully, a note counts most, a warning little. They are not a probability.':
        'Alan puanları yukarıdaki kontrolleri özetler: sorunsuz bir kontrol tam, bir not büyük ölçüde, bir uyarı az sayılır. Bir olasılık değildir.',
    'Address checked': 'Kontrol edilen adres', 'Final address': 'Son adres', 'HTTP status': 'HTTP durumu',
    'Redirect trail': 'Yönlendirme izi', 'Certificate': 'Sertifika', 'Issuer': 'Yayıncı', 'Valid until': 'Geçerlilik sonu',
    'Days left': 'Kalan gün', 'Protocol': 'Protokol', 'Names on the certificate': 'Sertifikadaki adlar',
    'Verified': 'Doğrulandı', 'Not verified': 'Doğrulanmadı',
    'Browser security headers': 'Tarayıcı güvenlik başlıkları', 'Present': 'Var', 'Covered by CSP': 'CSP ile karşılanıyor',
    'Not set': 'Ayarlanmamış', 'Not applicable': 'Geçerli değil', 'Not checked': 'Kontrol edilmedi',
    'Domain and hosting': 'Alan adı ve barındırma', 'Domain': 'Alan adı', 'Registered': 'Kayıt tarihi', 'Domain age': 'Alan adı yaşı',
    'days': 'gün', 'Not published': 'Yayımlanmamış', 'Server IP': 'Sunucu IP', 'Country': 'Ülke', 'Network': 'Ağ',
    'Name servers': 'Ad sunucuları', 'Mail servers': 'E-posta sunucuları',
    'Email sent in its name': 'Onun adına gönderilen e-posta', 'SPF record': 'SPF kaydı', 'DMARC policy': 'DMARC politikası',
    'Others can send email as this domain': 'Başkaları bu alan adıymış gibi e-posta gönderebilir', 'Protected': 'Korunuyor',
    'Not protected': 'Korunmuyor', 'missing': 'yok', 'invalid': 'geçersiz',
    'Software and scripts': 'Yazılım ve betikler', 'Version not shown': 'Sürüm gösterilmiyor', 'Old version': 'Eski sürüm',
    'Scripts from other sites': 'Diğer sitelerden betikler', 'Parts loaded over http://': 'http:// üzerinden yüklenen bölümler',
    'Cookies': 'Çerezler', 'Pages read': 'Okunan sayfalar', 'PAGE': 'SAYFA', 'TITLE': 'BAŞLIK',
    'read': 'okundu', 'not_a_page': 'sayfa değil', 'left_site': 'siteden çıktı', 'unavailable': 'alınamadı', 'blocked': 'engellendi',
    'Links and downloads': 'Bağlantılar ve indirmeler', 'Outside sites linked': 'Bağlantı verilen dış siteler',
    'Listed by Google': 'Google listesinde', 'Copies a brand': 'Bir markayı taklit ediyor', 'Betting site': 'Bahis sitesi',
    'Download': 'İndirme', 'Antivirus': 'Antivirüs', 'clean': 'temiz', 'found': 'bulundu',
    'Online shop details': 'Çevrim içi mağaza bilgileri', 'Phone': 'Telefon', 'Address': 'Adres', 'Company number': 'Şirket numarası',
    'Return policy': 'İade politikası', 'Card payment': 'Kartla ödeme', 'Bank transfer only': 'Yalnızca havale',
    'WhatsApp only': 'Yalnızca WhatsApp', 'Big discounts': 'Büyük indirimler', 'Found': 'Bulundu', 'Not found': 'Bulunamadı',
    'Privacy notice (KVKK)': 'Gizlilik / KVKK metni', 'All observations': 'Tüm gözlemler',
    'Checks that couldn’t run': 'Çalıştırılamayan kontroller',
    'This report reflects the website at the time of the scan. We read its pages like a visitor: no forms were sent, no scripts were run and nothing was attacked. It is information, not a guarantee of safety.':
        'Bu rapor web sitesinin tarama anındaki durumunu yansıtır. Sayfalarını bir ziyaretçi gibi okuduk: form gönderilmedi, betik çalıştırılmadı ve hiçbir şeye saldırılmadı. Bu bir bilgilendirmedir, güvenlik garantisi değildir.',
    'The verdict comes from MyScanner’s checks of the site: Google Web Risk, the address and domain, the pages we read, the sites they link to, downloads scanned with antivirus, and how the site is set up.':
        'Sonuç, MyScanner’ın siteye yaptığı kontrollerden gelir: Google Web Risk, adres ve alan adı, okuduğumuz sayfalar, bağlantı verdikleri siteler, antivirüsle taranan indirmeler ve sitenin nasıl kurulduğu.',
    'NO WARNING SIGNS': 'UYARI İŞARETİ YOK', 'NOT A REAL ADDRESS': 'GERÇEK BİR ADRES DEĞİL',
    'Google lists the site or its pages, or a download on it carries malware.':
        'Google siteyi ya da sayfalarını listeliyor veya sitedeki bir indirme zararlı yazılım içeriyor.',
    'Warning signs on the site, its links or its setup. Don’t enter passwords or card details until you are sure.':
        'Sitede, bağlantılarında ya da kurulumunda uyarı işaretleri var. Emin olana kadar şifre ya da kart bilgisi girme.',
    'A threat source flags the domain, or it is a new domain made to look like a known company.':
        'Bir tehdit kaynağı alan adını işaretliyor ya da tanınmış bir şirkete benzetilmiş yeni bir alan adı.',
    'The domain doesn’t exist or can’t receive email.': 'Alan adı yok ya da e-posta alamıyor.',
    'Signs that need care: a copied name, weak sender protection or a blocklist entry.':
        'Dikkat gerektiren işaretler: taklit bir ad, zayıf gönderen koruması ya da bir kara liste kaydı.',
    'No warning signs found. This doesn’t prove who is behind the address.': 'Uyarı işareti bulunamadı. Bu, adresin arkasında kimin olduğunu kanıtlamaz.',
    'Email address': 'E-posta adresi', 'Checked': 'Kontrol zamanı', 'Mail routing': 'E-posta yönlendirme', 'Accepts email': 'E-posta kabul ediyor',
    'Sender authentication': 'Gönderen doğrulama', 'SPF valid': 'SPF geçerli', 'DMARC record': 'DMARC kaydı',
    'Reputation and identity': 'İtibar ve kimlik', 'Blocklists': 'Kara listeler', 'Listed on': 'Listede olduğu yer',
    'Clean on': 'Temiz olduğu yer', 'Google Web Risk': 'Google Web Risk', 'Registrar': 'Kayıt şirketi',
    'Disposable address': 'Tek kullanımlık adres', 'Free email provider': 'Ücretsiz e-posta sağlayıcısı',
    'Mailbox probe': 'Posta kutusu yoklaması', 'Not requested': 'İstenmedi', 'Accepted': 'Kabul edildi', 'Rejected': 'Reddedildi',
    'Not listed': 'Listede değil', 'Listed': 'Listede', 'Evidence by category': 'Kategoriye göre kanıtlar', 'Findings': 'Bulgular',
    'Not checked here': 'Burada kontrol edilmeyenler', 'Yes': 'Evet', 'No': 'Hayır', 'None': 'Yok', 'Valid': 'Geçerli', 'Invalid': 'Geçersiz',
    'The verdict comes from MyScanner’s checks of the address: its domain and mail servers, sender authentication (SPF and DMARC), blocklists, Google Web Risk, the domain’s age and names that copy a company. The evidence index (0–100) summarises the deductions; it is not a probability.':
        'Sonuç, MyScanner’ın adrese yaptığı kontrollerden gelir: alan adı ve e-posta sunucuları, gönderen doğrulama (SPF ve DMARC), kara listeler, Google Web Risk, alan adının yaşı ve bir şirketi taklit eden adlar. Kanıt endeksi (0–100) kesintileri özetler; bir olasılık değildir.',
    'This report reflects the address at the time of the check. No email was sent. A clean result says nothing about who owns the address.':
        'Bu rapor adresin kontrol anındaki durumunu yansıtır. Hiç e-posta gönderilmedi. Temiz bir sonuç adresin sahibinin kim olduğu hakkında bir şey söylemez.',
}


def _t(lang):
    base = translator(lang)
    if lang != 'tr':
        return base
    return lambda text: PDF_TR.get(text) or base(text) if isinstance(text, str) else text


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _plain(report, lang, build):
    from services.report_i18n import translate_plain
    plain = report.get('plain') if isinstance(report.get('plain'), dict) else build(report)
    return translate_plain(plain, lang) if lang != 'en' else plain


def _when(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M UTC')
    except ValueError:
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _report_id(prefix, value):
    """MYS-W-261030-0915: the kind of report and when the scan ran (fits the cover card)."""
    try:
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00')).strftime('%y%m%d-%H%M')
    except ValueError:
        stamp = datetime.now(timezone.utc).strftime('%y%m%d-%H%M')
    return f'{prefix}-{stamp}'


def _age(days, lang):
    from services.report_i18n import translate
    from services.url_report_view import age_text
    return translate(age_text(days), lang)


def _document(ctx, story, title):
    buffer = BytesIO()
    doc = BaseDocTemplate(buffer, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=2 * cm, bottomMargin=2 * cm,
                          title=title, author='MyScanner', subject=ctx['t'](ctx['title']), creator='MyScanner')
    cover = Frame(MARGIN, PAGE_H / 2, CW, 20, id='cover', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body = Frame(MARGIN, 2 * cm, CW, PAGE_H - 2 * cm - 64, id='body', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id='cover', frames=[cover], onPage=lambda c, d: draw_cover(c, ctx)),
                          PageTemplate(id='content', frames=[body], onPage=lambda c, d: draw_content_page(c, d, ctx))])
    doc.build([Spacer(1, 1), NextPageTemplate('content'), PageBreak()] + story)
    buffer.seek(0)
    return buffer


def _summary(plain, t, first_card, tone):
    """Section 1: the page's own verdict, reasons, actions and checks."""
    vcol = TONE_COLORS[tone]
    story = [SectionHeader(1, t('SUMMARY'), t('What this report means for you')), Spacer(1, 12),
             verdict_banner(vcol, plain.get('headline') or plain.get('label') or '', plain.get('summary') or ''), Spacer(1, 12)]
    checks = [c for c in _list(plain.get('checks')) if isinstance(c, dict)]
    count = lambda *states: sum(c.get('state') in states for c in checks)  # noqa: E731
    story += [StatCards([first_card,
                         (t('WARNINGS'), count('bad', 'warn'), t('in the checks'),
                          COLORS['red'] if count('bad') else COLORS['yellow'] if count('warn') else COLORS['green']),
                         (t('FINE'), count('ok'), f'{len(checks)} {t("checks")}', COLORS['green']),
                         (t('NOT CHECKED'), count('na'), t('checks'), COLORS['muted'])]), Spacer(1, 16)]
    reasons = [r for r in _list(plain.get('reasons')) if isinstance(r, dict)]
    if reasons:
        story += [SubHeader(plain.get('why_title') or t('Why we think so'), vcol, len(reasons)), reasons_table(reasons), Spacer(1, 16)]
    actions = [a for a in _list(plain.get('actions')) if isinstance(a, str)]
    if actions:
        story += [SubHeader(t('Good to know' if tone == 'safe' else 'What to do'), COLORS['accent']), numbered_table(actions), Spacer(1, 16)]
    if checks:
        story.append(KeepTogether([SubHeader(t('What we checked'), COLORS['accent']), checks_table(checks, t)]))
    return story


def _section(number, title, subtitle, t):
    return [CondPageBreak(9 * cm), Spacer(1, 22), SectionHeader(number, t(title), t(subtitle)), Spacer(1, 12)]


def _table(title, rows, t):
    rows = [(label, str(value), state) for label, value, state in rows if value not in (None, '')]
    return [KeepTogether([SubHeader(t(title), COLORS['accent']), kv_table(rows, t)]), Spacer(1, 16)] if rows else []


def _legend(rows, t):
    st = get_styles()
    data = [[Paragraph(t('VERDICT'), st['th_c']), Paragraph(t('MEANING'), st['th'])]]
    style = [('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']), ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
             ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
             ('LEFTPADDING', (0, 0), (-1, -1), 11), ('BACKGROUND', (0, 0), (-1, 0), mix(COLORS['accent'], COLORS['dark_bg'], 0.16)),
             ('LINEBELOW', (0, 0), (-1, 0), 1.2, COLORS['accent']), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['card_bg'], COLORS['surface']])]
    for i, (tone, label, meaning) in enumerate(rows, start=1):
        col = TONE_COLORS[tone]
        data.append([Paragraph(f'<font color="{hx(col)}">{esc(t(label))}</font>', st['status']), Paragraph(esc(t(meaning)), st['cell'])])
        style.append(('BACKGROUND', (0, i), (0, i), mix(col, COLORS['card_bg'], 0.14)))
    table = Table(data, colWidths=[0.27 * CW, 0.73 * CW])
    table.setStyle(TableStyle(style))
    return table


def _closing(number, t, intro, limits, legend, now):
    st = get_styles()
    footer = Table([[[Paragraph(esc(t('Report generated by MyScanner')), st['foot1']),
                      Paragraph('https://myscanners.com  |  info@myscanners.com', st['foot2']),
                      Paragraph(f'(c) {now.year} MyScanner. {esc(t("All rights reserved."))}', st['foot3'])]]], colWidths=[CW])
    footer.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), COLORS['card_bg']), ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
                                ('LINEABOVE', (0, 0), (-1, 0), 2, COLORS['accent']), ('TOPPADDING', (0, 0), (-1, -1), 14),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 14)]))
    # The whole closing section moves as one block, so no page is left with only the footer.
    return [CondPageBreak(9 * cm), Spacer(1, 22),
            KeepTogether([SectionHeader(number, t('HOW TO READ THIS REPORT'), t('Verdicts and limits')), Spacer(1, 12),
                          Paragraph(esc(t(intro)), st['body']), Spacer(1, 10), _legend(legend, t), Spacer(1, 12),
                          Paragraph(esc(t(limits)), st['muted']), Spacer(1, 22), footer])]


def _rows_table(header, rows, widths, t):
    """A plain multi-column table: header labels, then rows of text."""
    st = get_styles()
    data = [[Paragraph(t(h), st['th']) for h in header]]
    data += [[Paragraph(esc(cell), st['cell']) for cell in row] for row in rows]
    table = Table(data, colWidths=[w * CW for w in widths], repeatRows=1)
    table.setStyle(TableStyle([('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']), ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
                               ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('TOPPADDING', (0, 0), (-1, -1), 6),
                               ('BOTTOMPADDING', (0, 0), (-1, -1), 6), ('LEFTPADDING', (0, 0), (-1, -1), 9),
                               ('BACKGROUND', (0, 0), (-1, 0), mix(COLORS['accent'], COLORS['dark_bg'], 0.16)),
                               ('LINEBELOW', (0, 0), (-1, 0), 1.2, COLORS['accent']),
                               ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['card_bg'], COLORS['surface']])]))
    return table


def area_scores(checks):
    """[(area, score or None, how many checks)] from the plain checks, by SITE_AREAS."""
    states = {c.get('name'): c.get('state') for c in checks if isinstance(c, dict)}
    rows = []
    for area, names in SITE_AREAS:
        points = [STATE_POINTS[states[n]] for n in names if n not in DESCRIPTIVE and states.get(n) in STATE_POINTS]
        rows.append((area, round(sum(points) / len(points)) if points else None, len(points)))
    return rows


def passed_percent(checks):
    counted = [c for c in checks if isinstance(c, dict) and c.get('state') in STATE_POINTS and c.get('name') not in DESCRIPTIVE]
    return round(100 * sum(c.get('state') == 'ok' for c in counted) / len(counted)) if counted else None


def generate_site_report(report, username, lang='en'):
    """The website check as a PDF. report: the signed site result (see report_receipts)."""
    from services.simple_report_view import plain_web_report
    report = _dict(report)
    lang = 'tr' if lang == 'tr' else 'en'
    t = _t(lang)
    plain = _plain(report, lang, lambda r: plain_web_report(r, source='site'))
    english = _dict(report.get('plain')) if isinstance(report.get('plain'), dict) else plain_web_report(report, source='site')
    tone = plain.get('tone') if plain.get('tone') in TONE_COLORS else 'unknown'
    vcol = TONE_COLORS[tone]
    checks_en = [c for c in _list(english.get('checks')) if isinstance(c, dict)]
    passed = passed_percent(checks_en)
    url = str(report.get('url') or report.get('domain') or '')
    now = datetime.now(timezone.utc)
    scanned = _when(report.get('analyzed_at'))
    report_id = _report_id('MYS-W', report.get('analyzed_at') or now.isoformat())
    ctx = {'t': t, 'title': 'WEBSITE SECURITY REPORT', 'subtitle': 'A read-only check of a whole website', 'meter': 'CHECKS PASSED',
           'meter_unit': 'PERCENT', 'target_label': 'CHECKED WEBSITE', 'incomplete': passed is None, 'trust': passed or 0,
           'score_display': f'{passed}' if passed is not None else 'N/A', 'vcolor': vcol, 'vlabel': plain.get('label') or '',
           'url': url, 'scanned': scanned, 'report_id': report_id, 'username': str(username or 'N/A')}

    story = _summary(plain, t, (t('CHECKS PASSED'), f'{passed}%' if passed is not None else 'N/A', t('passed'), vcol), tone)

    # 2. Score by area
    st = get_styles()
    bars = [(t(area), score, f'{n} {t("checks")}' if n else t('No checks in this area')) for area, score, n in area_scores(checks_en)]
    story += [CondPageBreak(9 * cm), Spacer(1, 22)]
    story.append(KeepTogether([SectionHeader(2, t('SCORE BY AREA'), t('How each part of the site did')), Spacer(1, 12), ScoreBars(bars), Spacer(1, 8),
                               Paragraph(esc(t('Area scores summarise the checks above: a fine check counts fully, a note counts most, a warning little. They are not a probability.')), st['muted'])]))

    # 3. Technical evidence
    http, tls, trust = _dict(report.get('http')), _dict(report.get('tls')), _dict(report.get('trust'))
    crawl, posture, dns = _dict(report.get('crawl')), _dict(report.get('posture')), _dict(report.get('dns'))
    story += _section(3, 'TECHNICAL EVIDENCE', 'For experts: how the verdict was reached', t)
    chain = [c for c in _list(http.get('chain')) if isinstance(c, dict)]
    story += _table('Scan overview', [
        (t('Address checked'), url, None),
        (t('Final address'), http.get('final_url') if http.get('final_url') != url else None, None),
        (t('HTTP status'), http.get('status_code'), 'good' if isinstance(http.get('status_code'), int) and http['status_code'] < 400 else 'warn' if http.get('status_code') else None),
        (t('Redirect trail'), ' → '.join(f'{c.get("status_code")} {c.get("url")}' for c in chain[:6]) if len(chain) > 1 else None, None),
        (t('Scanned'), scanned, None), (t('Report generated'), now.strftime('%Y-%m-%d %H:%M UTC'), None),
        (t('Report ID'), report_id, None), (t('Prepared for'), ctx['username'], None),
        (t('Policy'), ', '.join(p for p in (report.get('evidence_policy'), crawl.get('policy'), posture.get('policy'), trust.get('policy')) if isinstance(p, str)), None),
    ], t)
    verified = tls.get('verified') is True
    story += _table('Certificate', [
        (t('Certificate'), t('Verified') if verified else t('Not verified') if tls.get('status') == 'invalid' else t('Not checked'),
         'good' if verified else 'bad' if tls.get('status') == 'invalid' else None),
        (t('Issuer'), tls.get('issuer'), None), (t('Valid until'), str(tls.get('expires_at') or '')[:10], None),
        (t('Days left'), tls.get('days_remaining'), 'warn' if isinstance(tls.get('days_remaining'), int) and tls['days_remaining'] < 14 else None),
        (t('Protocol'), tls.get('tls_version'), 'good' if tls.get('tls_version') in ('TLSv1.2', 'TLSv1.3') else None),
        (t('Names on the certificate'), ', '.join(str(n) for n in _list(tls.get('subject_names'))[:8]), None),
    ], t)
    headers = [h for h in _list(report.get('header_observations')) if isinstance(h, dict)]
    story += _table('Browser security headers', [(h.get('name'), t(HEADER_STATES.get(h.get('status'), ('Not checked', None))[0]) + (f' — {h["value"][:80]}' if h.get('value') else ''),
                                                  HEADER_STATES.get(h.get('status'), ('', None))[1]) for h in headers], t)
    age, place, mail = _dict(trust.get('domain_age')), _dict(posture.get('hosting')), _dict(posture.get('mail'))
    story += _table('Domain and hosting', [
        (t('Domain'), age.get('domain') or report.get('domain'), None),
        (t('Registered'), age.get('created'), None),
        (t('Domain age'), _age(age['age_days'], lang) if isinstance(age.get('age_days'), int) else t('Not published'),
         'warn' if isinstance(age.get('age_days'), int) and age['age_days'] < 30 else None),
        (t('Server IP'), place.get('ip'), None),
        (t('Country'), t('Hidden behind a CDN') if place.get('cdn') else place.get('country'), None),
        (t('Network'), ' · '.join(str(x) for x in (place.get('network'), f'AS{place["asn"]}' if place.get('asn') else '') if x), None),
        (t('Name servers'), ', '.join(_list(_dict(dns.get('NS')).get('values'))[:4]), None),
        (t('Mail servers'), ', '.join(_list(_dict(dns.get('MX')).get('values'))[:4]), None),
    ], t)
    if mail.get('status') == 'completed':
        story += _table('Email sent in its name', [
            (t('Others can send email as this domain'), t('Protected') if mail.get('protected') else t('Not protected'), 'good' if mail.get('protected') else 'info'),
            (t('DMARC policy'), t(mail.get('dmarc_policy')) if mail.get('dmarc_policy') in ('missing', 'invalid') else mail.get('dmarc_policy'), None),
            (t('SPF record'), mail.get('spf') or t('None'), None),
        ], t)
    tech = [x for x in _list(posture.get('technology')) if isinstance(x, dict)]
    old = set(_list(posture.get('old_software')))
    mixed = _dict(posture.get('mixed_content'))
    software = [(str(x.get('name')), str(x.get('version') or t('Version not shown')), 'warn' if f'{x.get("name")} {x.get("version")}' in old else None) for x in tech[:10]]
    scripts = [x for x in _list(posture.get('outside_scripts')) if isinstance(x, dict)]
    if scripts:
        copied = {x.get('host') for x in _list(posture.get('copied_scripts')) if isinstance(x, dict)}
        software.append((t('Scripts from other sites'), ', '.join(str(x.get('host')) for x in scripts[:12]), 'bad' if copied else None))
    if mixed.get('scripts') or mixed.get('frames') or mixed.get('other'):
        software.append((t('Parts loaded over http://'), f'{mixed.get("scripts", 0)} / {mixed.get("frames", 0)} / {mixed.get("other", 0)}',
                         'warn' if mixed.get('scripts') or mixed.get('frames') else 'info'))
    cookies = [c for c in _list(posture.get('cookies')) if isinstance(c, dict)]
    if cookies:
        software.append((t('Cookies'), ', '.join(f'{c.get("name")} ({"Secure" if c.get("secure") else "-"}/{"HttpOnly" if c.get("httponly") else "-"})' for c in cookies[:8]), None))
    story += _table('Software and scripts', software, t)

    every_page = [p for p in _list(crawl.get('pages')) if isinstance(p, dict)]
    pages = [p for p in every_page if p.get('status') == 'read']
    if len(every_page) > len(pages):
        pages.append({'url': t('Pages that didn’t answer'), 'title': str(len(every_page) - len(pages)), 'status': 'unavailable'})
    if pages:
        story += [CondPageBreak(6 * cm), SubHeader(t('Pages read'), COLORS['accent'], crawl.get('pages_read')),
                  _rows_table(('PAGE', 'TITLE', 'STATUS'), [(_path(p.get('url')), str(p.get('title') or '')[:80], t(str(p.get('status') or '')))
                                                          for p in pages[:25]], (0.42, 0.40, 0.18), t), Spacer(1, 16)]
    links = []
    links += [(t('Listed by Google'), f'{x.get("host")} — {", ".join(_list(x.get("threat_types")))}', 'bad') for x in _list(crawl.get('listed_links')) if isinstance(x, dict)]
    links += [(t('Copies a brand'), f'{x.get("host")} — {x.get("brand")}', 'warn') for x in _list(crawl.get('lookalike_links')) if isinstance(x, dict)]
    links += [(t('Betting site'), str(x.get('host')), 'info') for x in _list(crawl.get('betting_links')) if isinstance(x, dict)]
    for item in _list(crawl.get('downloads')):
        if isinstance(item, dict):
            av = _dict(item.get('antivirus'))
            links.append((t('Download'), f'{item.get("url")} — {t("Antivirus")}: {av.get("signature") or t(str(av.get("status") or "unavailable"))}',
                          'bad' if av.get('status') == 'found' else 'good' if av.get('status') == 'clean' else None))
    if crawl.get('policy'):
        links.insert(0, (t('Outside sites linked'), crawl.get('external_sites', 0), None))
        links.append((t('Privacy notice (KVKK)'), t('Found') if crawl.get('privacy_notice') else t('Not found'), 'good' if crawl.get('privacy_notice') else 'info'))
    story += _table('Links and downloads', links, t)
    shop = _dict(crawl.get('shop'))
    if shop and not shop.get('not_judged'):
        rows = [(t(label), t('Found') if shop.get(key) else t('Not found'), 'good' if shop.get(key) else 'info')
                for label, key in (('Phone', 'phone'), ('Address', 'address'), ('Company number', 'company_id'),
                                   ('Return policy', 'returns'), ('ETBİS', 'etbis'), ('Card payment', 'card_payment'))]
        rows += [(t(label), t('Found'), 'warn') for label, key in (('Bank transfer only', 'bank_transfer_only'), ('WhatsApp only', 'whatsapp_only'),
                                                                   ('Big discounts', 'big_discounts')) if shop.get(key)]
        story += _table('Online shop details', rows, t)
    # Missing headers are in the headers table; the rest in the page's own words (WEB_FINDINGS) where it has them.
    from services.report_i18n import translate
    from services.simple_report_view import WEB_FINDINGS
    findings = [f for f in _list(report.get('findings')) if isinstance(f, dict) and f.get('title')
                and not str(f.get('code', '')).startswith('missing_')]
    lines = []
    for f in findings[:30]:
        title, detail = (WEB_FINDINGS[f['code']][1:] if f.get('code') in WEB_FINDINGS else (str(f['title']), str(f.get('detail') or '')))
        lines.append(f'{translate(title, lang)} — {translate(detail, lang)}')
    if lines:
        story += [SubHeader(t('All observations'), COLORS['accent'], len(lines)), flag_table(lines, 'info'), Spacer(1, 16)]
    missing = [m for m in _list(report.get('missing_checks')) if isinstance(m, str)]
    if missing:
        story += [SubHeader(t('Checks that couldn’t run'), COLORS['muted'], len(missing)), flag_table([t(m) for m in missing[:12]], 'info')]

    story += _closing(4, t, 'The verdict comes from MyScanner’s checks of the site: Google Web Risk, the address and domain, the pages we read, the sites they link to, downloads scanned with antivirus, and how the site is set up.',
                      'This report reflects the website at the time of the scan. We read its pages like a visitor: no forms were sent, no scripts were run and nothing was attacked. It is information, not a guarantee of safety.',
                      SITE_LEGEND, now)
    return _document(ctx, story, f'MyScanner - {url}')


def _path(url):
    try:
        parts = urlsplit(str(url))
        return (parts.path or '/') + (('?' + parts.query[:30] + ('…' if len(parts.query) > 30 else '')) if parts.query else '')
    except ValueError:
        return str(url)[:80]


def generate_email_report(report, username, lang='en'):
    """The email address check as a PDF. report: the signed email result (see report_receipts)."""
    from services.email_report_view import plain_email_report
    report = _dict(report)
    lang = 'tr' if lang == 'tr' else 'en'
    t = _t(lang)
    plain = _plain(report, lang, plain_email_report)
    tone = plain.get('tone') if plain.get('tone') in TONE_COLORS else 'unknown'
    vcol = TONE_COLORS[tone]
    assessment = _dict(report.get('assessment'))
    score = assessment.get('score') if isinstance(assessment.get('score'), int) and not isinstance(assessment.get('score'), bool) else None
    email = str(report.get('email') or '')
    now = datetime.now(timezone.utc)
    checked = _when(report.get('checked_at'))
    report_id = _report_id('MYS-E', report.get('checked_at') or now.isoformat())
    ctx = {'t': t, 'title': 'EMAIL ADDRESS REPORT', 'subtitle': 'An evidence-based check of one email address',
           'target_label': 'CHECKED ADDRESS', 'incomplete': score is None, 'trust': score or 0,
           'score_display': str(score) if score is not None else 'N/A', 'vcolor': vcol, 'vlabel': plain.get('label') or '',
           'url': email, 'scanned': checked, 'report_id': report_id, 'username': str(username or 'N/A')}
    story = _summary(plain, t, (t('EVIDENCE INDEX'), score if score is not None else 'N/A', t('out of 100'), vcol), tone)

    story += _section(2, 'TECHNICAL EVIDENCE', 'For experts: how the verdict was reached', t)
    story += _table('Scan overview', [(t('Email address'), email, None), (t('Domain'), report.get('domain'), None),
                                      (t('Checked'), checked, None), (t('Report generated'), now.strftime('%Y-%m-%d %H:%M UTC'), None),
                                      (t('Report ID'), report_id, None), (t('Prepared for'), ctx['username'], None),
                                      (t('Policy'), assessment.get('policy_version'), None)], t)
    bars = []
    for item in _list(assessment.get('categories')):
        if isinstance(item, dict) and item.get('weight'):
            weight = item['weight']
            kept = max(0, weight - (item.get('risk_deduction') or 0) - (item.get('coverage_deduction') or 0))
            taken = (item.get('risk_deduction') or 0) + (item.get('coverage_deduction') or 0)
            bars.append((t(str(item.get('label') or item.get('key'))), round(100 * kept / weight),
                         f'−{taken:g} {t("points deducted")}' if taken else t('No deductions')))
    if bars:
        story += [KeepTogether([SubHeader(t('Evidence by category'), COLORS['accent']), ScoreBars(bars)]), Spacer(1, 16)]
    findings = [f for f in _list(assessment.get('findings')) if isinstance(f, dict) and f.get('message')]
    if findings:
        story += [SubHeader(t('Findings'), COLORS['accent'], len(findings)),
                  flag_table([f'{t(f["message"])}   (−{f.get("deduction", 0):g} {t("pts")})' if f.get('deduction') else t(f['message'])
                              for f in findings[:20]], 'info'), Spacer(1, 16)]
    dns = _dict(report.get('dns'))
    mx, spf, dmarc = _dict(dns.get('mx')), _dict(dns.get('spf')), _dict(dns.get('dmarc'))
    servers = [r.get('exchange') for r in _list(mx.get('records')) if isinstance(r, dict) and r.get('exchange')]
    story += _table('Mail routing', [
        (t('Accepts email'), t('Yes') if mx.get('exists') else t('No') if mx.get('status') != 'unavailable' else t('Not checked'),
         'good' if mx.get('exists') else 'bad' if mx.get('status') != 'unavailable' else None),
        (t('Mail servers'), ', '.join(str(s) for s in servers[:5]), None)], t)
    spf_ok, dmarc_ok = _dict(spf.get('audit')).get('configuration_valid'), _dict(dmarc.get('audit')).get('configuration_valid')
    story += _table('Sender authentication', [
        (t('SPF record'), spf.get('record') or t('None'), 'good' if spf.get('record') else 'warn'),
        (t('SPF valid'), t('Yes') if spf_ok is True else t('No') if spf_ok is False else None, 'good' if spf_ok else 'warn' if spf_ok is False else None),
        (t('DMARC record'), dmarc.get('record') or t('None'), 'good' if dmarc.get('record') else 'warn'),
        (t('DMARC policy'), dmarc.get('policy'), 'good' if dmarc.get('policy') in ('quarantine', 'reject') else 'info' if dmarc.get('policy') else None),
    ], t)
    lists, info, risk = _dict(report.get('blacklist')), _dict(report.get('domain_info')), _dict(report.get('web_risk'))
    listed = [str(x) for x in _list(lists.get('blacklisted_on'))]
    smtp = _dict(report.get('smtp'))
    story += _table('Reputation and identity', [
        (t('Blocklists'), t('Listed') if listed else t('Not listed') if lists.get('coverage_status') == 'completed' or lists.get('clean_on') else t('Not checked'),
         'bad' if listed else 'good' if lists.get('coverage_status') == 'completed' or lists.get('clean_on') else None),
        (t('Listed on'), ', '.join(listed[:6]), None),
        # Free providers (gmail.com…) host everyone's mail: their website's reputation says nothing about one address.
        (t('Google Web Risk'), t('Listed') if risk.get('status') == 'matched' else t('Not listed') if risk.get('status') == 'not_found'
         else t('Not applicable') if risk.get('reason') == 'not_applicable' or report.get('is_free') else t('Not checked'),
         'bad' if risk.get('status') == 'matched' else 'good' if risk.get('status') == 'not_found' else None),
        (t('Domain age'), _age(info['age_days'], lang) if isinstance(info.get('age_days'), int) else t('Not published'),
         'warn' if isinstance(info.get('age_days'), int) and info['age_days'] < 90 else None),
        (t('Registrar'), info.get('registrar'), None),
        (t('Disposable address'), t('Yes') if report.get('is_disposable') else t('No'), 'warn' if report.get('is_disposable') else 'good'),
        (t('Free email provider'), t('Yes') if report.get('is_free') else t('No'), 'info' if report.get('is_free') else None),
        (t('Mailbox probe'), t('Accepted') if smtp.get('valid') is True else t('Rejected') if smtp.get('valid') is False else t('Not requested'),
         'good' if smtp.get('valid') is True else 'bad' if smtp.get('valid') is False else None),
    ], t)
    notes = [n for n in _list(assessment.get('missing_checks')) + _list(assessment.get('not_checked')) if isinstance(n, str)]
    if notes:
        story += [SubHeader(t('Not checked here'), COLORS['muted'], len(notes)), flag_table([t(n) for n in notes[:10]], 'info')]
    story += _closing(3, t, 'The verdict comes from MyScanner’s checks of the address: its domain and mail servers, sender authentication (SPF and DMARC), blocklists, Google Web Risk, the domain’s age and names that copy a company. The evidence index (0–100) summarises the deductions; it is not a probability.',
                      'This report reflects the address at the time of the check. No email was sent. A clean result says nothing about who owns the address.',
                      EMAIL_LEGEND, now)
    return _document(ctx, story, f'MyScanner - {email}')
