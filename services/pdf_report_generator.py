# services/pdf_report_generator.py
# =================================================================
# PDF REPORT GENERATOR v2 - مولد تقارير PDF احترافي
# تصميم داكن بهوية MyScanner (Navy + Cyan)
# - خلفية داكنة مرسومة على كل صفحة (حل مشكلة النص الفاتح على الأبيض)
# - بدون إيموجي (خطوط PDF القياسية لا تدعمها وتظهر مربعات سوداء)
# - مقياس دائري للغلاف، شريط مخاطر، أشرطة تقييم، بطاقات إحصائية
# - فهرس (Bookmarks) داخل ملف الـ PDF
# التوقيع ثابت: generate_vulnerability_report(scan, analysis, username)
# =================================================================

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table,
    TableStyle, Flowable, PageBreak, NextPageTemplate, CondPageBreak,
    KeepTogether,
)

# ═════════════════════════════════════════════════════════════════
# الأبعاد والألوان
# ═════════════════════════════════════════════════════════════════
PAGE_W, PAGE_H = A4
MARGIN = 1.5 * cm
CW = PAGE_W - 2 * MARGIN  # عرض المحتوى

COLORS = {
    'accent':   colors.HexColor('#00c8ff'),
    'dark_bg':  colors.HexColor('#07070f'),
    'surface':  colors.HexColor('#0e0e1a'),
    'card_bg':  colors.HexColor('#13132a'),
    'green':    colors.HexColor('#00e676'),
    'red':      colors.HexColor('#ff4560'),
    'yellow':   colors.HexColor('#ffd32a'),
    'white':    colors.HexColor('#e6e8f5'),
    'muted':    colors.HexColor('#8b90b8'),
    'border':   colors.HexColor('#2a2a48'),
}


def mix(fg, bg, t):
    """مزج لونين: t=1 يعطي fg بالكامل، t=0 يعطي bg"""
    return colors.Color(
        fg.red * t + bg.red * (1 - t),
        fg.green * t + bg.green * (1 - t),
        fg.blue * t + bg.blue * (1 - t),
    )


def hx(c):
    """لون -> #rrggbb لاستخدامه داخل <font color>"""
    return '#%02x%02x%02x' % tuple(int(round(v * 255)) for v in (c.red, c.green, c.blue))


def esc(v):
    return escape(str(v))


def clip(text, n):
    text = str(text)
    return text if len(text) <= n else text[: n - 3] + '...'


def to_num(v, default=0):
    try:
        return max(0, min(100, int(round(float(v)))))
    except (TypeError, ValueError):
        return default


def score_color(score):
    if score >= 80:
        return COLORS['green']
    if score >= 50:
        return COLORS['yellow']
    return COLORS['red']


# ═════════════════════════════════════════════════════════════════
# الأحكام (Verdicts)
# ═════════════════════════════════════════════════════════════════
VERDICTS = {
    'safe': (
        COLORS['green'], 'SAFE',
        'No significant threats were identified. The target shows strong trust '
        'signals across domain, encryption and reputation checks. Continue to '
        'apply standard caution when sharing sensitive data.'
    ),
    'suspicious': (
        COLORS['yellow'], 'SUSPICIOUS',
        'Several risk indicators were detected. Avoid entering credentials or '
        'sensitive information until the target is verified through an '
        'independent and trusted channel.'
    ),
    'malicious': (
        COLORS['red'], 'MALICIOUS',
        'Strong indicators of malicious activity were found. Do not visit this '
        'target or submit any information. Block it and report it to your '
        'security team.'
    ),
}


def resolve_verdict(trust_score, phishing):
    if phishing.get('in_database'):
        return 'malicious'
    if trust_score >= 80:
        return 'safe'
    if trust_score >= 50:
        return 'suspicious'
    return 'malicious'


DEFAULT_RECOMMENDATIONS = {
    'safe': [
        'Keep monitoring the target periodically; trust signals can change over time.',
        'Keep verifying links received by email or messaging apps before opening them.',
        'Keep browsers, extensions and endpoint protection fully updated.',
    ],
    'suspicious': [
        'Do not enter credentials, payment details or personal data on this target until verified.',
        'Verify the domain owner through an independent channel (official website, phone, support).',
        'If access is required, open the target only inside an isolated environment or sandbox.',
        'Re-scan the target later and compare the results.',
    ],
    'malicious': [
        'Do not visit this target and do not interact with any content it serves.',
        'Block the domain and URL at DNS, proxy and email-gateway level.',
        'If credentials were entered, reset them immediately and enable multi-factor authentication.',
        'Report the URL to your security team and to phishing-reporting services.',
    ],
}


# ═════════════════════════════════════════════════════════════════
# الأنماط (Styles)
# ═════════════════════════════════════════════════════════════════
_STYLES = None


def get_styles():
    global _STYLES
    if _STYLES:
        return _STYLES

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    white, muted, accent = COLORS['white'], COLORS['muted'], COLORS['accent']
    _STYLES = {
        'body': ps('Body', fontName='Helvetica', fontSize=9.5, leading=15,
                   textColor=white),
        'body_url': ps('BodyUrl', fontName='Helvetica', fontSize=9.5, leading=15,
                       textColor=white, wordWrap='CJK'),
        'muted': ps('Muted', fontName='Helvetica', fontSize=8.5, leading=13,
                    textColor=muted),
        'th': ps('TH', fontName='Helvetica-Bold', fontSize=7.5, leading=10,
                 textColor=accent),
        'th_c': ps('THC', fontName='Helvetica-Bold', fontSize=7.5, leading=10,
                   textColor=accent, alignment=TA_CENTER),
        'cell': ps('Cell', fontName='Helvetica', fontSize=8.5, leading=12,
                   textColor=white, wordWrap='CJK'),
        'cell_label': ps('CellLabel', fontName='Helvetica-Bold', fontSize=8,
                         leading=11, textColor=muted),
        'cell_c': ps('CellC', fontName='Helvetica', fontSize=8.5, leading=12,
                     textColor=white, alignment=TA_CENTER),
        'status': ps('Status', fontName='Helvetica-Bold', fontSize=7.5,
                     leading=10, alignment=TA_CENTER),
        'flag': ps('Flag', fontName='Helvetica', fontSize=9, leading=13,
                   textColor=white, wordWrap='CJK'),
        'icon': ps('Icon', fontName='Helvetica-Bold', fontSize=11, leading=13,
                   alignment=TA_CENTER),
        'banner_title': ps('BannerTitle', fontName='Helvetica-Bold', fontSize=15,
                           leading=19),
        'banner_text': ps('BannerText', fontName='Helvetica', fontSize=9,
                          leading=14, textColor=white),
        'foot1': ps('Foot1', fontName='Helvetica-Bold', fontSize=10, leading=14,
                    textColor=accent, alignment=TA_CENTER),
        'foot2': ps('Foot2', fontName='Helvetica', fontSize=8.5, leading=13,
                    textColor=muted, alignment=TA_CENTER),
        'foot3': ps('Foot3', fontName='Helvetica', fontSize=7.5, leading=11,
                    textColor=muted, alignment=TA_CENTER),
    }
    return _STYLES


# ═════════════════════════════════════════════════════════════════
# أدوات الرسم على Canvas
# ═════════════════════════════════════════════════════════════════
def gradient_rect(c, x, y, w, h, c_bottom, c_top, steps=60):
    step_h = h / steps
    for i in range(steps):
        t = i / (steps - 1)
        c.setFillColor(mix(c_top, c_bottom, t))
        c.rect(x, y + i * step_h, w, step_h + 0.6, fill=1, stroke=0)


def paint_background(c):
    """خلفية داكنة + شبكة خفيفة على كامل الصفحة"""
    c.setFillColor(COLORS['dark_bg'])
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setStrokeColor(mix(COLORS['accent'], COLORS['dark_bg'], 0.045))
    c.setLineWidth(0.3)
    step = 28
    x = 0
    while x <= PAGE_W:
        c.line(x, 0, x, PAGE_H)
        x += step
    y = 0
    while y <= PAGE_H:
        c.line(0, y, PAGE_W, y)
        y += step


def draw_spaced(c, x, y, text, font, size, spacing, align='center'):
    width = stringWidth(text, font, size) + spacing * (len(text) - 1)
    if align == 'center':
        x0 = x - width / 2
    elif align == 'right':
        x0 = x - width
    else:
        x0 = x
    t = c.beginText(x0, y)
    t.setFont(font, size)
    t.setCharSpace(spacing)
    t.textOut(text)
    t.setCharSpace(0)
    c.drawText(t)


def fit_text(text, font, size, max_w):
    text = str(text)
    if stringWidth(text, font, size) <= max_w:
        return text
    while text and stringWidth(text + '...', font, size) > max_w:
        text = text[:-1]
    return text + '...'


def draw_shield(c, cx, cy, s, fill, inner, check):
    """شعار الدرع (Vector) - بدون إيموجي"""
    c.saveState()

    def shield_path(k, dy=0):
        p = c.beginPath()
        p.moveTo(cx, cy + (42 * k + dy) * s)
        p.lineTo(cx + 34 * k * s, cy + (30 * k + dy) * s)
        p.lineTo(cx + 34 * k * s, cy + (2 * k + dy) * s)
        p.curveTo(cx + 34 * k * s, cy + (-24 * k + dy) * s,
                  cx + 14 * k * s, cy + (-38 * k + dy) * s,
                  cx, cy + (-44 * k + dy) * s)
        p.curveTo(cx - 14 * k * s, cy + (-38 * k + dy) * s,
                  cx - 34 * k * s, cy + (-24 * k + dy) * s,
                  cx - 34 * k * s, cy + (2 * k + dy) * s)
        p.lineTo(cx - 34 * k * s, cy + (30 * k + dy) * s)
        p.close()
        return p

    c.setFillColor(fill)
    c.drawPath(shield_path(1.0), fill=1, stroke=0)
    c.setFillColor(inner)
    c.drawPath(shield_path(0.80, dy=1), fill=1, stroke=0)

    c.setStrokeColor(check)
    c.setLineWidth(6 * s)
    c.setLineCap(1)
    c.setLineJoin(1)
    p = c.beginPath()
    p.moveTo(cx - 14 * s, cy + 1 * s)
    p.lineTo(cx - 4 * s, cy - 10 * s)
    p.lineTo(cx + 16 * s, cy + 15 * s)
    c.drawPath(p, fill=0, stroke=1)
    c.restoreState()


def draw_logo_text(c, x, y, size, align='left'):
    """MyScanner بلونين: My أبيض + Scanner سيان"""
    f = 'Helvetica-Bold'
    w1 = stringWidth('My', f, size)
    w2 = stringWidth('Scanner', f, size)
    if align == 'center':
        x = x - (w1 + w2) / 2
    c.setFont(f, size)
    c.setFillColor(COLORS['white'])
    c.drawString(x, y, 'My')
    c.setFillColor(COLORS['accent'])
    c.drawString(x + w1, y, 'Scanner')


# ═════════════════════════════════════════════════════════════════
# صفحة الغلاف
# ═════════════════════════════════════════════════════════════════
def draw_cover(c, ctx):
    c.saveState()
    bg, accent = COLORS['dark_bg'], COLORS['accent']
    paint_background(c)

    vcol = ctx['vcolor']
    cx = PAGE_W / 2

    # توهج علوي
    gradient_rect(c, 0, PAGE_H - 330, PAGE_W, 330, bg, mix(accent, bg, 0.16))
    # أشرطة جانبية
    c.setFillColor(accent)
    c.rect(0, 0, PAGE_W, 6, fill=1, stroke=0)
    c.rect(0, PAGE_H - 6, PAGE_W, 6, fill=1, stroke=0)

    # توهج خلف المقياس (يُرسم أولاً حتى لا يغطي النصوص)
    gy = 425
    r = 78
    for k in range(9):
        c.setFillColor(mix(vcol, bg, 0.012 * (k + 1)))
        c.circle(cx, gy, 138 - k * 7, fill=1, stroke=0)

    # الشعار
    draw_shield(c, cx, PAGE_H - 108, 1.05, accent, COLORS['dark_bg'], accent)
    draw_logo_text(c, cx, PAGE_H - 186, 40, align='center')
    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, PAGE_H - 207, 'ADVANCED CYBERSECURITY PLATFORM',
                'Helvetica', 8.5, 3)
    c.setStrokeColor(accent)
    c.setLineWidth(2)
    c.line(cx - 40, PAGE_H - 224, cx + 40, PAGE_H - 224)

    # عنوان التقرير
    c.setFillColor(COLORS['white'])
    c.setFont('Helvetica-Bold', 21)
    c.drawCentredString(cx, PAGE_H - 258, 'VULNERABILITY & THREAT')
    c.drawCentredString(cx, PAGE_H - 283, 'ANALYSIS REPORT')
    c.setFillColor(COLORS['muted'])
    c.setFont('Helvetica', 10)
    c.drawCentredString(cx, PAGE_H - 304, 'Comprehensive URL security assessment')

    # المقياس الدائري
    c.setFillColor(COLORS['surface'])
    c.circle(cx, gy, r - 6, fill=1, stroke=0)

    c.setLineWidth(12)
    c.setStrokeColor(COLORS['border'])
    c.circle(cx, gy, r, fill=0, stroke=1)

    sweep = min(359.9, ctx['trust'] * 3.6)
    if sweep > 0.5:
        c.setStrokeColor(vcol)
        c.setLineCap(1)
        c.arc(cx - r, gy - r, cx + r, gy + r, 90 - sweep, sweep)

    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, gy + 36, 'OVERALL SCORE', 'Helvetica-Bold', 8, 2.5)
    c.setFillColor(vcol)
    c.setFont('Helvetica-Bold', 50)
    c.drawCentredString(cx, gy - 16, ctx.get('score_display', str(ctx['trust'])))
    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, gy - 35, 'INCOMPLETE' if ctx.get('incomplete') else 'OUT OF 100', 'Helvetica', 7.5, 2)

    # شارة الحكم
    label = ctx['vlabel']
    pw = stringWidth(label, 'Helvetica-Bold', 15) + 76
    py = gy - r - 62
    c.setFillColor(mix(vcol, bg, 0.16))
    c.setStrokeColor(vcol)
    c.setLineWidth(1.2)
    c.roundRect(cx - pw / 2, py, pw, 36, 18, fill=1, stroke=1)
    c.setFillColor(vcol)
    c.circle(cx - pw / 2 + 22, py + 18, 5, fill=1, stroke=0)
    c.setFont('Helvetica-Bold', 15)
    c.drawString(cx - pw / 2 + 36, py + 12.5, label)

    # بطاقة الهدف
    bx, bw = MARGIN + 10, PAGE_W - 2 * (MARGIN + 10)
    ty = 200
    c.setFillColor(COLORS['card_bg'])
    c.setStrokeColor(COLORS['border'])
    c.setLineWidth(0.8)
    c.roundRect(bx, ty, bw, 66, 10, fill=1, stroke=1)
    c.setFillColor(accent)
    c.roundRect(bx, ty + 12, 3.5, 42, 1.7, fill=1, stroke=0)
    c.setFillColor(accent)
    draw_spaced(c, bx + 20, ty + 47, 'TARGET URL', 'Helvetica-Bold', 7.5, 2,
                align='left')
    c.setFillColor(COLORS['white'])
    c.setFont('Courier', 10)
    c.drawString(bx + 20, ty + 24,
                 fit_text(ctx['url'], 'Courier', 10, bw - 40))

    # بطاقات المعلومات
    gap = 10
    mw = (bw - 2 * gap) / 3
    meta = [
        ('REPORT DATE', ctx['date']),
        ('REPORT ID', ctx['report_id']),
        ('ANALYZED FOR', ctx['username']),
    ]
    for i, (lab, val) in enumerate(meta):
        x = bx + i * (mw + gap)
        c.setFillColor(COLORS['card_bg'])
        c.setStrokeColor(COLORS['border'])
        c.roundRect(x, 112, mw, 60, 10, fill=1, stroke=1)
        c.setFillColor(COLORS['muted'])
        draw_spaced(c, x + 14, 112 + 40, lab, 'Helvetica-Bold', 7, 2,
                    align='left')
        c.setFillColor(COLORS['white'])
        c.setFont('Helvetica-Bold', 10)
        c.drawString(x + 14, 112 + 20,
                     fit_text(val, 'Helvetica-Bold', 10, mw - 28))

    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, 62, 'CONFIDENTIAL REPORT  |  MYSCANNERS.COM',
                'Helvetica', 7, 2.5)
    c.restoreState()


# ═════════════════════════════════════════════════════════════════
# رأس وتذييل الصفحات الداخلية
# ═════════════════════════════════════════════════════════════════
def draw_content_page(c, doc, ctx):
    c.saveState()
    paint_background(c)
    c.setFillColor(COLORS['accent'])
    c.rect(0, PAGE_H - 4, PAGE_W, 4, fill=1, stroke=0)

    # الرأس
    draw_shield(c, MARGIN + 8, PAGE_H - 27, 0.22, COLORS['accent'],
                COLORS['dark_bg'], COLORS['accent'])
    draw_logo_text(c, MARGIN + 22, PAGE_H - 31, 11)
    c.setFillColor(COLORS['muted'])
    c.setFont('Courier', 7.5)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 30,
                      f'SECURITY REPORT  |  {ctx["report_id"]}')
    c.setStrokeColor(COLORS['border'])
    c.setLineWidth(0.6)
    c.line(MARGIN, PAGE_H - 44, PAGE_W - MARGIN, PAGE_H - 44)

    # التذييل
    c.line(MARGIN, 40, PAGE_W - MARGIN, 40)
    c.setFont('Helvetica', 7)
    c.setFillColor(COLORS['muted'])
    c.drawString(MARGIN, 26,
                 'MyScanner Advanced Cybersecurity Platform  |  myscanners.com')
    c.setFillColor(COLORS['accent'])
    draw_spaced(c, PAGE_W / 2 + 60, 26, 'CONFIDENTIAL', 'Helvetica-Bold', 7, 1.5)
    c.setFillColor(COLORS['muted'])
    c.setFont('Helvetica', 7)
    c.drawRightString(PAGE_W - MARGIN, 26, f'Page {doc.page}')
    c.restoreState()


# ═════════════════════════════════════════════════════════════════
# Flowables مخصصة
# ═════════════════════════════════════════════════════════════════
class SectionHeader(Flowable):
    """عنوان قسم مرقّم + إشارة مرجعية (Bookmark) في الـ PDF"""

    def __init__(self, number, title, subtitle=''):
        super().__init__()
        self.number, self.title, self.subtitle = number, title, subtitle
        self.keepWithNext = True

    def wrap(self, aw, ah):
        self.width = aw
        return aw, 42

    def draw(self):
        c = self.canv
        key = f'section_{self.number}'
        c.bookmarkPage(key)
        c.addOutlineEntry(f'{self.number}. {self.title}', key, 0, 0)

        c.setFillColor(COLORS['accent'])
        c.roundRect(0, 12, 28, 28, 7, fill=1, stroke=0)
        c.setFillColor(COLORS['dark_bg'])
        c.setFont('Helvetica-Bold', 14)
        c.drawCentredString(14, 21, str(self.number))
        c.setFillColor(COLORS['white'])
        c.setFont('Helvetica-Bold', 16)
        c.drawString(40, 27 if self.subtitle else 21, self.title.upper())
        if self.subtitle:
            c.setFillColor(COLORS['muted'])
            c.setFont('Helvetica', 8)
            c.drawString(40, 14, self.subtitle)
        c.setStrokeColor(COLORS['border'])
        c.setLineWidth(1)
        c.line(0, 2, self.width, 2)
        c.setStrokeColor(COLORS['accent'])
        c.setLineWidth(2)
        c.line(0, 2, 70, 2)


class SubHeader(Flowable):
    """عنوان فرعي ملوّن مع عدّاد"""

    def __init__(self, title, color, count=None):
        super().__init__()
        self.title, self.color, self.count = title, color, count
        self.keepWithNext = True

    def wrap(self, aw, ah):
        self.width = aw
        return aw, 26

    def draw(self):
        c = self.canv
        c.setFillColor(self.color)
        c.roundRect(0, 5, 3.5, 15, 1.7, fill=1, stroke=0)
        c.setFillColor(COLORS['white'])
        c.setFont('Helvetica-Bold', 11)
        c.drawString(12, 8.5, self.title)
        if self.count is not None:
            tw = stringWidth(self.title, 'Helvetica-Bold', 11)
            s = str(self.count)
            bw = stringWidth(s, 'Helvetica-Bold', 8) + 14
            c.setFillColor(mix(self.color, COLORS['dark_bg'], 0.2))
            c.setStrokeColor(self.color)
            c.setLineWidth(0.6)
            c.roundRect(12 + tw + 8, 4.5, bw, 15, 7.5, fill=1, stroke=1)
            c.setFillColor(self.color)
            c.setFont('Helvetica-Bold', 8)
            c.drawCentredString(12 + tw + 8 + bw / 2, 8.8, s)


class StatCards(Flowable):
    """صف بطاقات إحصائية: (label, value, sub, color)"""

    def __init__(self, items, height=70, gap=9):
        super().__init__()
        self.items, self.height_, self.gap = items, height, gap

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.height_

    def draw(self):
        c = self.canv
        n = len(self.items)
        cw = (self.width - self.gap * (n - 1)) / n
        h = self.height_
        for i, (label, value, sub, col) in enumerate(self.items):
            x = i * (cw + self.gap)
            c.setFillColor(COLORS['card_bg'])
            c.setStrokeColor(COLORS['border'])
            c.setLineWidth(0.7)
            c.roundRect(x, 0, cw, h, 9, fill=1, stroke=1)
            c.setStrokeColor(col)
            c.setLineWidth(2.5)
            c.setLineCap(1)
            c.line(x + 14, h - 1.2, x + cw - 14, h - 1.2)
            c.setFillColor(COLORS['muted'])
            draw_spaced(c, x + 14, h - 20, label, 'Helvetica-Bold', 6.8, 1.6,
                        align='left')
            c.setFillColor(col)
            c.setFont('Helvetica-Bold', 25)
            c.drawString(x + 14, 22, str(value))
            c.setFillColor(COLORS['muted'])
            c.setFont('Helvetica', 7.5)
            c.drawString(x + 14, 9, sub)


class RiskMeter(Flowable):
    """شريط طيف المخاطر مع مؤشر على الدرجة"""

    def __init__(self, score):
        super().__init__()
        self.score = score

    def wrap(self, aw, ah):
        self.width = aw
        return aw, 74

    def draw(self):
        c = self.canv
        W = self.width
        bar_y, bar_h = 28, 12
        c.setFillColor(COLORS['card_bg'])
        c.setStrokeColor(COLORS['border'])
        c.setLineWidth(0.7)
        c.roundRect(0, 0, W, 74, 9, fill=1, stroke=1)

        pad = 18
        bw = W - 2 * pad
        segs = [(0, 50, COLORS['red'], 'MALICIOUS'),
                (50, 80, COLORS['yellow'], 'SUSPICIOUS'),
                (80, 100, COLORS['green'], 'SAFE')]
        for a, b, col, name in segs:
            active = a <= self.score < b or (b == 100 and self.score == 100)
            x0 = pad + bw * a / 100 + (1.5 if a else 0)
            x1 = pad + bw * b / 100 - (1.5 if b < 100 else 0)
            c.setFillColor(col if active else mix(col, COLORS['dark_bg'], 0.38))
            c.rect(x0, bar_y, x1 - x0, bar_h, fill=1, stroke=0)
            c.setFillColor(col if active else COLORS['muted'])
            draw_spaced(c, (x0 + x1) / 2, bar_y - 14, name, 'Helvetica-Bold',
                        6.5, 1.4)

        mx = pad + bw * self.score / 100
        mx = max(pad + 4, min(pad + bw - 4, mx))
        c.setFillColor(COLORS['white'])
        p = c.beginPath()
        p.moveTo(mx - 6, bar_y + bar_h + 14)
        p.lineTo(mx + 6, bar_y + bar_h + 14)
        p.lineTo(mx, bar_y + bar_h + 4)
        p.close()
        c.drawPath(p, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 8)
        c.drawCentredString(mx, bar_y + bar_h + 18, str(self.score))


class ScoreBars(Flowable):
    """أشرطة تقييم أفقية: (label, score, detail)"""
    ROW_H = 36

    def __init__(self, rows):
        super().__init__()
        self.rows = rows

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.ROW_H * len(self.rows) + 14

    def draw(self):
        c = self.canv
        W = self.width
        H = self.ROW_H * len(self.rows) + 14
        c.setFillColor(COLORS['card_bg'])
        c.setStrokeColor(COLORS['border'])
        c.setLineWidth(0.7)
        c.roundRect(0, 0, W, H, 9, fill=1, stroke=1)

        x0, x1 = 200, W - 70
        for i, (label, score, detail) in enumerate(self.rows):
            y = H - 7 - (i + 1) * self.ROW_H
            col = score_color(score)
            c.setFillColor(COLORS['white'])
            c.setFont('Helvetica-Bold', 9)
            c.drawString(16, y + 18, label)
            c.setFillColor(COLORS['muted'])
            c.setFont('Helvetica', 7.2)
            c.drawString(16, y + 7, fit_text(detail, 'Helvetica', 7.2, x0 - 30))

            c.setFillColor(COLORS['border'])
            c.roundRect(x0, y + 13, x1 - x0, 8, 4, fill=1, stroke=0)
            if score > 0:
                c.setFillColor(col)
                c.roundRect(x0, y + 13, max(8, (x1 - x0) * score / 100), 8, 4,
                            fill=1, stroke=0)
            c.setFillColor(col)
            c.setFont('Helvetica-Bold', 10)
            c.drawRightString(W - 16, y + 12, f'{score}/100')
            if i < len(self.rows) - 1:
                c.setStrokeColor(mix(COLORS['border'], COLORS['card_bg'], 0.5))
                c.setLineWidth(0.4)
                c.line(16, y, W - 16, y)


# ═════════════════════════════════════════════════════════════════
# جداول مساعدة
# ═════════════════════════════════════════════════════════════════
STATUS_MAP = {
    'good': ('PASS', COLORS['green']),
    'warn': ('WARNING', COLORS['yellow']),
    'bad': ('FAIL', COLORS['red']),
    'info': ('INFO', COLORS['accent']),
    None: ('-', COLORS['muted']),
}


def kv_table(rows):
    """جدول (Field | Value | Status) بتلوين حسب الحالة"""
    st = get_styles()
    data = [[Paragraph('FIELD', st['th']), Paragraph('VALUE', st['th']),
             Paragraph('STATUS', st['th_c'])]]
    style = [
        ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 11),
        ('RIGHTPADDING', (0, 0), (-1, -1), 11),
        ('BACKGROUND', (0, 0), (-1, 0), mix(COLORS['accent'], COLORS['dark_bg'], 0.16)),
        ('LINEBELOW', (0, 0), (-1, 0), 1.2, COLORS['accent']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['card_bg'], COLORS['surface']]),
    ]
    for i, (label, value, status) in enumerate(rows, start=1):
        text, col = STATUS_MAP.get(status, STATUS_MAP[None])
        data.append([
            Paragraph(esc(label), st['cell_label']),
            Paragraph(esc(value), st['cell']),
            Paragraph(f'<font color="{hx(col)}">{text}</font>', st['status']),
        ])
        if status:
            style.append(('BACKGROUND', (2, i), (2, i),
                          mix(col, COLORS['card_bg'], 0.14)))
    t = Table(data, colWidths=[0.27 * CW, 0.55 * CW, 0.18 * CW], repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def flag_text(item):
    if isinstance(item, dict):
        for k in ('message', 'reason', 'title', 'description', 'text', 'name'):
            if item.get(k):
                return str(item[k])
    return str(item)


def flag_table(items, kind):
    """قائمة بطاقات: red / green / info"""
    st = get_styles()
    cfg = {'red': (COLORS['red'], '!'),
           'green': (COLORS['green'], '+'),
           'info': (COLORS['accent'], 'i')}
    col, sym = cfg[kind]
    data = [[Paragraph(f'<font color="{hx(col)}">{sym}</font>', st['icon']),
             Paragraph(esc(flag_text(it)), st['flag'])] for it in items]
    t = Table(data, colWidths=[1.0 * cm, CW - 1.0 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), mix(col, COLORS['card_bg'], 0.14)),
        ('BACKGROUND', (1, 0), (1, -1), COLORS['card_bg']),
        ('LINEBEFORE', (0, 0), (0, -1), 3, col),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('LINEAFTER', (-1, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEABOVE', (0, 0), (-1, 0), 0.7, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (1, 0), (1, -1), 12),
        ('RIGHTPADDING', (1, 0), (1, -1), 12),
        ('LEFTPADDING', (0, 0), (0, -1), 4),
        ('RIGHTPADDING', (0, 0), (0, -1), 4),
    ]))
    return t


def numbered_table(items):
    """توصيات مرقّمة"""
    st = get_styles()
    data = []
    for i, it in enumerate(items, start=1):
        data.append([
            Paragraph(f'<font color="{hx(COLORS["accent"])}">{i:02d}</font>',
                      st['icon']),
            Paragraph(esc(flag_text(it)), st['flag']),
        ])
    t = Table(data, colWidths=[1.3 * cm, CW - 1.3 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), mix(COLORS['accent'], COLORS['card_bg'], 0.12)),
        ('BACKGROUND', (1, 0), (1, -1), COLORS['card_bg']),
        ('LINEBEFORE', (0, 0), (0, -1), 3, COLORS['accent']),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('LINEAFTER', (-1, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEABOVE', (0, 0), (-1, 0), 0.7, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
        ('LEFTPADDING', (1, 0), (1, -1), 12),
        ('RIGHTPADDING', (1, 0), (1, -1), 12),
    ]))
    return t


def verdict_banner(vcol, vlabel, vdesc):
    st = get_styles()
    inner = [
        Paragraph(f'<font color="{hx(vcol)}">VERDICT: {vlabel}</font>',
                  st['banner_title']),
        Spacer(1, 4),
        Paragraph(esc(vdesc), st['banner_text']),
    ]
    t = Table([['', inner]], colWidths=[7, CW - 7])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), vcol),
        ('BACKGROUND', (1, 0), (1, 0), mix(vcol, COLORS['card_bg'], 0.10)),
        ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
        ('LEFTPADDING', (1, 0), (1, 0), 16),
        ('RIGHTPADDING', (1, 0), (1, 0), 16),
        ('TOPPADDING', (1, 0), (1, 0), 13),
        ('BOTTOMPADDING', (1, 0), (1, 0), 13),
        ('LEFTPADDING', (0, 0), (0, 0), 0),
        ('RIGHTPADDING', (0, 0), (0, 0), 0),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return t


def legend_table():
    st = get_styles()
    rows = [
        ('80 - 100', 'SAFE', COLORS['green'],
         'Strong trust signals, no significant threat indicators.'),
        ('50 - 79', 'SUSPICIOUS', COLORS['yellow'],
         'Mixed or weak signals. Verify before trusting the target.'),
        ('0 - 49', 'MALICIOUS', COLORS['red'],
         'Strong threat indicators. Avoid and block the target.'),
    ]
    data = [[Paragraph('SCORE', st['th']), Paragraph('VERDICT', st['th_c']),
             Paragraph('MEANING', st['th'])]]
    style = [
        ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 11),
        ('BACKGROUND', (0, 0), (-1, 0), mix(COLORS['accent'], COLORS['dark_bg'], 0.16)),
        ('LINEBELOW', (0, 0), (-1, 0), 1.2, COLORS['accent']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['card_bg'], COLORS['surface']]),
    ]
    for i, (rng, name, col, meaning) in enumerate(rows, start=1):
        data.append([
            Paragraph(f'<font name="Courier-Bold">{rng}</font>', st['cell']),
            Paragraph(f'<font color="{hx(col)}">{name}</font>', st['status']),
            Paragraph(meaning, st['cell']),
        ])
        style.append(('BACKGROUND', (1, i), (1, i), mix(col, COLORS['card_bg'], 0.14)))
    t = Table(data, colWidths=[0.2 * CW, 0.2 * CW, 0.6 * CW])
    t.setStyle(TableStyle(style))
    return t


def generic_rows(data, limit=14):
    """تحويل dict عشوائي إلى صفوف (label, value, None) بشكل آمن"""
    rows = []
    if not isinstance(data, dict):
        return rows
    for k, v in data.items():
        if len(rows) >= limit:
            break
        label = str(k).replace('_', ' ').strip().title()
        if isinstance(v, bool):
            val = 'Yes' if v else 'No'
        elif isinstance(v, (int, float)):
            val = str(v)
        elif isinstance(v, str):
            val = clip(v, 90)
        elif isinstance(v, (list, tuple)):
            val = ', '.join(clip(x, 50) for x in v[:5])
            if len(v) > 5:
                val += f' (+{len(v) - 5} more)'
        else:
            continue
        if val:
            rows.append((label, val, None))
    return rows


def yes_no(flag, yes='Yes', no='No'):
    return yes if flag else no


# ═════════════════════════════════════════════════════════════════
# تقييم الوضع الأمني (مشتق من الإشارات المتوفرة)
# ═════════════════════════════════════════════════════════════════
def compute_posture(trust, local, domain_info, ssl_vet, feats, phishing, typo):
    rows = [
        ('url.vet Trust Score', trust, 'Aggregated result of 33 signals / 18 analyzers'),
        ('Local Security Score', local, "MyScanner's proprietary local engine"),
    ]
    if ssl_vet:
        tls = bool(ssl_vet.get('has_tls'))
        chain = bool(ssl_vet.get('chain_valid'))
        s = (50 if tls else 0) + (50 if tls and chain else 0)
        d = ('HTTPS enabled with a valid certificate chain' if tls and chain else
             'HTTPS enabled but the certificate chain is invalid' if tls else
             'No HTTPS / TLS detected')
        rows.append(('Encryption & TLS', s, d))
    if feats:
        keys = ['url_shortener', 'uses_ip', 'contains_punycode',
                'has_homoglyph', 'has_keywords']
        hits = sum(1 for k in keys if feats.get(k))
        rows.append(('URL Structure', max(0, 100 - 25 * hits),
                     f'{hits} suspicious URL characteristic(s) found'))
    if domain_info:
        s = 100
        notes = []
        if not domain_info.get('dnssec'):
            s -= 15
            notes.append('DNSSEC disabled')
        else:
            notes.append('DNSSEC enabled')
        try:
            days = float(domain_info.get('age_days'))
            if days < 30:
                s -= 45
            elif days < 180:
                s -= 25
            elif days < 365:
                s -= 10
        except (TypeError, ValueError):
            pass
        age = domain_info.get('age_human')
        if age:
            notes.append(f'age {age}')
        rows.append(('Domain Reputation', max(0, s), ', '.join(notes)))
    rows.append(('Phishing Exposure', 0 if phishing.get('in_database') else 100,
                 'Listed in phishing database' if phishing.get('in_database')
                 else 'Not found in phishing databases'))
    rows.append(('Typosquatting Risk', 0 if typo.get('is_suspicious') else 100,
                 'Lookalike of a known brand detected' if typo.get('is_suspicious')
                 else 'No lookalike patterns detected'))
    return rows


# ═════════════════════════════════════════════════════════════════
# الدالة الرئيسية
# ═════════════════════════════════════════════════════════════════
def generate_vulnerability_report(scan, analysis, username):
    """
    توليد تقرير PDF احترافي كامل

    Args:
        scan: كائن Scan من قاعدة البيانات
        analysis: dict يحتوي على نتائج التحليل (من URLDeepAnalyzer)
        username: اسم المستخدم

    Returns:
        BytesIO: ملف PDF جاهز للتحميل
    """
    st = get_styles()
    analysis = analysis or {}

    # ── استخراج البيانات ─────────────────────────────────────────
    urlvet = analysis.get('urlvet', {}) or {}
    trust = to_num(urlvet.get('trust_score', 0))
    verdict_raw = urlvet.get('verdict_raw', 'Unknown')
    red_flags = urlvet.get('red_flags', []) or []
    green_flags = urlvet.get('green_flags', []) or []
    neutral = urlvet.get('neutral_reasons', []) or []
    domain_info = urlvet.get('domain_info', {}) or {}
    ssl_vet = urlvet.get('ssl_info', {}) or {}
    feats = urlvet.get('url_features', {}) or {}
    analysis_vet = urlvet.get('analysis', {}) or {}
    phishing = urlvet.get('phishing', {}) or {}
    typo = urlvet.get('typosquatting', {}) or {}

    local = to_num(analysis.get('security_score', 0))
    recs = analysis.get('recommendations', []) or []
    ssl_local = analysis.get('ssl', {}) or {}
    dns_records = analysis.get('dns', {}) or {}

    from services.url_assessment import assess_url
    aggregate = analysis.get('aggregate_assessment') or assess_url(analysis, analysis.get('deep_analysis', {}))
    overall = to_num(aggregate.get('score') or 0)
    vkey = {'harmless':'safe','high_risk':'suspicious'}.get(aggregate.get('verdict'), aggregate.get('verdict','unknown'))
    if vkey in VERDICTS:
        vcol, vlabel, vdesc = VERDICTS[vkey]
    else:
        vkey = 'unknown'
        vcol, vlabel, vdesc = COLORS['yellow'], 'UNKNOWN', 'Available evidence does not confirm safety. Review coverage limitations.' 

    try:
        report_id = f'MYS-{int(scan.id):06d}'
    except (TypeError, ValueError, AttributeError):
        report_id = 'MYS-000000'
    url = str(getattr(scan, 'url', '') or 'N/A')
    now = datetime.now(timezone.utc)
    date_str = now.strftime('%Y-%m-%d %H:%M UTC')
    username = str(username or 'N/A')

    ctx = {
        'incomplete': aggregate.get('score') is None, 'trust': overall, 'score_display': str(aggregate['score']) if aggregate.get('score') is not None else 'N/A', 'vcolor': vcol, 'vlabel': vlabel, 'url': url,
        'date': date_str, 'report_id': report_id, 'username': username,
    }

    # ── المستند وقوالب الصفحات ───────────────────────────────────
    buffer = BytesIO()
    doc = BaseDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=2 * cm, bottomMargin=2 * cm,
        title=f'MyScanner Security Report - {url}',
        author='MyScanner Security',
        subject='Vulnerability & Threat Analysis Report',
        creator='MyScanner Advanced Cybersecurity Platform',
    )
    cover_frame = Frame(MARGIN, PAGE_H / 2, CW, 20, id='cover',
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body_frame = Frame(MARGIN, 2 * cm, CW, PAGE_H - 2 * cm - 64, id='body',
                       leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id='cover', frames=[cover_frame],
                     onPage=lambda c, d: draw_cover(c, ctx)),
        PageTemplate(id='content', frames=[body_frame],
                     onPage=lambda c, d: draw_content_page(c, d, ctx)),
    ])

    E = []
    E += [Spacer(1, 1), NextPageTemplate('content'), PageBreak()]

    # ═════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ═════════════════════════════════════════════════════════════
    E.append(SectionHeader(1, 'Executive Summary', 'Overall assessment at a glance'))
    E.append(Spacer(1, 12))
    E.append(Paragraph(
        f'This report presents a comprehensive security analysis of '
        f'<font color="{hx(COLORS["accent"])}"><b>{esc(url)}</b></font>, conducted by '
        f"MyScanner's advanced threat detection engine. The analysis combines "
        f'<b>url.vet</b> (33 security signals across 18 analyzers) with the '
        f'<b>MyScanner local security engine</b> and deep content checks to provide an evidence assessment '
        f"of the target's security posture.", st['body_url']))
    E.append(Paragraph('Coverage: '+esc(aggregate['coverage'])+'; '+esc('; '.join(aggregate['missing_checks'])), st['body']))
    E.append(Spacer(1, 14))
    E.append(verdict_banner(vcol, vlabel, vdesc))
    E.append(Spacer(1, 12))
    E.append(StatCards([
        ('OVERALL SCORE', aggregate.get('score') if aggregate.get('score') is not None else 'N/A', 'assessment incomplete' if aggregate.get('score') is None else 'out of 100', COLORS['yellow'] if aggregate.get('score') is None else score_color(overall)),
        ('LOCAL SCORE', local, 'out of 100', score_color(local)),
        ('RED FLAGS', len(red_flags), 'threat indicators',
         COLORS['red'] if red_flags else COLORS['green']),
        ('GREEN FLAGS', len(green_flags), 'positive signals', COLORS['green']),
    ]))
    E.append(Spacer(1, 12))
    if aggregate.get('score') is not None:
        E.append(RiskMeter(overall))
    E.append(Spacer(1, 16))

    E.append(SubHeader('Scan Overview', COLORS['accent']))
    overview = [
        ('Target URL', url, None),
        ('Report ID', report_id, None),
        ('Generated', date_str, None),
        ('Analyzed For', username, None),
        ('url.vet Verdict', str(verdict_raw), 'info'),
        ('Engines', 'url.vet + MyScanner Local Security Engine', None),
    ]
    created = getattr(scan, 'created_at', None)
    if created:
        try:
            overview.insert(2, ('Scan Time', created.strftime('%Y-%m-%d %H:%M UTC'), None))
        except AttributeError:
            pass
    E.append(kv_table(overview))

    # ═════════════════════════════════════════════════════════════
    # 2. URL.VET THREAT ANALYSIS
    # ═════════════════════════════════════════════════════════════
    E.append(CondPageBreak(7 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(2, 'url.vet Threat Analysis', 'Signals collected by the url.vet engine'))
    E.append(Spacer(1, 12))

    if red_flags:
        E.append(SubHeader('Red Flags - Threats Detected', COLORS['red'], len(red_flags)))
        E.append(flag_table(red_flags, 'red'))
        E.append(Spacer(1, 16))
    else:
        E.append(SubHeader('Red Flags - Threats Detected', COLORS['red'], 0))
        E.append(flag_table(['No threat indicators were detected for this target.'], 'info'))
        E.append(Spacer(1, 16))

    if green_flags:
        E.append(SubHeader('Green Flags - Positive Signals', COLORS['green'], len(green_flags)))
        E.append(flag_table(green_flags, 'green'))
        E.append(Spacer(1, 16))

    if neutral:
        E.append(SubHeader('Informational', COLORS['accent'], len(neutral[:8])))
        E.append(flag_table(neutral[:8], 'info'))
        E.append(Spacer(1, 10))

    # ═════════════════════════════════════════════════════════════
    # 3. TECHNICAL DETAILS
    # ═════════════════════════════════════════════════════════════
    E.append(CondPageBreak(8 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(3, 'Technical Details', 'Domain, certificate and URL characteristics'))
    E.append(Spacer(1, 12))

    if domain_info:
        E.append(SubHeader('Domain Information', COLORS['accent']))
        E.append(kv_table([
            ('Age', str(domain_info.get('age_human', 'N/A')), None),
            ('Registrar', clip(domain_info.get('registrar', 'N/A'), 60), None),
            ('Created', str(domain_info.get('created', 'N/A'))[:10], None),
            ('Expires', str(domain_info.get('expiry', 'N/A'))[:10], None),
            ('DNSSEC', yes_no(domain_info.get('dnssec'), 'Enabled', 'Disabled'),
             'good' if domain_info.get('dnssec') else 'warn'),
        ]))
        E.append(Spacer(1, 18))

    if ssl_vet:
        E.append(SubHeader('SSL / TLS Certificate', COLORS['accent']))
        E.append(kv_table([
            ('HTTPS', yes_no(ssl_vet.get('has_tls'), 'Yes', 'No'),
             'good' if ssl_vet.get('has_tls') else 'bad'),
            ('Chain Validity', yes_no(ssl_vet.get('chain_valid'), 'Valid', 'Invalid'),
             'good' if ssl_vet.get('chain_valid') else 'bad'),
            ('Issuer', clip(ssl_vet.get('issuer', 'N/A'), 60), None),
            ('Expires', str(ssl_vet.get('not_after', 'N/A'))[:10], None),
        ]))
        E.append(Spacer(1, 18))

    if feats:
        kw = feats.get('keywords_found', []) or []
        E.append(SubHeader('URL Security Features', COLORS['accent']))
        E.append(kv_table([
            ('URL Shortener', yes_no(feats.get('url_shortener'), 'Detected', 'Not used'),
             'warn' if feats.get('url_shortener') else 'good'),
            ('Uses IP Address', yes_no(feats.get('uses_ip'), 'Yes', 'No'),
             'warn' if feats.get('uses_ip') else 'good'),
            ('Punycode', yes_no(feats.get('contains_punycode'), 'Detected', 'Not used'),
             'warn' if feats.get('contains_punycode') else 'good'),
            ('Homoglyph Attack', yes_no(feats.get('has_homoglyph'), 'Detected', 'None'),
             'warn' if feats.get('has_homoglyph') else 'good'),
            ('Sensitive Keywords',
             ', '.join(str(k) for k in kw) if feats.get('has_keywords') and kw
             else ('Found' if feats.get('has_keywords') else 'None'),
             'warn' if feats.get('has_keywords') else 'good'),
        ]))
        E.append(Spacer(1, 18))

    E.append(SubHeader('Phishing & Typosquatting', COLORS['accent']))
    E.append(kv_table([
        ('PhishTank', yes_no(phishing.get('in_database'), 'Listed', 'Clean'),
         'bad' if phishing.get('in_database') else 'good'),
        ('Typosquatting', yes_no(typo.get('is_suspicious'), 'Detected', 'Clean'),
         'bad' if typo.get('is_suspicious') else 'good'),
    ]))
    E.append(Spacer(1, 18))

    for title, data in (('Additional url.vet Analysis', analysis_vet),
                        ('Local Engine - SSL', ssl_local),
                        ('Local Engine - DNS Records', dns_records)):
        rows = generic_rows(data)
        if rows:
            block = [SubHeader(title, COLORS['accent']), kv_table(rows)]
            if len(rows) < 8:
                E.append(KeepTogether(block))
            else:
                E.extend(block)
            E.append(Spacer(1, 18))

    # ═════════════════════════════════════════════════════════════
    # 4. SECURITY POSTURE BREAKDOWN
    # ═════════════════════════════════════════════════════════════
    E.append(CondPageBreak(9 * cm))
    E.append(Spacer(1, 6))
    E.append(SectionHeader(4, 'Security Posture', 'Score breakdown derived from the collected signals'))
    E.append(Spacer(1, 12))
    E.append(ScoreBars(compute_posture(trust, local, domain_info, ssl_vet,
                                       feats, phishing, typo)))

    # ═════════════════════════════════════════════════════════════
    # 5. RECOMMENDATIONS
    # ═════════════════════════════════════════════════════════════
    E.append(CondPageBreak(8 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(5, 'Security Recommendations', 'Suggested actions based on the findings'))
    E.append(Spacer(1, 12))
    rec_items = recs if recs else DEFAULT_RECOMMENDATIONS.get(vkey, ['Do not treat incomplete checks as confirmation of safety. Verify the destination independently.'])
    E.append(numbered_table(rec_items))

    # ═════════════════════════════════════════════════════════════
    # 6. METHODOLOGY & DISCLAIMER
    # ═════════════════════════════════════════════════════════════
    E.append(CondPageBreak(10 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(6, 'Methodology & Disclaimer', 'How to read this report'))
    E.append(Spacer(1, 12))
    E.append(Paragraph(
        'Scores range from 0 to 100, where a higher value indicates a more '
        'favorable evidence index. The overall score combines capped transport, identity, '
        'content, behavior and reputation categories, counting duplicate signals once. '
        'Verified threat matches override high source scores. Unverified reports '
        'and unavailable checks prevent confirmation of safety.', st['body']))
    E.append(Spacer(1, 10))
    E.append(legend_table())
    E.append(Spacer(1, 12))
    E.append(Paragraph(
        'This report reflects the state of the target at the time of the scan. '
        'Websites change quickly, so results may differ over time. The '
        'assessment is provided for informational purposes and does not '
        'constitute a guarantee of safety. MyScanner is not liable for '
        'decisions taken solely on the basis of this report.', st['muted']))
    E.append(Spacer(1, 22))

    footer = Table([[[
        Paragraph('Report generated by MyScanner Advanced Cybersecurity Platform', st['foot1']),
        Paragraph('https://myscanners.com  |  info@myscanners.com', st['foot2']),
        Paragraph(f'(c) {now.year} MyScanner. All rights reserved.  |  Confidential Report',
                  st['foot3']),
    ]]], colWidths=[CW])
    footer.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLORS['card_bg']),
        ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEABOVE', (0, 0), (-1, 0), 2, COLORS['accent']),
        ('TOPPADDING', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
    ]))
    E.append(KeepTogether([footer]))

    doc.build(E)
    buffer.seek(0)
    return buffer
