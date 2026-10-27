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
from pathlib import Path
import unicodedata

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table,
    TableStyle, Flowable, PageBreak, NextPageTemplate, CondPageBreak,
    KeepTogether,
)

# ═════════════════════════════════════════════════════════════════
# الأبعاد والألوان
# ═════════════════════════════════════════════════════════════════
# DejaVu (a free font with every Turkish letter: ğ ş ı İ); the built-in PDF fonts lack them.
FONT_DIR = Path(__file__).with_name('fonts')
for _name, _file in (('MS', 'DejaVuSans.ttf'), ('MS-Bold', 'DejaVuSans-Bold.ttf'), ('MS-Mono', 'DejaVuSansMono.ttf')):
    if _name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(_name, str(FONT_DIR / _file)))

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
    # Emoji and symbols (🚩, ⚠️) have no glyph in a PDF font and print as boxes.
    text = ''.join(c for c in str(v) if unicodedata.category(c) != 'So' and c not in '\ufe0f\u200d')
    return escape(text.strip())


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
# The report's tones, coloured as on the site.
TONE_COLORS = {'danger': COLORS['red'], 'caution': COLORS['yellow'], 'unknown': COLORS['muted'],
               'safe': COLORS['green'], 'info': COLORS['accent']}
LEGEND = [
    ('danger', 'DANGEROUS', 'A threat list, our antivirus or the site’s own host confirms it is dangerous.'),
    ('danger', 'HIGH RISK', 'Strong warning signs together, or a trick in the address. Treat it as unsafe.'),
    ('caution', 'BE CAREFUL', 'Signs common on scam pages. Don’t enter passwords or card details.'),
    ('unknown', 'NOT SURE', 'Some checks couldn’t run, so we can’t call it safe.'),
    ('safe', 'LOOKS SAFE', 'No warning signs in the checks we ran. This is not a guarantee of safety.'),
]
# Evidence categories of the assessment, as the site names them.
COMPONENTS = [('transport', 'Connection security'), ('identity', 'Address and name'), ('content', 'Page content'),
              ('behavior', 'Redirects'), ('reputation', 'Threat intelligence')]
# Values url.vet sends when it has nothing to report.
EMPTY_VALUES = {'', 'N/A', 'None', '0001-01-01', '0001-01-01T00:00:00Z', 'Unknown'}

PDF_TR = {
    'ADVANCED CYBERSECURITY PLATFORM': 'GELİŞMİŞ SİBER GÜVENLİK PLATFORMU',
    'LINK SECURITY REPORT': 'BAĞLANTI GÜVENLİK RAPORU',
    'An evidence-based check of one link': 'Tek bir bağlantının kanıta dayalı kontrolü',
    'EVIDENCE INDEX': 'KANIT ENDEKSİ', 'OUT OF 100': '100 ÜZERİNDEN', 'INCOMPLETE': 'EKSİK',
    'CHECKED LINK': 'KONTROL EDİLEN BAĞLANTI', 'SCANNED': 'TARAMA', 'REPORT ID': 'RAPOR NO',
    'PREPARED FOR': 'HAZIRLANDIĞI KİŞİ', 'CONFIDENTIAL REPORT': 'GİZLİ RAPOR', 'CONFIDENTIAL': 'GİZLİ', 'Page': 'Sayfa',
    'SUMMARY': 'ÖZET', 'What this report means for you': 'Bu rapor senin için ne anlama geliyor',
    'WARNINGS': 'UYARI', 'FINE': 'SORUNSUZ', 'NOT CHECKED': 'KONTROL EDİLMEDİ',
    'out of 100': '100 üzerinden', 'in the checks': 'kontrollerde', 'checks': 'kontrol',
    'What to do': 'Ne yapmalı', 'What we checked': 'Neleri kontrol ettik', 'Good to know': 'Bilmekte fayda var',
    'TECHNICAL EVIDENCE': 'TEKNİK KANITLAR', 'For experts: how the verdict was reached': 'Uzmanlar için: sonuca nasıl ulaşıldı',
    'Scan overview': 'Tarama özeti', 'Checked link': 'Kontrol edilen bağlantı', 'Final address': 'Son adres',
    'Scanned': 'Tarama zamanı', 'Report generated': 'Rapor oluşturuldu', 'Report ID': 'Rapor no', 'Prepared for': 'Hazırlandığı kişi',
    'Policy': 'Politika', 'Sources': 'Kaynaklar', 'Evidence by category': 'Kategoriye göre kanıtlar',
    'Not assessed': 'Değerlendirilmedi', 'No deductions': 'Kesinti yok', 'points deducted': 'puan düşüldü',
    'Findings': 'Bulgular', 'pts': 'puan', 'Checks that couldn’t run': 'Çalıştırılamayan kontroller',
    'URL.VET OBSERVATIONS': 'URL.VET GÖZLEMLERİ',
    'Inputs from url.vet. They inform the verdict but don’t decide it.': 'url.vet’ten gelen girdiler. Sonucu etkiler ama tek başına belirlemez.',
    'Warnings from url.vet': 'url.vet uyarıları', 'Positive signals': 'Olumlu işaretler', 'Notes': 'Notlar',
    'Domain information': 'Alan adı bilgileri', 'Age': 'Yaş', 'Registrar': 'Kayıt şirketi', 'Created': 'Oluşturulma',
    'Expires': 'Bitiş', 'Enabled': 'Açık', 'Disabled': 'Kapalı', 'Certificate (url.vet)': 'Sertifika (url.vet)',
    'Certificate chain': 'Sertifika zinciri', 'Valid': 'Geçerli', 'Invalid': 'Geçersiz', 'Issuer': 'Yayıncı',
    'Yes': 'Evet', 'No': 'Hayır', 'Not available': 'Mevcut değil',
    'Address features (url.vet)': 'Adres özellikleri (url.vet)', 'URL shortener': 'URL kısaltıcı', 'Uses an IP address': 'IP adresi kullanıyor',
    'Punycode': 'Punycode', 'Look-alike letters': 'Benzer harfler', 'Sensitive keywords': 'Hassas anahtar kelimeler',
    'Detected': 'Tespit edildi', 'Not used': 'Kullanılmıyor', 'None': 'Yok', 'Found': 'Bulundu',
    'PhishTank (via url.vet)': 'PhishTank (url.vet üzerinden)', 'Listed': 'Listede', 'Not listed': 'Listede değil',
    'Our certificate check': 'Kendi sertifika kontrolümüz', 'DNS records': 'DNS kayıtları',
    'FIELD': 'ALAN', 'VALUE': 'DEĞER', 'STATUS': 'DURUM', 'PASS': 'GEÇTİ', 'WARNING': 'UYARI', 'FAIL': 'BAŞARISIZ', 'INFO': 'BİLGİ',
    'CHECK': 'KONTROL', 'RESULT': 'SONUÇ', 'VERDICT': 'SONUÇ', 'MEANING': 'ANLAMI',
    'HOW TO READ THIS REPORT': 'BU RAPOR NASIL OKUNUR', 'Verdicts and limits': 'Sonuçlar ve sınırlar',
    'The verdict comes from MyScanner’s checks: threat lists, the address itself, the page, its redirects and an antivirus scan, weighed together. The evidence index (0–100) summarises the deductions; it is not a probability, and the verdict can be stricter than the number when a strong sign is found.':
        'Sonuç, MyScanner’ın kontrollerinden gelir: tehdit listeleri, adresin kendisi, sayfa, yönlendirmeleri ve antivirüs taraması birlikte değerlendirilir. Kanıt endeksi (0–100) kesintileri özetler; bir olasılık değildir ve güçlü bir işaret bulunduğunda sonuç bu sayıdan daha katı olabilir.',
    'This report reflects the link at the time of the scan. Websites change quickly, so results may differ later. It is information, not a guarantee of safety.':
        'Bu rapor, bağlantının tarama anındaki durumunu yansıtır. Web siteleri hızla değişir, bu yüzden sonuçlar daha sonra farklı olabilir. Bu bir bilgilendirmedir, güvenlik garantisi değildir.',
    'Report generated by MyScanner': 'Bu rapor MyScanner tarafından oluşturuldu', 'All rights reserved.': 'Tüm hakları saklıdır.',
    'DANGEROUS': 'TEHLİKELİ', 'HIGH RISK': 'YÜKSEK RİSK', 'BE CAREFUL': 'DİKKATLİ OL', 'NOT SURE': 'EMİN DEĞİLİZ', 'LOOKS SAFE': 'GÜVENLİ GÖRÜNÜYOR',
    'A threat list, our antivirus or the site’s own host confirms it is dangerous.': 'Bir tehdit listesi, antivirüsümüz ya da sitenin kendi barındırıcısı tehlikeli olduğunu doğruluyor.',
    'Strong warning signs together, or a trick in the address. Treat it as unsafe.': 'Birlikte güçlü uyarı işaretleri ya da adreste bir hile var. Güvensiz kabul et.',
    'Signs common on scam pages. Don’t enter passwords or card details.': 'Dolandırıcılık sayfalarında yaygın işaretler. Şifre ya da kart bilgisi girme.',
    'Some checks couldn’t run, so we can’t call it safe.': 'Bazı kontroller çalıştırılamadı, bu yüzden güvenli diyemeyiz.',
    'No warning signs in the checks we ran. This is not a guarantee of safety.': 'Çalıştırdığımız kontrollerde uyarı işareti yok. Bu bir güvenlik garantisi değildir.',
    'Certificate check unavailable': 'Sertifika kontrolü yapılamadı',
    'HTTP header check unavailable': 'HTTP başlık kontrolü yapılamadı',
    'URLVet assessment unavailable or incomplete': 'url.vet değerlendirmesi eksik ya da alınamadı',
    'URLVet domain registration (WHOIS) check unavailable': 'url.vet alan adı kaydı (WHOIS) kontrolü yapılamadı',
    'Deep page content was not assessed': 'Sayfa içeriği değerlendirilmedi',
    'Redirect behavior was not assessed': 'Yönlendirmeler değerlendirilmedi',
    'Phishing database evidence is unverified or unavailable': 'Oltalama veri tabanı kanıtı doğrulanmadı ya da alınamadı',
    'Redirect destination of the short link could not be reached': 'Kısa bağlantının hedefine ulaşılamadı',
    'Transport evidence unavailable': 'Bağlantı güvenliği kanıtı yok', 'Identity evidence unavailable': 'Adres kanıtı yok',
    'Content evidence unavailable': 'Sayfa içeriği kanıtı yok', 'Behavior evidence unavailable': 'Yönlendirme kanıtı yok',
    'Reputation evidence unavailable': 'Tehdit istihbaratı kanıtı yok',
    'Error': 'Hata', 'A Records': 'A kayıtları', 'Aaaa Records': 'AAAA kayıtları', 'Mx Records': 'MX kayıtları',
    'Ns Records': 'NS kayıtları', 'Txt Records': 'TXT kayıtları', 'Has Spf': 'SPF kaydı', 'Has Dmarc': 'DMARC kaydı',
    'Subject': 'Konu', 'Days Left': 'Kalan gün', 'Days Until Expiry': 'Bitişe kalan gün', 'Version': 'Sürüm',
    'Connection security': 'Bağlantı güvenliği', 'Address and name': 'Adres ve alan adı', 'Page content': 'Sayfa içeriği',
    'Redirects': 'Yönlendirmeler', 'Threat intelligence': 'Tehdit istihbaratı',
}


def translator(lang):
    """Text in the report's language: the PDF's own words first, then the site's report catalog."""
    if lang != 'tr':
        return lambda text: text
    from services.site_i18n import _catalogs, _lookup
    catalog = _catalogs()['tr']

    def t(text):
        if not isinstance(text, str) or not text:
            return text
        return PDF_TR.get(text) or _lookup(text, catalog, 'tr') or text
    return t


def upper(text, lang):
    """Upper case that keeps Turkish dotted and dotless i apart (istihbarat → İSTİHBARAT)."""
    if lang == 'tr':
        text = text.replace('i', 'İ').replace('ı', 'I')
    return text.upper()


def missing_text(messages):
    """The checks that couldn't run, once each, in words a reader understands ("local"/"deep" dropped)."""
    seen = []
    for message in messages:
        text = message.removeprefix('local ').removeprefix('deep ').strip()
        text = text[:1].upper() + text[1:]
        if text and text not in seen:
            seen.append(text)
    return seen


def age_words(text, lang):
    """url.vet's "8 years 10 months" in the report's language."""
    if lang != 'tr' or not isinstance(text, str):
        return text
    import re
    return re.sub(r'(\d+) months?', r'\1 ay', re.sub(r'(\d+) years?', r'\1 yıl', re.sub(r'(\d+) days?', r'\1 gün', text)))


def present(value):
    """A url.vet value worth printing, or None for its "nothing to report" placeholders."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return None if text in EMPTY_VALUES or text.startswith('0001-01-01') else text


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
        'body': ps('Body', fontName='MS', fontSize=9.5, leading=15,
                   textColor=white),
        'body_url': ps('BodyUrl', fontName='MS', fontSize=9.5, leading=15,
                       textColor=white, wordWrap='CJK'),
        'muted': ps('Muted', fontName='MS', fontSize=8.5, leading=13,
                    textColor=muted),
        'th': ps('TH', fontName='MS-Bold', fontSize=7.5, leading=10,
                 textColor=accent),
        'th_c': ps('THC', fontName='MS-Bold', fontSize=7.5, leading=10,
                   textColor=accent, alignment=TA_CENTER),
        'cell': ps('Cell', fontName='MS', fontSize=8.5, leading=12,
                   textColor=white, wordWrap='CJK'),
        'cell_label': ps('CellLabel', fontName='MS-Bold', fontSize=8,
                         leading=11, textColor=muted),
        'cell_c': ps('CellC', fontName='MS', fontSize=8.5, leading=12,
                     textColor=white, alignment=TA_CENTER),
        'status': ps('Status', fontName='MS-Bold', fontSize=7.5,
                     leading=10, alignment=TA_CENTER),
        'flag': ps('Flag', fontName='MS', fontSize=9, leading=13,
                   textColor=white, wordWrap='CJK'),
        'icon': ps('Icon', fontName='MS-Bold', fontSize=11, leading=13,
                   alignment=TA_CENTER),
        'banner_title': ps('BannerTitle', fontName='MS-Bold', fontSize=15,
                           leading=19),
        'banner_text': ps('BannerText', fontName='MS', fontSize=9,
                          leading=14, textColor=white),
        'foot1': ps('Foot1', fontName='MS-Bold', fontSize=10, leading=14,
                    textColor=accent, alignment=TA_CENTER),
        'foot2': ps('Foot2', fontName='MS', fontSize=8.5, leading=13,
                    textColor=muted, alignment=TA_CENTER),
        'foot3': ps('Foot3', fontName='MS', fontSize=7.5, leading=11,
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
    f = 'MS-Bold'
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
    draw_spaced(c, cx, PAGE_H - 207, ctx['t']('ADVANCED CYBERSECURITY PLATFORM'),
                'MS', 8.5, 3)
    c.setStrokeColor(accent)
    c.setLineWidth(2)
    c.line(cx - 40, PAGE_H - 224, cx + 40, PAGE_H - 224)

    # عنوان التقرير
    c.setFillColor(COLORS['white'])
    c.setFont('MS-Bold', 22)
    c.drawCentredString(cx, PAGE_H - 266, ctx['t']('LINK SECURITY REPORT'))
    c.setFillColor(COLORS['muted'])
    c.setFont('MS', 10)
    c.drawCentredString(cx, PAGE_H - 290, ctx['t']('An evidence-based check of one link'))

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
    draw_spaced(c, cx, gy + 36, ctx['t']('EVIDENCE INDEX'), 'MS-Bold', 8, 2.5)
    c.setFillColor(vcol)
    c.setFont('MS-Bold', 50)
    c.drawCentredString(cx, gy - 16, ctx.get('score_display', str(ctx['trust'])))
    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, gy - 35, ctx['t']('INCOMPLETE' if ctx.get('incomplete') else 'OUT OF 100'), 'MS', 7.5, 2)

    # شارة الحكم
    label = ctx['vlabel']
    pw = stringWidth(label, 'MS-Bold', 15) + 76
    py = gy - r - 62
    c.setFillColor(mix(vcol, bg, 0.16))
    c.setStrokeColor(vcol)
    c.setLineWidth(1.2)
    c.roundRect(cx - pw / 2, py, pw, 36, 18, fill=1, stroke=1)
    c.setFillColor(vcol)
    c.circle(cx - pw / 2 + 22, py + 18, 5, fill=1, stroke=0)
    c.setFont('MS-Bold', 15)
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
    draw_spaced(c, bx + 20, ty + 47, ctx['t']('CHECKED LINK'), 'MS-Bold', 7.5, 2,
                align='left')
    c.setFillColor(COLORS['white'])
    c.setFont('MS-Mono', 10)
    c.drawString(bx + 20, ty + 24,
                 fit_text(ctx['url'], 'MS-Mono', 10, bw - 40))

    # بطاقات المعلومات
    gap = 10
    mw = (bw - 2 * gap) / 3
    meta = [
        (ctx['t']('SCANNED'), ctx['scanned']),
        (ctx['t']('REPORT ID'), ctx['report_id']),
        (ctx['t']('PREPARED FOR'), ctx['username']),
    ]
    for i, (lab, val) in enumerate(meta):
        x = bx + i * (mw + gap)
        c.setFillColor(COLORS['card_bg'])
        c.setStrokeColor(COLORS['border'])
        c.roundRect(x, 112, mw, 60, 10, fill=1, stroke=1)
        c.setFillColor(COLORS['muted'])
        draw_spaced(c, x + 14, 112 + 40, lab, 'MS-Bold', 7, 2,
                    align='left')
        c.setFillColor(COLORS['white'])
        c.setFont('MS-Bold', 10)
        c.drawString(x + 14, 112 + 20,
                     fit_text(val, 'MS-Bold', 10, mw - 28))

    c.setFillColor(COLORS['muted'])
    draw_spaced(c, cx, 62, ctx['t']('CONFIDENTIAL REPORT') + '  |  MYSCANNERS.COM',
                'MS', 7, 2.5)
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
    c.setFont('MS-Mono', 7.5)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 30,
                      f'{ctx["t"]("LINK SECURITY REPORT")}  |  {ctx["report_id"]}')
    c.setStrokeColor(COLORS['border'])
    c.setLineWidth(0.6)
    c.line(MARGIN, PAGE_H - 44, PAGE_W - MARGIN, PAGE_H - 44)

    # التذييل
    c.line(MARGIN, 40, PAGE_W - MARGIN, 40)
    c.setFont('MS', 7)
    c.setFillColor(COLORS['muted'])
    c.drawString(MARGIN, 26, 'MyScanner  |  myscanners.com')
    c.setFillColor(COLORS['accent'])
    draw_spaced(c, PAGE_W / 2, 26, ctx['t']('CONFIDENTIAL'), 'MS-Bold', 7, 1.5)
    c.setFillColor(COLORS['muted'])
    c.setFont('MS', 7)
    c.drawRightString(PAGE_W - MARGIN, 26, f'{ctx["t"]("Page")} {doc.page}')
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
        c.setFont('MS-Bold', 14)
        c.drawCentredString(14, 21, str(self.number))
        c.setFillColor(COLORS['white'])
        c.setFont('MS-Bold', 16)
        c.drawString(40, 27 if self.subtitle else 21, self.title)
        if self.subtitle:
            c.setFillColor(COLORS['muted'])
            c.setFont('MS', 8)
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
        c.setFont('MS-Bold', 11)
        c.drawString(12, 8.5, self.title)
        if self.count is not None:
            tw = stringWidth(self.title, 'MS-Bold', 11)
            s = str(self.count)
            bw = stringWidth(s, 'MS-Bold', 8) + 14
            c.setFillColor(mix(self.color, COLORS['dark_bg'], 0.2))
            c.setStrokeColor(self.color)
            c.setLineWidth(0.6)
            c.roundRect(12 + tw + 8, 4.5, bw, 15, 7.5, fill=1, stroke=1)
            c.setFillColor(self.color)
            c.setFont('MS-Bold', 8)
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
            draw_spaced(c, x + 14, h - 20, label, 'MS-Bold', 6.8, 1.6,
                        align='left')
            c.setFillColor(col)
            c.setFont('MS-Bold', 25)
            c.drawString(x + 14, 22, str(value))
            c.setFillColor(COLORS['muted'])
            c.setFont('MS', 7.5)
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
            draw_spaced(c, (x0 + x1) / 2, bar_y - 14, name, 'MS-Bold',
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
        c.setFont('MS-Bold', 8)
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
            col = COLORS['muted'] if score is None else score_color(score)
            c.setFillColor(COLORS['white'])
            c.setFont('MS-Bold', 9)
            c.drawString(16, y + 18, label)
            c.setFillColor(COLORS['muted'])
            c.setFont('MS', 7.2)
            c.drawString(16, y + 7, fit_text(detail, 'MS', 7.2, x0 - 30))

            c.setFillColor(COLORS['border'])
            c.roundRect(x0, y + 13, x1 - x0, 8, 4, fill=1, stroke=0)
            if score:
                c.setFillColor(col)
                c.roundRect(x0, y + 13, max(8, (x1 - x0) * score / 100), 8, 4,
                            fill=1, stroke=0)
            c.setFillColor(col)
            c.setFont('MS-Bold', 10)
            c.drawRightString(W - 16, y + 12, '—' if score is None else f'{score}/100')
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


def kv_table(rows, t=lambda text: text):
    """جدول (Field | Value | Status) بتلوين حسب الحالة"""
    st = get_styles()
    data = [[Paragraph(t('FIELD'), st['th']), Paragraph(t('VALUE'), st['th']),
             Paragraph(t('STATUS'), st['th_c'])]]
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
            Paragraph(f'<font color="{hx(col)}">{t(text)}</font>', st['status']),
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
        Paragraph(f'<font color="{hx(vcol)}">{esc(vlabel)}</font>',
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


def verdict_legend(t):
    """What each verdict on the report means, in the same words and colours as the site."""
    st = get_styles()
    data = [[Paragraph(t('VERDICT'), st['th_c']), Paragraph(t('MEANING'), st['th'])]]
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
    for i, (tone, label, meaning) in enumerate(LEGEND, start=1):
        col = TONE_COLORS[tone]
        data.append([Paragraph(f'<font color="{hx(col)}">{esc(t(label))}</font>', st['status']),
                     Paragraph(esc(t(meaning)), st['cell'])])
        style.append(('BACKGROUND', (0, i), (0, i), mix(col, COLORS['card_bg'], 0.14)))
    table = Table(data, colWidths=[0.24 * CW, 0.76 * CW])
    table.setStyle(TableStyle(style))
    return table


def reasons_table(reasons):
    """The report's "why we think so" list, each with its own colour and mark."""
    st = get_styles()
    marks = {'bad': (COLORS['red'], '!'), 'warn': (COLORS['yellow'], '!'), 'info': (COLORS['accent'], 'i'),
             'ok': (COLORS['green'], '+'), 'na': (COLORS['muted'], '–')}
    data, style = [], [
        ('BACKGROUND', (1, 0), (1, -1), COLORS['card_bg']),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('LINEAFTER', (-1, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEABOVE', (0, 0), (-1, 0), 0.7, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8), ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (1, 0), (1, -1), 12), ('RIGHTPADDING', (1, 0), (1, -1), 12),
    ]
    for i, reason in enumerate(reasons):
        col, mark = marks.get(reason.get('tone'), marks['info'])
        data.append([Paragraph(f'<font color="{hx(col)}">{mark}</font>', st['icon']),
                     Paragraph(f'<b>{esc(reason.get("title", ""))}</b><br/>'
                               f'<font color="{hx(COLORS["muted"])}">{esc(reason.get("detail", ""))}</font>', st['flag'])])
        style += [('BACKGROUND', (0, i), (0, i), mix(col, COLORS['card_bg'], 0.14)), ('LINEBEFORE', (0, i), (0, i), 3, col)]
    table = Table(data, colWidths=[1.0 * cm, CW - 1.0 * cm])
    table.setStyle(TableStyle(style))
    return table


def checks_table(checks, t):
    """The report's "what we checked" list: check, result, and the state colour."""
    st = get_styles()
    states = {'bad': COLORS['red'], 'warn': COLORS['yellow'], 'ok': COLORS['green'], 'info': COLORS['accent'], 'na': COLORS['muted']}
    data = [[Paragraph(t('CHECK'), st['th']), Paragraph(t('RESULT'), st['th_c'])]]
    style = [
        ('BOX', (0, 0), (-1, -1), 0.7, COLORS['border']),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, COLORS['border']),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 11), ('RIGHTPADDING', (0, 0), (-1, -1), 11),
        ('BACKGROUND', (0, 0), (-1, 0), mix(COLORS['accent'], COLORS['dark_bg'], 0.16)),
        ('LINEBELOW', (0, 0), (-1, 0), 1.2, COLORS['accent']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['card_bg'], COLORS['surface']]),
    ]
    for i, check in enumerate(checks, start=1):
        col = states.get(check.get('state'), COLORS['muted'])
        data.append([Paragraph(esc(check.get('name', '')), st['cell']),
                     Paragraph(f'<font color="{hx(col)}"><b>{esc(check.get("result", ""))}</b></font>', st['cell_c'])])
        style.append(('BACKGROUND', (1, i), (1, i), mix(col, COLORS['card_bg'], 0.14)))
    table = Table(data, colWidths=[0.62 * CW, 0.38 * CW], repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


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
# الدالة الرئيسية
# ═════════════════════════════════════════════════════════════════
def generate_vulnerability_report(scan, analysis, username, deep=None, lang='en'):
    """The URL report as a PDF, built from the same verdict and plain summary the site shows.

    analysis: the saved quick analysis with its aggregate_assessment; deep: the saved deep
    analysis; lang: 'en' or 'tr'. Returns a BytesIO.
    """
    from services.report_i18n import translate_plain
    from services.url_report_view import plain_report

    st = get_styles()
    analysis = analysis if isinstance(analysis, dict) else {}
    deep = deep if isinstance(deep, dict) else analysis.get('deep_analysis') if isinstance(analysis.get('deep_analysis'), dict) else {}
    lang = 'tr' if lang == 'tr' else 'en'
    t = translator(lang)

    url = str(getattr(scan, 'url', '') or 'N/A')
    from services.url_assessment import assess_url
    aggregate = analysis.get('aggregate_assessment') or assess_url(analysis, deep)
    plain = plain_report(aggregate, analysis, deep, url)
    if lang != 'en':
        plain = translate_plain(plain, lang)
    tone = plain.get('tone') if plain.get('tone') in TONE_COLORS else 'unknown'
    vcol = TONE_COLORS[tone]
    score = aggregate.get('score')

    urlvet = analysis.get('urlvet', {}) or {}
    domain_info = urlvet.get('domain_info', {}) or {}
    ssl_vet = urlvet.get('ssl_info', {}) or {}
    feats = urlvet.get('url_features', {}) or {}
    analysis_vet = urlvet.get('analysis', {}) or {}
    phishing = urlvet.get('phishing', {}) or {}

    try:
        report_id = f'MYS-{int(scan.id):06d}'
    except (TypeError, ValueError, AttributeError):
        report_id = 'MYS-000000'
    now = datetime.now(timezone.utc)
    scanned_at = getattr(scan, 'date_posted', None) or getattr(scan, 'created_at', None)
    try:
        scanned = scanned_at.strftime('%Y-%m-%d %H:%M UTC')
    except AttributeError:
        scanned = now.strftime('%Y-%m-%d %H:%M UTC')
    username = str(username or 'N/A')

    ctx = {
        't': t, 'incomplete': score is None, 'trust': to_num(score or 0), 'score_display': str(score) if score is not None else 'N/A',
        'vcolor': vcol, 'vlabel': plain.get('label') or '', 'url': url, 'scanned': scanned, 'report_id': report_id, 'username': username,
    }

    buffer = BytesIO()
    doc = BaseDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=2 * cm, bottomMargin=2 * cm,
        title=f'MyScanner - {url}', author='MyScanner', subject=t('LINK SECURITY REPORT'), creator='MyScanner',
    )
    cover_frame = Frame(MARGIN, PAGE_H / 2, CW, 20, id='cover', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body_frame = Frame(MARGIN, 2 * cm, CW, PAGE_H - 2 * cm - 64, id='body', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id='cover', frames=[cover_frame], onPage=lambda c, d: draw_cover(c, ctx)),
        PageTemplate(id='content', frames=[body_frame], onPage=lambda c, d: draw_content_page(c, d, ctx)),
    ])

    E = [Spacer(1, 1), NextPageTemplate('content'), PageBreak()]

    # 1. SUMMARY: the same verdict, reasons, actions and checks as the report on the site.
    E.append(SectionHeader(1, t('SUMMARY'), t('What this report means for you')))
    E.append(Spacer(1, 12))
    E.append(verdict_banner(vcol, plain.get('headline') or plain.get('label') or '', plain.get('summary') or ''))
    E.append(Spacer(1, 12))
    checks = [c for c in plain.get('checks') or [] if isinstance(c, dict)]
    count = lambda *states: sum(c.get('state') in states for c in checks)
    E.append(StatCards([
        (t('EVIDENCE INDEX'), score if score is not None else 'N/A', t('out of 100'), vcol),
        (t('WARNINGS'), count('bad', 'warn'), t('in the checks'), COLORS['red'] if count('bad') else COLORS['yellow'] if count('warn') else COLORS['green']),
        (t('FINE'), count('ok'), f'{len(checks)} {t("checks")}', COLORS['green']),
        (t('NOT CHECKED'), count('na'), t('checks'), COLORS['muted']),
    ]))
    E.append(Spacer(1, 16))
    reasons = [r for r in plain.get('reasons') or [] if isinstance(r, dict)]
    if reasons:
        E.append(SubHeader(plain.get('why_title') or t('Why we think so'), vcol, len(reasons)))
        E.append(reasons_table(reasons))
        E.append(Spacer(1, 16))
    actions = [a for a in plain.get('actions') or [] if isinstance(a, str)]
    if actions:
        E.append(SubHeader(t('Good to know' if tone == 'safe' else 'What to do'), COLORS['accent']))
        E.append(numbered_table(actions))
        E.append(Spacer(1, 16))
    if checks:
        E.append(KeepTogether([SubHeader(t('What we checked'), COLORS['accent']), checks_table(checks, t)]))

    # 2. TECHNICAL EVIDENCE: how the verdict was reached.
    E.append(CondPageBreak(9 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(2, t('TECHNICAL EVIDENCE'), t('For experts: how the verdict was reached')))
    E.append(Spacer(1, 12))
    final_url = (deep.get('behavior') or {}).get('final_url') if isinstance(deep.get('behavior'), dict) else None
    overview = [(t('Checked link'), url, None)]
    if isinstance(final_url, str) and final_url and final_url != url:
        overview.append((t('Final address'), final_url, None))
    overview += [(t('Scanned'), scanned, None), (t('Report generated'), now.strftime('%Y-%m-%d %H:%M UTC'), None),
                 (t('Report ID'), report_id, None), (t('Prepared for'), username, None),
                 (t('Policy'), str(aggregate.get('policy_version') or '—'), None),
                 (t('Sources'), ', '.join(str(x) for x in aggregate.get('sources') or []) or '—', None)]
    E.append(SubHeader(t('Scan overview'), COLORS['accent']))
    E.append(kv_table(overview, t))
    E.append(Spacer(1, 18))

    components = aggregate.get('components') or {}
    bars = []
    for key, name in COMPONENTS:
        part = components.get(key) if isinstance(components.get(key), dict) else {}
        weight, taken = part.get('weight') or 0, part.get('deduction') or 0
        if part.get('status') != 'assessed' or not weight:
            bars.append((t(name), None, t('Not assessed')))
        else:
            bars.append((t(name), round(100 * (weight - taken) / weight), f'−{taken:g} {t("points deducted")}' if taken else t('No deductions')))
    E.append(KeepTogether([SubHeader(t('Evidence by category'), COLORS['accent']), ScoreBars(bars)]))
    E.append(Spacer(1, 18))

    findings = [r for r in aggregate.get('reasons') or [] if isinstance(r, dict) and r.get('message')]
    if findings:
        E.append(SubHeader(t('Findings'), COLORS['accent'], len(findings)))
        E.append(flag_table([f'{t(r["message"])}   (−{r.get("deduction", 0):g} {t("pts")})' if r.get('deduction') else t(r['message'])
                             for r in findings], 'info'))
        E.append(Spacer(1, 16))
    missing = [m for m in aggregate.get('missing_checks') or [] if isinstance(m, str)]
    if missing:
        E.append(SubHeader(t('Checks that couldn’t run'), COLORS['muted'], len(missing)))
        E.append(flag_table([t(m) for m in missing_text(missing)[:10]], 'info'))
        E.append(Spacer(1, 16))

    # 3. URL.VET OBSERVATIONS: inputs, never the verdict.
    E.append(CondPageBreak(8 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(3, t('URL.VET OBSERVATIONS'), t('Inputs from url.vet. They inform the verdict but don’t decide it.')))
    E.append(Spacer(1, 12))
    for title, items, kind, col in (('Warnings from url.vet', urlvet.get('red_flags'), 'red', COLORS['yellow']),
                                    ('Positive signals', urlvet.get('green_flags'), 'green', COLORS['green']),
                                    ('Notes', urlvet.get('neutral_reasons'), 'info', COLORS['accent'])):
        items = [age_words(t(flag_text(x)), lang) for x in (items or [])[:8] if esc(flag_text(x))]
        if items:
            E.append(SubHeader(t(title), col, len(items)))
            E.append(flag_table(items, 'info' if kind == 'red' else kind))
            E.append(Spacer(1, 14))

    yes = lambda flag, a='Yes', b='No': t(a) if flag else t(b)
    if domain_info:
        rows = [(t(label), value, None) for label, value in (('Age', age_words(present(domain_info.get('age_human')), lang)),
                                                             ('Registrar', present(domain_info.get('registrar'))),
                                                             ('Created', present(str(domain_info.get('created') or '')[:10])),
                                                             ('Expires', present(str(domain_info.get('expiry') or '')[:10]))) if value]
        rows.append((t('DNSSEC'), yes(domain_info.get('dnssec'), 'Enabled', 'Disabled'), 'good' if domain_info.get('dnssec') else 'warn'))
        E.append(KeepTogether([SubHeader(t('Domain information'), COLORS['accent']), kv_table(rows, t)]))
        E.append(Spacer(1, 16))
    if ssl_vet:
        rows = [('HTTPS', yes(ssl_vet.get('has_tls')), 'good' if ssl_vet.get('has_tls') else 'bad')]
        if ssl_vet.get('has_tls'):
            rows.append((t('Certificate chain'), yes(ssl_vet.get('chain_valid'), 'Valid', 'Invalid'), 'good' if ssl_vet.get('chain_valid') else 'bad'))
        for label, value in (('Issuer', present(ssl_vet.get('issuer'))), ('Expires', present(str(ssl_vet.get('not_after') or '')[:10]))):
            if value:
                rows.append((t(label), clip(value, 60), None))
        E.append(KeepTogether([SubHeader(t('Certificate (url.vet)'), COLORS['accent']), kv_table(rows, t)]))
        E.append(Spacer(1, 16))
    if feats:
        keywords = [str(k) for k in feats.get('keywords_found') or []]
        rows = [(t('URL shortener'), yes(feats.get('url_shortener'), 'Detected', 'Not used'), 'warn' if feats.get('url_shortener') else 'good'),
                (t('Uses an IP address'), yes(feats.get('uses_ip')), 'warn' if feats.get('uses_ip') else 'good'),
                (t('Punycode'), yes(feats.get('contains_punycode'), 'Detected', 'Not used'), 'warn' if feats.get('contains_punycode') else 'good'),
                (t('Look-alike letters'), yes(feats.get('has_homoglyph'), 'Detected', 'None'), 'warn' if feats.get('has_homoglyph') else 'good'),
                (t('Sensitive keywords'), ', '.join(keywords) if feats.get('has_keywords') and keywords else yes(feats.get('has_keywords'), 'Found', 'None'),
                 'warn' if feats.get('has_keywords') else 'good'),
                (t('PhishTank (via url.vet)'), yes(phishing.get('in_database'), 'Listed', 'Not listed'), 'bad' if phishing.get('in_database') else 'good')]
        E.append(KeepTogether([SubHeader(t('Address features (url.vet)'), COLORS['accent']), kv_table(rows, t)]))
        E.append(Spacer(1, 16))
    ssl_local = analysis.get('ssl', {}) or {}
    for title, data in (('Our certificate check', ssl_local), ('DNS records', analysis.get('dns', {}) or {})):
        rows = [(t(label), t(value) if value in ('Yes', 'No') else value, None) for label, value, _ in generic_rows(data) if present(value)]
        if rows:
            E.append(KeepTogether([SubHeader(t(title), COLORS['accent']), kv_table(rows, t)]))
            E.append(Spacer(1, 16))
    del analysis_vet  # url.vet's redirect view is covered by our own redirect evidence above

    # 4. HOW TO READ THIS REPORT
    E.append(CondPageBreak(10 * cm))
    E.append(Spacer(1, 22))
    E.append(SectionHeader(4, t('HOW TO READ THIS REPORT'), t('Verdicts and limits')))
    E.append(Spacer(1, 12))
    E.append(Paragraph(esc(t('The verdict comes from MyScanner’s checks: threat lists, the address itself, the page, its redirects and an antivirus scan, weighed together. The evidence index (0–100) summarises the deductions; it is not a probability, and the verdict can be stricter than the number when a strong sign is found.')), st['body']))
    E.append(Spacer(1, 10))
    E.append(verdict_legend(t))
    E.append(Spacer(1, 12))
    E.append(Paragraph(esc(t('This report reflects the link at the time of the scan. Websites change quickly, so results may differ later. It is information, not a guarantee of safety.')), st['muted']))
    E.append(Spacer(1, 22))
    footer = Table([[[
        Paragraph(esc(t('Report generated by MyScanner')), st['foot1']),
        Paragraph('https://myscanners.com  |  info@myscanners.com', st['foot2']),
        Paragraph(f'(c) {now.year} MyScanner. {esc(t("All rights reserved."))}', st['foot3']),
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
