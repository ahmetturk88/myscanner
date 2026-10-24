"""The "Pro coming soon" page: its text, the real early-access price, and interest tracking.

Nothing is sold here. The page shows what Pro will add and its planned price,
counts visits by where they came from, and keeps an email waitlist, so the
price can be tested before any payment system exists (docs/plan, stage 0).
"""
import re
from urllib.parse import urlparse

from extensions import db

EMAIL = re.compile(r'[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,24}')
SOURCE = re.compile(r'[a-z0-9_.-]{1,40}')
BOTS = re.compile(r'bot|crawl|spider|slurp|preview|monitor|curl|wget|python', re.I)

CONTENT = {
    'en': {
        'title': 'MyScanner Pro (coming soon)',
        'description': 'Check a message or a screenshot before you pay: links, IBANs and QR codes checked, with steps to verify it yourself. Early-access price $4.99 a month.',
        'eyebrow': 'MyScanner Pro · coming soon',
        'heading': 'Check it <em>before you pay.</em>',
        'lead': 'A cargo fee, a bank alert, a tax refund, a second-hand sale: send us the message or a screenshot, and see the evidence before you pay, tap or share anything.',
        'how_title': 'How it will work',
        'how': [
            'Paste the message, share it from any app, or upload a screenshot.',
            'We read the text on our own server and pull out every link, phone number, IBAN and QR code.',
            'Each link and QR code goes through our real checks: where it leads, how new the site is, whether it copies a brand, and threat lists.',
            'You get a clear answer with the reasons, and what we could not check.',
            'You get steps to verify it yourself, such as calling your bank on the number printed on your card.',
            'Already paid or shared a code? You get the steps for what happened: block the card, change the password, report it.',
        ],
        'plans_title': 'Free stays free',
        'free_name': 'Free',
        'free_price': '$0',
        'free': [
            'Every current tool: links, files, emails, QR codes, domains, IPs, SSL and passwords',
            '10 link checks a day',
            'A few message and screenshot checks to try it',
            'PDF reports',
        ],
        'pro_name': 'Pro',
        'pro_price': '$4.99',
        'pro_period': 'a month',
        'pro_note': 'Planned early-access price. Monthly, cancel any time. The first members get a founding discount.',
        'pro': [
            'Message and screenshot checks: 60 screenshots a month',
            'Higher daily limits on every tool, shown clearly',
            'Searchable history for 90 days, with export and delete',
            'Detailed PDF reports you can keep or send',
        ],
        'honest_title': 'What we promise, and what we don’t',
        'honest': [
            'We show evidence and explain it. No tool can promise that something is 100% safe.',
            'A screenshot can’t prove who sent a message, and a valid IBAN doesn’t prove who owns it. We say so in every report.',
            'Your screenshot will be deleted within 24 hours of the check and will never leave our server.',
        ],
        'form_title': 'Tell me when Pro opens',
        'form_lead': 'No payment now. We’ll email you once when Pro opens. You can ask us to delete your email any time.',
        'email_label': 'Email',
        'submit': 'Notify me',
        'thanks': 'Thanks! We’ll email you once when Pro opens.',
        'invalid': 'Please enter a valid email address.',
        'try_free': 'Try the free link check',
    },
    'tr': {
        'title': 'MyScanner Pro (yakında)',
        'description': 'Ödemeden önce mesajı ya da ekran görüntüsünü kontrol et: linkler, IBAN’lar ve QR kodlar incelenir, kendin doğrulaman için adımlar verilir. Erken erişim fiyatı ayda ₺199.',
        'eyebrow': 'MyScanner Pro · yakında',
        'heading': '<em>Ödemeden önce</em> kontrol et.',
        'lead': 'Kargo ücreti, banka uyarısı, vergi iadesi, ikinci el satış: mesajı ya da ekran görüntüsünü bize gönder; ödemeden, tıklamadan ya da bir şey paylaşmadan önce kanıtı gör.',
        'how_title': 'Nasıl çalışacak',
        'how': [
            'Mesajı yapıştır, herhangi bir uygulamadan paylaş ya da ekran görüntüsü yükle.',
            'Metni kendi sunucumuzda okur; içindeki tüm linkleri, telefon numaralarını, IBAN’ları ve QR kodları çıkarırız.',
            'Her link ve QR kod gerçek kontrollerimizden geçer: nereye gittiği, sitenin ne kadar yeni olduğu, bir markayı taklit edip etmediği ve tehdit listeleri.',
            'Nedenleriyle birlikte net bir cevap alırsın; neyi kontrol edemediğimizi de söyleriz.',
            'Kendin doğrulaman için adımlar alırsın; örneğin bankanı kartının arkasındaki numaradan aramak gibi.',
            'Ödedin ya da bir kod mu paylaştın? Olana göre adımlar alırsın: kartı kapat, şifreyi değiştir, şikâyet et.',
        ],
        'plans_title': 'Ücretsiz plan ücretsiz kalıyor',
        'free_name': 'Ücretsiz',
        'free_price': '₺0',
        'free': [
            'Mevcut tüm araçlar: link, dosya, e-posta, QR kod, alan adı, IP, SSL ve şifre',
            'Günde 10 link kontrolü',
            'Denemen için birkaç mesaj ve ekran görüntüsü kontrolü',
            'PDF raporlar',
        ],
        'pro_name': 'Pro',
        'pro_price': '₺199',
        'pro_period': 'ayda',
        'pro_note': 'Planlanan erken erişim fiyatı. Aylık, istediğin zaman iptal. İlk üyelere kurucu indirimi.',
        'pro': [
            'Mesaj ve ekran görüntüsü kontrolü: ayda 60 ekran görüntüsü',
            'Tüm araçlarda daha yüksek ve açıkça gösterilen günlük haklar',
            '90 gün aranabilir geçmiş; dışa aktarma ve silme',
            'Saklayabileceğin ya da gönderebileceğin ayrıntılı PDF raporlar',
        ],
        'honest_title': 'Neyi vaat ediyoruz, neyi etmiyoruz',
        'honest': [
            'Kanıtı gösterir ve açıklarız. Hiçbir araç bir şeyin %100 güvenli olduğunu vaat edemez.',
            'Ekran görüntüsü mesajı kimin gönderdiğini kanıtlamaz; geçerli bir IBAN da sahibini kanıtlamaz. Bunu her raporda söyleriz.',
            'Ekran görüntün kontrolden sonra 24 saat içinde silinecek ve sunucumuzdan hiç çıkmayacak.',
        ],
        'form_title': 'Pro açılınca haber ver',
        'form_lead': 'Şimdi ödeme yok. Pro açıldığında sana bir kez e-posta göndeririz. E-postanı istediğin zaman sildirebilirsin.',
        'email_label': 'E-posta',
        'submit': 'Haber ver',
        'thanks': 'Teşekkürler! Pro açıldığında sana bir kez e-posta göndereceğiz.',
        'invalid': 'Lütfen geçerli bir e-posta adresi gir.',
        'try_free': 'Ücretsiz link kontrolünü dene',
    },
}


def visit_source(args, referrer, site_host):
    """Where a visitor came from: ?utm_source / ?ref, else the referring site, else direct."""
    for key in ('utm_source', 'ref', 'src'):
        value = (args.get(key) or '').strip().lower()
        if SOURCE.fullmatch(value):
            return value
    host = (urlparse(referrer or '').hostname or '').lower()
    if not host:
        return 'direct'
    if host == site_host or host.endswith('.' + site_host):
        return 'site'
    host = host[4:] if host.startswith('www.') else host
    return host[:40] if SOURCE.fullmatch(host[:40]) else 'other'


def is_bot(user_agent):
    return not user_agent or bool(BOTS.search(user_agent))


def record_visit(source, lang):
    from models import ProInterest
    db.session.add(ProInterest(kind='visit', source=source, lang=lang))
    db.session.commit()


def normalize_email(value):
    value = (value or '').strip().lower()
    return value if len(value) <= 254 and EMAIL.fullmatch(value) else None


def sign_up(email, source, lang, user_id=None):
    """Add the email to the waitlist once. Returns 'added' or 'already'."""
    from models import ProInterest
    if ProInterest.query.filter_by(kind='signup', email=email).first():
        return 'already'
    db.session.add(ProInterest(kind='signup', source=source, lang=lang, email=email, user_id=user_id))
    db.session.commit()
    return 'added'


def stats(days=30):
    """Visits and sign-ups per source for the admin page."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func
    from models import ProInterest
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    rows = (db.session.query(ProInterest.source, ProInterest.kind, func.count())
            .filter(ProInterest.created_at >= since).group_by(ProInterest.source, ProInterest.kind).all())
    table = {}
    for source, kind, count in rows:
        table.setdefault(source, {'visit': 0, 'signup': 0})[kind] = count
    sources = sorted(table.items(), key=lambda item: (-item[1]['visit'], item[0]))
    visits = sum(row['visit'] for _, row in sources)
    signups = sum(row['signup'] for _, row in sources)
    total = ProInterest.query.filter_by(kind='signup').count()
    return {'days': days, 'sources': sources, 'visits': visits, 'signups': signups, 'all_signups': total,
            'rate': round(100 * signups / visits, 1) if visits else None}
