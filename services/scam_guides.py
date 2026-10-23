"""Scam guides: short pages on the scams people in Türkiye meet most, in English and Turkish.

Each guide shows a typical message, the warning signs, what to do and which
MyScanner tool checks it. The text is written per language (not run through the
page translator), so each page reads naturally and search engines index both.
"""

UI = {
    'en': {
        'index_title': 'Scam guides', 'index_eyebrow': 'Scam guides',
        'index_heading': 'Know the scam <em>before it reaches you.</em>',
        'index_lead': 'The messages people in Türkiye receive most, how to spot them, and how to check one before you click.',
        'index_description': 'How to spot the most common scams in Türkiye: fake cargo SMS, e-Devlet refunds, bank calls, WhatsApp codes, fake shops and more.',
        'read': 'Read the guide', 'example': 'A typical message', 'signs': 'Warning signs', 'todo': 'What to do',
        'clicked': 'Already clicked or replied?', 'check': 'Check it with MyScanner', 'check_lead': 'Paste the link or upload the file and see the evidence in seconds. Free.',
        'others': 'More scam guides', 'back': 'All scam guides', 'note': 'Example for illustration; real messages vary.',
        'clicked_steps': [
            'Stop: do not enter anything else on that page and close it.',
            'If you typed a password, change it now on the real site or app, and turn on two-step verification.',
            'If you entered card details or approved a payment, call your bank on the number on your card and block the card.',
            'If you installed an app from a link, delete it and scan your phone with a trusted security app.',
            'Report it: forward scam SMS and links to your operator, and to your bank if it used their name.',
        ],
    },
    'tr': {
        'index_title': 'Dolandırıcılık rehberi', 'index_eyebrow': 'Dolandırıcılık rehberi',
        'index_heading': 'Dolandırıcılığı <em>sana ulaşmadan tanı.</em>',
        'index_lead': "Türkiye'de en sık gelen sahte mesajlar, onları nasıl tanıyacağın ve tıklamadan önce nasıl kontrol edeceğin.",
        'index_description': "Türkiye'deki en yaygın dolandırıcılıkları tanıyın: sahte kargo SMS'leri, e-Devlet iadesi, banka aramaları, WhatsApp kodu, sahte mağazalar ve daha fazlası.",
        'read': 'Rehberi oku', 'example': 'Örnek bir mesaj', 'signs': 'Uyarı işaretleri', 'todo': 'Ne yapmalısın',
        'clicked': 'Tıkladın ya da cevap mı verdin?', 'check': "MyScanner ile kontrol et", 'check_lead': 'Linki yapıştır ya da dosyayı yükle, kanıtı saniyeler içinde gör. Ücretsiz.',
        'others': 'Diğer rehberler', 'back': 'Tüm rehberler', 'note': 'Örnek amaçlıdır; gerçek mesajlar farklı olabilir.',
        'clicked_steps': [
            'Dur: o sayfaya başka hiçbir şey girme ve sayfayı kapat.',
            'Bir şifre yazdıysan hemen gerçek site ya da uygulamadan değiştir ve iki adımlı doğrulamayı aç.',
            'Kart bilgisi girdiysen ya da bir ödemeyi onayladıysan kartının arkasındaki numaradan bankanı ara ve kartı kapattır.',
            'Bir linkten uygulama yüklediysen sil ve telefonunu güvendiğin bir güvenlik uygulamasıyla tara.',
            "Bildir: dolandırıcılık SMS'lerini ve linklerini operatörüne, adı kullanıldıysa bankana ilet.",
        ],
    },
}

GUIDES = [
    {
        'slug': 'fake-cargo-sms', 'icon': 'box', 'tool': 'dashboard',
        'en': {
            'title': 'Fake cargo and PTT delivery SMS',
            'summary': '“Your package could not be delivered” messages that ask for a small fee or your card details.',
            'description': 'How to spot fake cargo and PTT delivery SMS scams in Türkiye, and what to do if you clicked.',
            'example': 'PTT: Your package could not be delivered due to a missing address. Update your address and pay the 18.90 TL fee within 24 hours: ptt-teslimat-kargo[.]com',
            'signs': [
                'A link to a site that is not the courier’s real address (look for extra words, dashes or odd endings).',
                'A small fee for “customs”, “address update” or “redelivery”, paid by card.',
                'A short deadline: “within 24 hours”, or the package will be returned.',
                'You were not expecting a package, or it does not name the shop you ordered from.',
            ],
            'todo': [
                'Do not tap the link. Open the courier’s official app or type its address yourself and track with your tracking number.',
                'Couriers do not ask for card details by SMS to redeliver a package.',
                'Not sure? Paste the link into the MyScanner URL scanner and see where it really leads.',
            ],
        },
        'tr': {
            'title': 'Sahte kargo ve PTT teslimat SMS’leri',
            'summary': '“Paketiniz teslim edilemedi” diyerek küçük bir ücret ya da kart bilgisi isteyen mesajlar.',
            'description': "Türkiye'deki sahte kargo ve PTT teslimat SMS dolandırıcılığını nasıl tanırsın, tıkladıysan ne yapmalısın.",
            'example': 'PTT: Adres eksikliği nedeniyle kargonuz teslim edilemedi. 24 saat içinde adresinizi güncelleyip 18,90 TL ücreti ödeyin: ptt-teslimat-kargo[.]com',
            'signs': [
                'Kargo firmasının gerçek adresi olmayan bir site (fazladan kelimeler, tireler ya da garip uzantılar).',
                '“Gümrük”, “adres güncelleme” ya da “yeniden gönderim” için kartla ödenen küçük bir ücret.',
                'Kısa süre baskısı: “24 saat içinde”, yoksa paket iade edilecek.',
                'Bir paket beklemiyorsun ya da mesaj sipariş verdiğin mağazanın adını vermiyor.',
            ],
            'todo': [
                'Linke dokunma. Kargo firmasının resmi uygulamasını aç ya da adresini kendin yaz ve takip numaranla sorgula.',
                'Kargo firmaları paketi yeniden göndermek için SMS ile kart bilgisi istemez.',
                'Emin değil misin? Linki MyScanner URL tarayıcısına yapıştır ve gerçekte nereye gittiğini gör.',
            ],
        },
    },
    {
        'slug': 'e-devlet-refund', 'icon': 'shield', 'tool': 'dashboard',
        'en': {
            'title': 'Fake e-Devlet refund and compensation messages',
            'summary': 'Messages promising a tax refund or compensation, leading to a copy of the e-Devlet sign-in page.',
            'description': 'How to recognise fake e-Devlet refund SMS and emails that steal your e-Devlet password and card details.',
            'example': 'e-Devlet: You have a refund of 1,250 TL. To receive it, verify your identity before it expires: edevlet-iade-basvuru[.]net',
            'signs': [
                'The real e-Devlet address is turkiye.gov.tr. Any other address is not e-Devlet.',
                'Money is offered “for you” and you only need to “verify” or “apply” through a link.',
                'The page asks for your e-Devlet password, then your card number or an SMS code.',
            ],
            'todo': [
                'Never enter your e-Devlet password on a page you reached from a message. Type turkiye.gov.tr yourself.',
                'Real refunds and payments appear inside e-Devlet itself; you do not need to “claim” them by SMS.',
                'If you entered your password, change it on turkiye.gov.tr straight away.',
            ],
        },
        'tr': {
            'title': 'Sahte e-Devlet iade ve tazminat mesajları',
            'summary': 'Vergi iadesi ya da tazminat vaat edip e-Devlet giriş sayfasının kopyasına götüren mesajlar.',
            'description': "e-Devlet şifreni ve kart bilgilerini çalan sahte e-Devlet iade SMS'lerini ve e-postalarını nasıl tanırsın.",
            'example': 'e-Devlet: Adınıza 1.250 TL iade tanımlanmıştır. Süresi dolmadan kimliğinizi doğrulayarak alın: edevlet-iade-basvuru[.]net',
            'signs': [
                "e-Devlet'in gerçek adresi turkiye.gov.tr'dir. Başka bir adres e-Devlet değildir.",
                'Sana para teklif ediliyor ve sadece bir linkten “doğrulama” ya da “başvuru” yapman isteniyor.',
                'Sayfa önce e-Devlet şifreni, sonra kart numaranı ya da bir SMS kodunu istiyor.',
            ],
            'todo': [
                "Bir mesajdan ulaştığın sayfaya asla e-Devlet şifreni girme. turkiye.gov.tr'yi kendin yaz.",
                'Gerçek iade ve ödemeler e-Devlet içinde görünür; bunları SMS ile “talep etmen” gerekmez.',
                "Şifreni girdiysen hemen turkiye.gov.tr'den değiştir.",
            ],
        },
    },
    {
        'slug': 'bank-security-scam', 'icon': 'lock', 'tool': 'dashboard',
        'en': {
            'title': '“Your account is blocked” bank messages and calls',
            'summary': 'Messages or calls in your bank’s name that ask for your password, an SMS code or a transfer to a “safe account”.',
            'description': 'How to spot bank impersonation scams by SMS and phone, and why your bank never asks for passwords or SMS codes.',
            'example': 'YourBank: Suspicious activity was detected and your card has been restricted. To lift the block, sign in now: yourbank-guvenli-giris[.]com',
            'signs': [
                'Urgency: your account is “blocked”, “frozen” or “at risk” and you must act now.',
                'A link to sign in, or a caller asking for your password, card PIN or the code your bank just sent you.',
                'A request to move your money to a “safe account”. No real bank does this.',
                'A caller ID or sender name that looks like your bank. These can be faked.',
            ],
            'todo': [
                'Hang up or ignore the message. Call your bank yourself on the number on the back of your card.',
                'Never share an SMS code: it is the key that approves a payment or a new device.',
                'Sign in only through your bank’s official app or by typing its address.',
            ],
        },
        'tr': {
            'title': '“Hesabınız bloke edildi” banka mesajları ve aramaları',
            'summary': 'Bankan adına gelen ve şifreni, bir SMS kodunu ya da “güvenli hesaba” para aktarmanı isteyen mesaj ve aramalar.',
            'description': 'SMS ve telefonla gelen banka taklidi dolandırıcılığını nasıl tanırsın; bankan neden asla şifre ya da SMS kodu istemez.',
            'example': 'Bankanız: Hesabınızda şüpheli işlem tespit edildi ve kartınız kısıtlandı. Kısıtlamayı kaldırmak için hemen giriş yapın: banka-guvenli-giris[.]com',
            'signs': [
                'Aciliyet: hesabın “bloke”, “donduruldu” ya da “risk altında” ve hemen işlem yapmalısın.',
                'Giriş yapman için bir link ya da şifreni, kart şifreni veya bankanın az önce gönderdiği kodu isteyen biri.',
                'Paranı “güvenli bir hesaba” aktarma talebi. Hiçbir gerçek banka bunu yapmaz.',
                'Bankana benzeyen arayan numara ya da gönderici adı. Bunlar taklit edilebilir.',
            ],
            'todo': [
                'Telefonu kapat ya da mesajı yok say. Bankanı kartının arkasındaki numaradan kendin ara.',
                'SMS kodunu asla paylaşma: bu kod bir ödemeyi ya da yeni bir cihazı onaylayan anahtardır.',
                'Yalnızca bankanın resmi uygulamasından ya da adresini kendin yazarak giriş yap.',
            ],
        },
    },
    {
        'slug': 'whatsapp-code-scam', 'icon': 'chat', 'tool': None,
        'en': {
            'title': 'The WhatsApp verification code scam',
            'summary': '“I sent you a code by mistake, can you forward it?” The code is the key to your WhatsApp account.',
            'description': 'How scammers take over WhatsApp accounts by asking for your 6-digit code, and how to protect yours with two-step verification.',
            'example': 'Hi, I accidentally sent my verification code to your number. Could you send me the 6-digit code you just got? It’s urgent 🙏',
            'signs': [
                'Someone, often a friend’s hacked account, asks for a 6-digit code you just received by SMS.',
                'You receive a WhatsApp registration code you did not request.',
                'Pressure and a believable story: “by mistake”, “urgent”, “just this once”.',
            ],
            'todo': [
                'Never share a WhatsApp code with anyone, even a friend. WhatsApp itself never asks for it in a chat.',
                'Turn on two-step verification: WhatsApp › Settings › Account › Two-step verification, and set a PIN.',
                'If a friend’s account asks for money or codes, call them by phone before doing anything.',
            ],
        },
        'tr': {
            'title': 'WhatsApp doğrulama kodu dolandırıcılığı',
            'summary': '“Yanlışlıkla sana kod gönderdim, iletir misin?” O kod WhatsApp hesabının anahtarıdır.',
            'description': "Dolandırıcılar 6 haneli kodunu isteyerek WhatsApp hesaplarını nasıl ele geçirir, iki adımlı doğrulamayla nasıl korunursun.",
            'example': 'Selam, doğrulama kodumu yanlışlıkla senin numarana gönderdim. Az önce gelen 6 haneli kodu bana atar mısın? Çok acil 🙏',
            'signs': [
                'Biri (çoğu zaman ele geçirilmiş bir arkadaş hesabı) sana SMS ile az önce gelen 6 haneli kodu istiyor.',
                'Senin istemediğin bir WhatsApp kayıt kodu geliyor.',
                'Baskı ve inandırıcı bir hikâye: “yanlışlıkla”, “acil”, “sadece bu seferlik”.',
            ],
            'todo': [
                "WhatsApp kodunu kimseyle, arkadaşınla bile paylaşma. WhatsApp'ın kendisi sohbette asla kod istemez.",
                'İki adımlı doğrulamayı aç: WhatsApp › Ayarlar › Hesap › İki adımlı doğrulama, ve bir PIN belirle.',
                'Bir arkadaşının hesabı para ya da kod istiyorsa, bir şey yapmadan önce onu telefonla ara.',
            ],
        },
    },
    {
        'slug': 'prize-giveaway-scam', 'icon': 'spark', 'tool': 'dashboard',
        'en': {
            'title': 'Fake prizes and giveaways',
            'summary': '“Congratulations, you won!” messages and social media pages that ask for a shipping fee or your details.',
            'description': 'How to recognise fake prize and giveaway scams on SMS and social media in Türkiye.',
            'example': 'Congratulations! You have been selected as the winner of our anniversary draw 🎁 To receive your phone, pay only the 29.90 TL shipping fee: hediye-kazandiniz[.]shop',
            'signs': [
                'You won a draw you never entered.',
                'You only need to pay a small “shipping”, “tax” or “activation” fee.',
                'A new social media page or a web address that is not the brand’s official one.',
                'A countdown or “only 3 prizes left”.',
            ],
            'todo': [
                'Real prizes do not require you to pay first.',
                'Check the brand’s official account or website by searching for it yourself.',
                'Paste the link into MyScanner to see how new the site is and what it really is.',
            ],
        },
        'tr': {
            'title': 'Sahte çekiliş ve hediyeler',
            'summary': '“Tebrikler, kazandınız!” diyerek kargo ücreti ya da bilgilerini isteyen mesajlar ve sosyal medya sayfaları.',
            'description': "Türkiye'de SMS ve sosyal medyadaki sahte çekiliş ve hediye dolandırıcılığını nasıl tanırsın.",
            'example': 'Tebrikler! Yıl dönümü çekilişimizin kazananı olarak seçildiniz 🎁 Telefonunuzu almak için sadece 29,90 TL kargo ücretini ödeyin: hediye-kazandiniz[.]shop',
            'signs': [
                'Hiç katılmadığın bir çekilişi kazanmışsın.',
                'Sadece küçük bir “kargo”, “vergi” ya da “aktivasyon” ücreti ödemen gerekiyor.',
                'Yeni açılmış bir sosyal medya sayfası ya da markanın resmi adresi olmayan bir site.',
                'Geri sayım ya da “son 3 hediye kaldı”.',
            ],
            'todo': [
                'Gerçek ödüller önce ödeme yapmanı istemez.',
                'Markanın resmi hesabını ya da sitesini kendin arayarak kontrol et.',
                "Linki MyScanner'a yapıştır; sitenin ne kadar yeni olduğunu ve gerçekte ne olduğunu gör.",
            ],
        },
    },
    {
        'slug': 'fake-online-shops', 'icon': 'globe', 'tool': 'domain_lookup',
        'en': {
            'title': 'Fake online shops and too-good-to-be-true discounts',
            'summary': 'Ads and sites with huge discounts that take your money and send nothing, or a fake.',
            'description': 'How to check an online shop before you buy: domain age, payment methods, contact details and reviews.',
            'example': 'Season-end SALE 🔥 Original sneakers 80% off, today only! Limited stock, free shipping. Order now: marka-outlet-indirim[.]store',
            'signs': [
                'Prices far below everywhere else, “today only”.',
                'A web address created only weeks ago, often with words like outlet, indirim or sale.',
                'Payment only by bank transfer (havale/EFT) or a request to pay outside the site.',
                'No real company details: no address, no tax number, only a WhatsApp number.',
            ],
            'todo': [
                'Look the domain up in MyScanner’s Domain Lookup: a shop opened last month with huge discounts is a red flag.',
                'Prefer card payment with 3D Secure, which gives you a way to dispute the charge.',
                'Search the shop’s name with the word “şikayet” (complaint) before ordering.',
            ],
        },
        'tr': {
            'title': 'Sahte online mağazalar ve inanılmaz indirimler',
            'summary': 'Paranı alıp hiçbir şey göndermeyen ya da sahte ürün gönderen, dev indirimli reklamlar ve siteler.',
            'description': 'Bir online mağazayı alışverişten önce nasıl kontrol edersin: alan adının yaşı, ödeme yöntemleri, iletişim bilgileri ve yorumlar.',
            'example': 'Sezon sonu İNDİRİM 🔥 Orijinal spor ayakkabılarda %80 indirim, sadece bugün! Stoklar sınırlı, kargo bedava. Hemen sipariş ver: marka-outlet-indirim[.]store',
            'signs': [
                'Fiyatlar her yerden çok daha düşük ve “sadece bugün”.',
                'Sadece birkaç hafta önce açılmış, çoğu zaman outlet, indirim ya da sale kelimeleri içeren bir adres.',
                'Sadece havale/EFT ile ödeme ya da site dışında ödeme yapma talebi.',
                'Gerçek şirket bilgisi yok: adres yok, vergi numarası yok, sadece bir WhatsApp numarası.',
            ],
            'todo': [
                "Alan adını MyScanner'ın Alan Adı Sorgulama aracında kontrol et: geçen ay açılmış ve dev indirim yapan bir mağaza ciddi bir uyarı işaretidir.",
                'İtiraz hakkı veren 3D Secure ile kartla ödemeyi tercih et.',
                'Sipariş vermeden önce mağazanın adını “şikayet” kelimesiyle birlikte ara.',
            ],
        },
    },
    {
        'slug': 'qr-code-scam', 'icon': 'qr', 'tool': 'qr_scanner',
        'en': {
            'title': 'Fake QR codes (quishing)',
            'summary': 'QR stickers on parking meters, posters or menus that lead to fake payment pages.',
            'description': 'How fake QR codes (quishing) work and how to check where a QR code leads before you pay.',
            'example': 'A sticker on a parking meter: “Pay by QR, faster and contactless”, placed over the real code and leading to a lookalike payment page.',
            'signs': [
                'A sticker placed on top of another code, or a code that looks added later.',
                'The address it opens is not the official one of the car park, restaurant or company.',
                'It asks for card details for a small, everyday payment.',
            ],
            'todo': [
                'Before paying, look at the full address the QR code opens.',
                'Use the MyScanner QR scanner: it shows where the code leads and checks that address before you open it.',
                'When in doubt, pay through the official app or at the counter.',
            ],
        },
        'tr': {
            'title': 'Sahte QR kodlar (quishing)',
            'summary': 'Otopark makinelerine, afişlere ya da menülere yapıştırılmış, sahte ödeme sayfalarına götüren QR etiketleri.',
            'description': 'Sahte QR kodlar (quishing) nasıl çalışır, ödeme yapmadan önce bir QR kodun nereye götürdüğünü nasıl kontrol edersin.',
            'example': 'Bir otopark makinesinde etiket: “QR ile öde, daha hızlı ve temassız”. Gerçek kodun üstüne yapıştırılmış ve benzer bir ödeme sayfasına götürüyor.',
            'signs': [
                'Başka bir kodun üstüne yapıştırılmış ya da sonradan eklenmiş gibi duran bir etiket.',
                'Açılan adres otoparkın, restoranın ya da şirketin resmi adresi değil.',
                'Küçük, günlük bir ödeme için kart bilgilerini istiyor.',
            ],
            'todo': [
                'Ödemeden önce QR kodun açtığı adresin tamamına bak.',
                "MyScanner QR tarayıcısını kullan: kodun nereye götürdüğünü gösterir ve açmadan önce o adresi kontrol eder.",
                'Şüphedeysen resmi uygulamadan ya da kasada öde.',
            ],
        },
    },
    {
        'slug': 'invoice-attachment-malware', 'icon': 'file', 'tool': 'file_scanner',
        'en': {
            'title': 'Fake invoices, receipts and bank statements by email',
            'summary': 'Emails with an “invoice”, “payment receipt” or “account statement” attachment that installs malware.',
            'description': 'How to recognise malicious invoice, receipt and bank statement attachments, and how to check a file before opening it.',
            'example': 'Subject: Payment receipt (Dekont) – Your transfer has been completed. Please find the receipt attached: Odeme_Dekontu_2026.zip',
            'signs': [
                'An unexpected invoice, receipt or statement, often from a company you do not use.',
                'A ZIP, RAR, HTML, ISO or IMG attachment, or a name like “dekont.pdf.exe” that hides a program.',
                'An Office file that asks you to “Enable content” or “Enable macros”.',
                'The sender address does not match the company in the message.',
            ],
            'todo': [
                'Do not open the attachment. Upload it to the MyScanner file scanner first: it checks it with an antivirus engine and looks inside without running it.',
                'Never click “Enable content” on a document from email.',
                'If it is about real money, check in your bank’s app instead of the attachment.',
            ],
        },
        'tr': {
            'title': 'E-postayla gelen sahte fatura, dekont ve hesap hareketleri',
            'summary': '“Fatura”, “ödeme dekontu” ya da “hesap hareketleri” eki içeren ve zararlı yazılım yükleyen e-postalar.',
            'description': 'Zararlı fatura, dekont ve hesap hareketi eklerini nasıl tanırsın, bir dosyayı açmadan önce nasıl kontrol edersin.',
            'example': 'Konu: Ödeme dekontu – Havale işleminiz gerçekleşmiştir. Dekont ektedir: Odeme_Dekontu_2026.zip',
            'signs': [
                'Beklemediğin bir fatura, dekont ya da ekstre; çoğu zaman kullanmadığın bir şirketten.',
                'ZIP, RAR, HTML, ISO ya da IMG eki veya bir programı gizleyen “dekont.pdf.exe” gibi bir ad.',
                '“İçeriği etkinleştir” ya da “Makroları etkinleştir” demeni isteyen bir Office dosyası.',
                'Gönderen adresi mesajdaki şirketle uyuşmuyor.',
            ],
            'todo': [
                'Eki açma. Önce MyScanner dosya tarayıcısına yükle: dosyayı antivirüs motoruyla kontrol eder ve çalıştırmadan içine bakar.',
                'E-postadan gelen bir belgede asla “İçeriği etkinleştir”e tıklama.',
                'Gerçek bir para işlemiyse eke değil, bankanın uygulamasına bak.',
            ],
        },
    },
]

BY_SLUG = {guide['slug']: guide for guide in GUIDES}
TOOL_NAMES = {
    'en': {'dashboard': 'Check a link', 'domain_lookup': 'Look up a domain', 'qr_scanner': 'Scan a QR code', 'file_scanner': 'Scan a file'},
    'tr': {'dashboard': 'Bir linki kontrol et', 'domain_lookup': 'Alan adı sorgula', 'qr_scanner': 'QR kod tara', 'file_scanner': 'Dosya tara'},
}
