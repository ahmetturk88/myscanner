# constants/__init__.py
"""
ثوابت عامة للمشروع
"""

# Disposable (temporary inbox) domains. A curated list of the services people meet most;
# unknown ones are not flagged (absence from this list proves nothing).
DISPOSABLE_DOMAINS = {
    'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'tempmail.net', 'tempmail.dev', 'tempmail.plus', 'tempmailo.com',
    'temp-mail.com', 'tempail.com', 'tempinbox.com', 'tempr.email', 'tmpmail.org', 'tmpmail.net',
    'emailtemporal.org', 'temporary-mail.net', 'temporarymail.com', 'tmail.ws',
    '10minutemail.com', '10minutemail.net', '10minutemail.co.uk', '10minemail.com', '20minutemail.com', '30minutemail.com',
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz', 'guerrillamail.de',
    'guerrillamailblock.com', 'grr.la', 'sharklasers.com', 'pokemail.net', 'spam4.me',
    'mailinator.com', 'mailinator.net', 'mailinator2.com', 'mailnator.com', 'notmailinator.com', 'reallymymail.com',
    'yopmail.com', 'yopmail.net', 'yopmail.fr', 'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx',
    'mega.zik.dj', 'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
    'throwawaymail.com', 'throwaway.email', 'trashmail.com', 'trashmail.net', 'trashmail.de', 'trashmail.me',
    'trashmail.io', 'trashmail.ws', 'wegwerfmail.de', 'wegwerfmail.net', 'einrot.com', 'spambog.com',
    'getnada.com', 'nada.email', 'inboxkitten.com', 'maildrop.cc', 'mailnesia.com', 'mailcatch.com',
    'mintemail.com', 'mohmal.com', 'mytemp.email', 'dispostable.com', 'discard.email', 'discardmail.com',
    'fakeinbox.com', 'fakemail.net', 'fake-mail.net', 'emailondeck.com', 'burnermail.io', 'spamgourmet.com',
    'mailpoof.com', 'moakt.com', 'moakt.cc', 'tmpbox.net', 'luxusmail.org', 'harakirimail.com', 'mailforspam.com',
    'emailfake.com', 'email-fake.com', 'generator.email', 'crazymailing.com', 'byom.de',
    'mail.tm', 'mail.gw', 'tempmail.lol', '1secmail.com', '1secmail.net', '1secmail.org', 'esiix.com', 'wwjmp.com',
    'xojxe.com', 'yoggm.com', 'kzccv.com', 'qiott.com', 'dpptd.com', 'vjuum.com', 'laafd.com', 'txcct.com',
    'mailtemp.net', 'minuteinbox.com', 'emltmp.com', 'tempm.com', 'linshiyouxiang.net', 'bccto.me', 'chacuo.net',
    'anonbox.net', 'anonymbox.com', 'deadaddress.com', 'mailexpire.com', 'mailmoat.com', 'mytrashmail.com',
    'spamex.com', 'spamfree24.org', 'spaml.com', 'tempemail.net', 'trash-mail.com', 'mailsac.com',
    'inboxbear.com', 'tempmailaddress.com', 'smailpro.com', 'dropmail.me',
}

# Free webmail providers: anyone can open an address there, so the name proves nothing.
FREE_DOMAINS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.de', 'yahoo.fr', 'ymail.com', 'rocketmail.com',
    'hotmail.com', 'hotmail.com.tr', 'hotmail.co.uk', 'hotmail.de', 'hotmail.fr', 'outlook.com', 'outlook.com.tr',
    'outlook.de', 'live.com', 'live.co.uk', 'msn.com', 'windowslive.com', 'icloud.com', 'me.com', 'mac.com',
    'aol.com', 'protonmail.com', 'proton.me', 'pm.me', 'tutanota.com', 'tutanota.de', 'tuta.io', 'zoho.com',
    'mail.com', 'gmx.com', 'gmx.net', 'gmx.de', 'web.de', 'yandex.com', 'yandex.com.tr', 'yandex.ru', 'ya.ru',
    'mail.ru', 'inbox.ru', 'list.ru', 'bk.ru', 'mynet.com', 'qq.com', '163.com', '126.com', 'naver.com',
}

# قائمة البلاك ليست ( blacklists )
BLACKLISTS = [
    'spamhaus.org', 'spamcop.net', 'barracudacentral.org'
]