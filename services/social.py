"""MyScanner's public accounts: the site footer and the contact page link them.

Profiles (profile=True) also go into Google's structured data (sameAs). The
WhatsApp channel is MyScanner's own public broadcast account, so it counts as one.
"""
SOCIAL_LINKS = [
    {'name': 'LinkedIn', 'url': 'https://www.linkedin.com/company/myscanners/', 'icon': 'linkedin', 'profile': True,
     'title': 'Follow MyScanner', 'text': 'Scam alerts, security tips and product updates.'},
    {'name': 'WhatsApp channel', 'url': 'https://whatsapp.com/channel/0029Vb9Mor5GOj9eRROdFO0x', 'icon': 'whatsapp', 'profile': True,
     'title': 'Follow the channel', 'text': 'Scam alerts, safety tips and MyScanner news on WhatsApp.'},
]
