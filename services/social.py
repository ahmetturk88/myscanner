"""MyScanner's public accounts: the site footer and the contact page link them.

Profiles (profile=True) also go into Google's structured data (sameAs); a chat
invite is not a profile of the organisation, so it stays out.
"""
SOCIAL_LINKS = [
    {'name': 'LinkedIn', 'url': 'https://www.linkedin.com/company/myscanners/', 'icon': 'linkedin', 'profile': True,
     'title': 'Follow MyScanner', 'text': 'Scam alerts, security tips and product updates.'},
    {'name': 'WhatsApp community', 'url': 'https://chat.whatsapp.com/CMW7MsX7WZD0G24oXpHWN2', 'icon': 'whatsapp', 'profile': False,
     'title': 'Join the community', 'text': 'Announcements, early features and a place to share feedback.'},
]
