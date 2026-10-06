"""Daily service limits shared by atomic reservations and account displays."""
DAILY_LIMITS = {
    'user': {
        'site_scan': 10,
        'file_scan': 5,
        'url_analyzer': 3,
        'email_check': 15,
        'ip_check': 15,
        'domain_lookup': 15,
        'ssl_check': 15,
        'qr_scan': 15,
        'subdomain_finder': 5,
        'password_check': 3,
        'sandbox_analysis': 3
    },

    'premium': {
        'site_scan': 999999,
        'file_scan': 999999,
        'url_analyzer': 999999,
        'email_check': 999999,
        'ip_check': 999999,
        'domain_lookup': 999999,
        'ssl_check': 999999,
        'qr_scan': 999999,
        'subdomain_finder': 999999,
        'password_check': 999999,
        'sandbox_analysis': 20
    },
    'admin': {
        'site_scan': 999999,
        'file_scan': 999999,
        'url_analyzer': 999999,
        'email_check': 999999,
        'ip_check': 999999,
        'domain_lookup': 999999,
        'ssl_check': 999999,
        'qr_scan': 999999,
        'subdomain_finder': 999999,
        'password_check': 999999,
        'sandbox_analysis': 999999
    }
}

# One accepted request/element reserves one service unit.
SERVICE_COST = {
    'site_scan': 1,
    'file_scan': 1,
    'url_analyzer': 1,
    'email_check': 1,
    'ip_check': 1,
    'domain_lookup': 1,
    'ssl_check': 1,
    'qr_scan': 1,
    'subdomain_finder': 1,
    'password_check': 1,
    'sandbox_analysis': 1
}

