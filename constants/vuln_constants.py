# constants/vuln_constants.py
"""
ثوابت وأعدادات ماسح الثغرات المتقدم
"""

import os
from dotenv import load_dotenv
load_dotenv()

# إعدادات OWASP ZAP
ZAP_CONFIG = {
    'api_key': os.getenv('ZAP_API_KEY', ''),
    'host': os.getenv('ZAP_HOST', 'localhost'),
    'port': int(os.getenv('ZAP_PORT', 8080)),
    'use_https': False,
    'timeout': 3600,
    'max_targets_per_scan': 10,
    'scan_policy': 'Default Policy',
    'context_name': 'Default Context'
}

# إعدادات OpenVAS/GVM
OPENVAS_CONFIG = {
    'host': os.getenv('OPENVAS_HOST', 'localhost'),
    'port': int(os.getenv('OPENVAS_PORT', 9392)),
    'username': os.getenv('OPENVAS_USERNAME', 'admin'),
    'password': os.getenv('OPENVAS_PASSWORD', ''),
    'use_https': True,
    'timeout': 7200,
    'max_hosts': 50,
    'max_concurrent_scans': 3,
    'default_config': 'daba56c8-73ec-11df-a475-002264764cea'
}

# أوزان الثغرات حسب الخطورة
SEVERITY_WEIGHTS = {
    'critical': 10,
    'high': 8,
    'medium': 5,
    'low': 2,
    'info': 0
}

# ألوان الثغرات لعرضها في الواجهة
SEVERITY_COLORS = {
    'critical': '#ff0033',
    'high': '#ff6b35',
    'medium': '#ffd32a',
    'low': '#00e676',
    'info': '#00c8ff'
}

# أيقونات الثغرات
SEVERITY_ICONS = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🟢',
    'info': '🔵'
}

# أنواع الثغرات المدعومة
VULNERABILITY_TYPES = {
    'sql_injection': 'SQL Injection',
    'xss': 'Cross-Site Scripting',
    'csrf': 'CSRF',
    'command_injection': 'Command Injection',
    'path_traversal': 'Path Traversal',
    'file_inclusion': 'File Inclusion',
    'xxe': 'XXE Injection',
    'ssrf': 'SSRF',
    'open_redirect': 'Open Redirect',
    'weak_crypto': 'Weak Cryptography',
    'missing_headers': 'Missing Security Headers',
    'cve': 'Known CVE',
    'misconfiguration': 'Misconfiguration',
    'information_disclosure': 'Information Disclosure'
}

# إعدادات التقرير
REPORT_CONFIG = {
    'formats': ['pdf', 'html', 'json', 'csv'],
    'max_vulnerabilities_per_page': 50,
    'include_remediation': True,
    'include_executive_summary': True,
    'company_logo': '/static/logo.png',
    'default_language': 'en'
}

# أوقات إعادة المحاولة
RETRY_CONFIG = {
    'max_retries': 3,
    'retry_delay': 5,
    'backoff_factor': 2
}