# models/__init__.py
from models.user import User
from models.scan import Scan
from models.vulnerability import VulnerabilityScan, Vulnerability, ScanConfig

__all__ = ['User', 'Scan', 'VulnerabilityScan', 'Vulnerability', 'ScanConfig']