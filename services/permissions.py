# services/permissions.py
# ================================================================
# نظام الصلاحيات والحدود الموحد لجميع الخدمات
# ================================================================

from flask_login import current_user
from functools import wraps
from flask import jsonify
from models import User
from extensions import db
from datetime import datetime, timezone

# ================================================================
# 1. تعريف حدود كل خدمة حسب دور المستخدم
# ================================================================

# حدود الفحوصات اليومية لكل دور
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
        'sandbox_analysis': 3      # 👈 أضف هذا السطر
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

# نقاط التكلفة لكل خدمة (كم تستهلك من الـ remaining_scans)
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


# ================================================================
# 2. دوال التحقق من الصلاحيات والحدود
# ================================================================

def reset_daily_scans():
    """إعادة تعيين حدود الفحوصات اليومية لجميع المستخدمين"""
    from app import app
    with app.app_context():
        users = User.query.all()
        for user in users:
            role = user.role if user.role in DAILY_LIMITS else 'user'
            # إعادة تعيين كل الخدمات
            for service, limit in DAILY_LIMITS[role].items():
                setattr(user, f'{service}_remaining', limit)
            user.scans_reset_date = datetime.now(timezone.utc)
        db.session.commit()
        print("[PERMISSIONS] Daily scans reset for all users!")


def check_permission(service_name: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Authentication required"}), 401
            
            # ← إعادة تحميل المستخدم من DB مباشرة
            user = User.query.get(current_user.id)
            if not user:
                return jsonify({"error": "User not found"}), 401

            role = user.role if user.role in DAILY_LIMITS else 'user'
            remaining_field = f'{service_name}_remaining'
            remaining = getattr(user, remaining_field, None)

            print(f"[DEBUG] {service_name} → remaining: {remaining} | user: {user.username}")

            if remaining is None:
                default_limit = DAILY_LIMITS[role].get(service_name, 0)
                setattr(user, remaining_field, default_limit)
                db.session.commit()
                remaining = default_limit

            if remaining <= 0:
                return jsonify({
                    "error": f"Daily limit reached for {service_name}.",
                    "remaining": 0
                }), 429

            # خصم فحص
            setattr(user, remaining_field, remaining - 1)
            db.session.commit()

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def check_permission_manual(service_name: str):
    """
    دالة للتحقق اليدوي (بدون decorator)
    تعيد (allowed, message, remaining)
    """
    if not current_user.is_authenticated:
        return False, "Authentication required", 0
    
    role = current_user.role if current_user.role in DAILY_LIMITS else 'user'
    remaining_field = f'{service_name}_remaining'
    
    if not hasattr(current_user, remaining_field):
        return False, f"Service '{service_name}' not configured", 0
    
    remaining = getattr(current_user, remaining_field, 0)
    
    if remaining <= 0:
        limit = DAILY_LIMITS[role].get(service_name, 0)
        return False, f"Daily limit reached. You have {limit} scans per day.", remaining
    
    return True, "OK", remaining


def deduct_scan(service_name: str):
    """خصم فحص من رصيد المستخدم"""
    if not current_user.is_authenticated:
        return False
    
    remaining_field = f'{service_name}_remaining'
    if hasattr(current_user, remaining_field):
        remaining = getattr(current_user, remaining_field, 0)
        if remaining > 0:
            setattr(current_user, remaining_field, remaining - 1)
            db.session.commit()
            return True
    return False


def get_remaining_scans(service_name: str) -> int:
    """الحصول على عدد الفحوصات المتبقية لخدمة معينة"""
    if not current_user.is_authenticated:
        return 0
    
    remaining_field = f'{service_name}_remaining'
    if hasattr(current_user, remaining_field):
        return getattr(current_user, remaining_field, 0)
    return 0


def get_user_limits() -> dict:
    """الحصول على جميع حدود المستخدم"""
    if not current_user.is_authenticated:
        return {}
    
    role = current_user.role if current_user.role in DAILY_LIMITS else 'user'
    limits = DAILY_LIMITS[role].copy()
    
    # إضافة القيم المتبقية
    for service in limits.keys():
        remaining_field = f'{service}_remaining'
        if hasattr(current_user, remaining_field):
            limits[f'{service}_remaining'] = getattr(current_user, remaining_field, 0)
    
    return {
        'role': role,
        'limits': limits,
        'is_premium': role == 'premium',
        'is_admin': role == 'admin'
    }