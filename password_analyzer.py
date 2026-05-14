# password_analyzer.py - تحليل متقدم لكلمات المرور
import re
import hashlib
import requests
from datetime import datetime
from typing import Dict, Any, List
import math

class PasswordAnalyzer:
    """تحليل متقدم لقوة كلمات المرور"""
    
    # قائمة الكلمات الشائعة (sample)
    COMMON_PASSWORDS = {
        '123456', 'password', '123456789', '12345', '12345678', 'qwerty', 'abc123', 
        'password1', '111111', '123123', 'admin', 'admin123', 'root', 'toor',
        'welcome', 'login', 'passw0rd', 'user', 'test', 'test123', 'qwerty123',
        '1qaz2wsx', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'iloveyou', 'monkey',
        'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball'
    }
    
    # أنماط ضعيفة
    WEAK_PATTERNS = [
        (r'^123456', 'Starts with 123456'),
        (r'^qwerty', 'Starts with qwerty'),
        (r'^password', 'Starts with password'),
        (r'^admin', 'Starts with admin'),
        (r'^test', 'Starts with test'),
        (r'(\w)\1{3,}', 'Repeated characters (e.g., aaaa)'),
        (r'^[a-z]+$', 'Only lowercase letters'),
        (r'^[A-Z]+$', 'Only uppercase letters'),
        (r'^[0-9]+$', 'Only numbers'),
        (r'^[a-zA-Z]+$', 'Only letters (no numbers/symbols)'),
        (r'[0-9]{4,}', 'Long number sequence'),
        (r'(0123|1234|2345|3456|4567|5678|6789|7890)', 'Sequential numbers'),
        (r'(qwer|asdf|zxcv|wert|sdfg|xcvb)', 'Keyboard pattern'),
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MyScanner-Password-Checker'})
    
    def check_length(self, password: str) -> Dict[str, Any]:
        """فحص طول كلمة المرور"""
        length = len(password)
        
        if length < 8:
            score = 0
            status = "Very Weak"
            message = "Password is too short (minimum 8 characters)"
        elif length < 10:
            score = 30
            status = "Weak"
            message = "Acceptable length, but could be longer"
        elif length < 12:
            score = 60
            status = "Good"
            message = "Good length"
        elif length < 16:
            score = 80
            status = "Strong"
            message = "Strong length"
        else:
            score = 100
            status = "Very Strong"
            message = "Excellent length"
        
        return {
            "length": length,
            "score": score,
            "status": status,
            "message": message
        }
    
    def check_character_variety(self, password: str) -> Dict[str, Any]:
        """فحص تنوع الأحرف"""
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
        
        score = (variety_count / 4) * 100
        
        recommendations = []
        if not has_upper:
            recommendations.append("Add uppercase letters")
        if not has_lower:
            recommendations.append("Add lowercase letters")
        if not has_digit:
            recommendations.append("Add numbers")
        if not has_symbol:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        return {
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "variety_count": variety_count,
            "score": score,
            "recommendations": recommendations
        }
    
    def check_common_patterns(self, password: str) -> Dict[str, Any]:
        """فحص الأنماط الضعيفة"""
        issues = []
        
        for pattern, description in self.WEAK_PATTERNS:
            if re.search(pattern, password.lower()):
                issues.append(description)
        
        # فحص الكلمات الشائعة
        if password.lower() in self.COMMON_PASSWORDS:
            issues.append(f"Common password '{password}' is easily guessable")
        
        # فحص التواريخ
        date_patterns = [
            (r'(19|20)\d{2}', 'Contains a year'),
            (r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', 'Contains month name'),
            (r'(0[1-9]|1[0-2])/(0[1-9]|1[0-9]|2[0-9]|3[0-1])', 'Contains date pattern')
        ]
        
        for pattern, description in date_patterns:
            if re.search(pattern, password.lower()):
                issues.append(description)
        
        # فحص اسم المستخدم المحتمل
        if len(password) >= 4 and password.isalpha():
            issues.append("Password contains only letters (might be a dictionary word)")
        
        score = max(0, 100 - (len(issues) * 15))
        
        return {
            "has_issues": len(issues) > 0,
            "issues": issues[:5],  # أقصى 5 مشاكل
            "score": score
        }
    
    def check_entropy(self, password: str) -> Dict[str, Any]:
        """حساب الإنتروبي (كم تحتاج لتكسير الكلمة)"""
        # حساب عدد الأحرف الممكنة
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            charset_size += 33  # أحرف خاصة شائعة
        
        if charset_size == 0:
            return {"entropy_bits": 0, "crack_time": "instant", "score": 0}
        
        # حساب الإنتروبي (bits)
        entropy = len(password) * math.log2(charset_size)
        
        # تقدير وقت الاختراق
        if entropy < 28:
            crack_time = "Instant (seconds)"
            score = 0
        elif entropy < 36:
            crack_time = "Minutes to hours"
            score = 25
        elif entropy < 60:
            crack_time = "Days to weeks"
            score = 50
        elif entropy < 80:
            crack_time = "Years"
            score = 75
        else:
            crack_time = "Centuries"
            score = 100
        
        return {
            "entropy_bits": round(entropy, 2),
            "crack_time": crack_time,
            "score": score
        }
    
    def check_pwned(self, password: str) -> Dict[str, Any]:
        """فحص إذا كانت كلمة المرور مسربة (Have I Been Pwned)"""
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            response = self.session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.split(':')[0] == suffix:
                        count = int(line.split(':')[1])
                        return {
                            "is_pwned": True,
                            "count": count,
                            "message": f"Found in {count} data breaches!"
                        }
            
            return {
                "is_pwned": False,
                "count": 0,
                "message": "Not found in known breaches"
            }
            
        except Exception as e:
            return {
                "is_pwned": False,
                "count": 0,
                "message": "Could not check breaches (API error)"
            }
    
    def calculate_final_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """حساب النتيجة النهائية"""
        scores = {
            'length': results['length']['score'],
            'variety': results['variety']['score'],
            'patterns': results['patterns']['score'],
            'entropy': results['entropy']['score']
        }
        
        # الوزن لكل معيار
        weights = {
            'length': 0.25,
            'variety': 0.30,
            'patterns': 0.25,
            'entropy': 0.20
        }
        
        final_score = sum(scores[k] * weights[k] for k in scores)
        final_score = round(final_score, 2)
        
        # خصم 50 نقطة إذا كانت الكلمة مسربة
        if results.get('pwned', {}).get('is_pwned', False):
            final_score = max(0, final_score - 50)
        
        # تحديد التقييم النهائي
        if final_score >= 80:
            strength = "Very Strong"
            color = "green"
            icon = "✅"
        elif final_score >= 60:
            strength = "Strong"
            color = "green"
            icon = "✅"
        elif final_score >= 40:
            strength = "Medium"
            color = "yellow"
            icon = "⚠️"
        elif final_score >= 20:
            strength = "Weak"
            color = "red"
            icon = "❌"
        else:
            strength = "Very Weak"
            color = "red"
            icon = "❌"
        
        return {
            "score": final_score,
            "strength": strength,
            "color": color,
            "icon": icon,
            "scores": scores
        }
    
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """توليد توصيات لتحسين كلمة المرور"""
        recommendations = []
        
        # توصيات الطول
        if results['length']['length'] < 10:
            recommendations.append("🔐 Make your password longer (12+ characters recommended)")
        
        # توصيات التنوع
        variety_recs = results['variety']['recommendations']
        for rec in variety_recs[:3]:
            recommendations.append(f"🔤 {rec}")
        
        # توصيات الأنماط
        if results['patterns']['has_issues']:
            for issue in results['patterns']['issues'][:3]:
                recommendations.append(f"🚫 Avoid: {issue}")
        
        # توصيات التسريب
        if results.get('pwned', {}).get('is_pwned', False):
            recommendations.append("⚠️ This password has been exposed in data breaches! Change it immediately.")
        
        # توصيات عامة
        if not recommendations:
            recommendations.append("✅ Your password is strong! Consider using a password manager.")
        
        return recommendations[:6]  # أقصى 6 توصيات
    
    def comprehensive_analysis(self, password: str) -> Dict[str, Any]:
        """التحليل الشامل لكلمة المرور"""
        
        if not password:
            return {"error": "No password provided"}
        
        # جمع كل التحليلات
        results = {
            "password_length": len(password),
            "length": self.check_length(password),
            "variety": self.check_character_variety(password),
            "patterns": self.check_common_patterns(password),
            "entropy": self.check_entropy(password),
            "pwned": self.check_pwned(password)
        }
        
        # حساب النتيجة النهائية
        final = self.calculate_final_score(results)
        results['final'] = final
        
        # التوصيات
        results['recommendations'] = self.generate_recommendations(results)
        
        # أمثلة لكلمات مرور قوية
        results['examples'] = [
            "C0mpl3x!P@ssw0rd2024",
            "Blue!Sky@Mountain#42",
            "Summer$Beach%Wave!89"
        ]
        
        return results