# password_analyzer.py - تحليل متقدم لكلمات المرور
import re
import hashlib
import requests
from datetime import datetime
from typing import Dict, Any, List
import math
import logging
logger = logging.getLogger(__name__)

class PasswordAnalyzer:
    """تحليل متقدم لقوة كلمات المرور"""
    
    COMMON_PASSWORDS = {
        '123456', 'password', '123456789', '12345', '12345678', 'qwerty', 'abc123', 
        'password1', '111111', '123123', 'admin', 'admin123', 'root', 'toor',
        'welcome', 'login', 'passw0rd', 'user', 'test', 'test123', 'qwerty123',
        '1qaz2wsx', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'iloveyou', 'monkey',
        'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball'
    }
    
    # ✅ أنماط ضعيفة - أزلنا الأنماط التي تعطي false positives
    WEAK_PATTERNS = [
        (r'^123456',                          'Starts with 123456'),
        (r'^qwerty',                          'Starts with qwerty'),
        (r'^password',                        'Starts with "password"'),
        (r'^admin',                           'Starts with "admin"'),
        (r'^test',                            'Starts with "test"'),
        (r'(.)\1{3,}',                        'Repeated characters (e.g., aaaa)'),
        (r'^[0-9]+$',                         'Only numbers'),
        (r'(0123|1234|2345|3456|4567|5678|6789|7890)', 'Sequential numbers'),
        (r'(qwer|asdf|zxcv|wert|sdfg|xcvb)', 'Keyboard pattern'),
    ]

    # ✅ أنماط منفصلة لها وزن خفيف فقط (تحذير لا عقوبة كبيرة)
    MINOR_PATTERNS = [
        (r'^[a-z]+$',      'Only lowercase letters'),
        (r'^[A-Z]+$',      'Only uppercase letters'),
        (r'^[a-zA-Z]+$',   'Only letters (no numbers/symbols)'),
        (r'[0-9]{4,}',     'Long number sequence'),
        (r'(19|20)\d{2}',  'Contains a year'),
        (r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', 'Contains month name'),
        (r'(0[1-9]|1[0-2])/(0[1-9]|1[0-9]|2[0-9]|3[0-1])', 'Contains date pattern'),
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MyScanner-Password-Checker'})
        logger.info("✅ PasswordAnalyzer initialized successfully")
    
    def check_length(self, password: str) -> Dict[str, Any]:
        logger.debug("Checking password length")
        length = len(password)
        
        if length < 8:
            score, status, message = 0, "Very Weak", "Password is too short (minimum 8 characters)"
        elif length < 10:
            score, status, message = 30, "Weak", "Acceptable length, but could be longer"
        elif length < 12:
            score, status, message = 60, "Good", "Good length"
        elif length < 16:
            score, status, message = 80, "Strong", "Strong length"
        else:
            score, status, message = 100, "Very Strong", "Excellent length"
        
        return {"length": length, "score": score, "status": status, "message": message}
    
    def check_character_variety(self, password: str) -> Dict[str, Any]:
        logger.debug("Checking character variety")
        has_upper  = bool(re.search(r'[A-Z]', password))
        has_lower  = bool(re.search(r'[a-z]', password))
        has_digit  = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
        score = (variety_count / 4) * 100
        
        recommendations = []
        if not has_upper:  recommendations.append("Add uppercase letters")
        if not has_lower:  recommendations.append("Add lowercase letters")
        if not has_digit:  recommendations.append("Add numbers")
        if not has_symbol: recommendations.append("Add special characters (!@#$%^&*)")
        
        return {
            "has_uppercase": has_upper, "has_lowercase": has_lower,
            "has_digits": has_digit,   "has_symbols": has_symbol,
            "variety_count": variety_count, "score": score,
            "recommendations": recommendations
        }
    
    def check_common_patterns(self, password: str) -> Dict[str, Any]:
        logger.debug("Checking common patterns")
        issues       = []   # مشاكل خطيرة  → خصم 15 لكل واحدة
        minor_issues = []   # مشاكل خفيفة → خصم 5  لكل واحدة

        # ✅ أنماط خطيرة
        for pattern, description in self.WEAK_PATTERNS:
            if re.search(pattern, password.lower()):
                issues.append(description)

        # ✅ أنماط خفيفة
        for pattern, description in self.MINOR_PATTERNS:
            if re.search(pattern, password.lower()):
                minor_issues.append(description)

        # كلمة مرور شائعة
        if password.lower() in self.COMMON_PASSWORDS:
            issues.append(f"Common password - easily guessable")
            logger.warning(f"Common password detected: {password[:3]}***")

        score = max(0, 100 - (len(issues) * 15) - (len(minor_issues) * 5))

        all_issues = issues + minor_issues
        if issues:
            logger.warning(f"Found {len(issues)} major weak patterns in password")
        if minor_issues:
            logger.debug(f"Found {len(minor_issues)} minor patterns in password (not critical)")

        return {
            "has_issues":   len(issues) > 0,       # فقط المشاكل الخطيرة
            "issues":       all_issues[:5],
            "major_count":  len(issues),
            "minor_count":  len(minor_issues),
            "score":        score
        }
    
    def check_entropy(self, password: str) -> Dict[str, Any]:
        logger.debug("Calculating password entropy")
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password): charset_size += 33
        
        if charset_size == 0:
            return {"entropy_bits": 0, "crack_time": "instant", "score": 0}
        
        entropy = len(password) * math.log2(charset_size)
        
        if entropy < 28:
            crack_time, score = "Instant (seconds)", 0
        elif entropy < 36:
            crack_time, score = "Minutes to hours", 25
        elif entropy < 60:
            crack_time, score = "Days to weeks", 50
        elif entropy < 80:
            crack_time, score = "Years", 75
        else:
            crack_time, score = "Centuries", 100
        
        return {"entropy_bits": round(entropy, 2), "crack_time": crack_time, "score": score}
    
    def check_pwned(self, password: str) -> Dict[str, Any]:
        logger.debug("Checking if password has been pwned")
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = self.session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10
            )
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.split(':')[0] == suffix:
                        count = int(line.split(':')[1])
                        logger.warning(f"Password found in pwned database! Count: {count}")
                        return {"is_pwned": True, "count": count,
                                "message": f"Found in {count} data breaches!"}
            
            return {"is_pwned": False, "count": 0, "message": "Not found in known breaches"}
            
        except Exception as e:
            logger.error(f"Error checking pwned password: {str(e)}")
            return {"is_pwned": False, "count": 0, "message": "Could not check breaches (API error)"}
    
    def calculate_final_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Calculating final score")

        scores = {
            'length':   results['length']['score'],
            'variety':  results['variety']['score'],
            'patterns': results['patterns']['score'],
            'entropy':  results['entropy']['score']
        }

        weights = {'length': 0.25, 'variety': 0.30, 'patterns': 0.25, 'entropy': 0.20}
        final_score = sum(scores[k] * weights[k] for k in scores)
        final_score = round(final_score, 2)

        # ✅ خصم 50 إذا كانت مسربة
        if results.get('pwned', {}).get('is_pwned', False):
            final_score = max(0, final_score - 50)
            logger.warning("Final score reduced by 50 due to pwned status")

        # ✅ إذا عنده مشاكل خطيرة، الحد الأقصى يصير 60 (لا يمكن أن يكون "Very Strong")
        major_count = results['patterns'].get('major_count', 0)
        if major_count >= 2:
            final_score = min(final_score, 40)
            logger.warning(f"Score capped at 40 due to {major_count} major pattern issues")
        elif major_count == 1:
            final_score = min(final_score, 60)
            logger.warning(f"Score capped at 60 due to 1 major pattern issue")

        # ✅ إذا عنده مشاكل خفيفة فقط، الحد الأقصى 75 (يطلع "Strong" مش "Very Strong")
        minor_count = results['patterns'].get('minor_count', 0)
        if minor_count > 0 and major_count == 0:
            final_score = min(final_score, 75)

        if final_score >= 80:
            strength, color, icon = "Very Strong", "green",  "✅"
        elif final_score >= 60:
            strength, color, icon = "Strong",      "green",  "✅"
        elif final_score >= 40:
            strength, color, icon = "Medium",      "yellow", "⚠️"
        elif final_score >= 20:
            strength, color, icon = "Weak",        "red",    "❌"
        else:
            strength, color, icon = "Very Weak",   "red",    "❌"

        logger.info(f"Final score: {final_score} | Strength: {strength} "
                    f"| Major issues: {major_count} | Minor issues: {minor_count}")

        return {"score": final_score, "strength": strength,
                "color": color, "icon": icon, "scores": scores}
    
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        logger.debug("Generating recommendations")
        recommendations = []
        
        if results['length']['length'] < 10:
            recommendations.append("🔐 Make your password longer (12+ characters recommended)")
        
        for rec in results['variety']['recommendations'][:3]:
            recommendations.append(f"🔤 {rec}")
        
        if results['patterns']['has_issues']:
            for issue in results['patterns']['issues'][:3]:
                recommendations.append(f"🚫 Avoid: {issue}")
        
        if results.get('pwned', {}).get('is_pwned', False):
            recommendations.append("⚠️ This password has been exposed in data breaches! Change it immediately.")
        
        if not recommendations:
            recommendations.append("✅ Your password is strong! Consider using a password manager.")
        
        return recommendations[:6]
    
    def comprehensive_analysis(self, password: str) -> Dict[str, Any]:
        logger.info(f"🔍 Starting comprehensive password analysis (length: {len(password)})")
        
        if not password:
            logger.error("No password provided for analysis")
            return {"error": "No password provided"}
        
        results = {
            "password_length": len(password),
            "length":   self.check_length(password),
            "variety":  self.check_character_variety(password),
            "patterns": self.check_common_patterns(password),
            "entropy":  self.check_entropy(password),
            "pwned":    self.check_pwned(password)
        }
        
        final = self.calculate_final_score(results)
        results['final'] = final
        results['recommendations'] = self.generate_recommendations(results)
        results['examples'] = [
            "C0mpl3x!P@ssw0rd2024",
            "Blue!Sky@Mountain#42",
            "Summer$Beach%Wave!89"
        ]
        
        logger.info(f"✅ Password analysis completed | Score: {final['score']} | Strength: {final['strength']}")
        return results