# password_analyzer.py - تحليل متقدم لكلمات المرور
import re
import hashlib
import requests
from time import monotonic
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
            logger.warning("Common password pattern detected")

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
    
    @staticmethod
    def breach_result(status, count=None):
        messages = {
            'found': 'This password appears in the Pwned Passwords dataset. Replace it.',
            'not_found': 'No match in the checked dataset. This does not prove the password is safe.',
            'unavailable': 'Breach lookup could not be completed. Exposure remains unknown.',
            'skipped': 'Breach lookup was not requested. Exposure remains unknown.',
        }
        return {'status': status, 'is_pwned': True if status == 'found' else False if status == 'not_found' else None,
                'count': count, 'source': 'Have I Been Pwned — Pwned Passwords', 'message': messages[status]}

    def check_pwned(self, password: str) -> Dict[str, Any]:
        """Send only a five-character hash prefix; never turn failure into a negative match."""
        from services.source_switches import source_enabled
        if not source_enabled('pwnedpasswords'):
            return self.breach_result('unavailable')
        response = None
        try:
            digest = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = digest[:5], digest[5:]
            deadline = monotonic() + 12
            response = self.session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'Add-Padding': 'true'}, timeout=(3, 5),
                allow_redirects=False, stream=True,
            )
            if response.status_code != 200:
                return self.breach_result('unavailable')
            body = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                if monotonic() > deadline or len(body) + len(chunk) > 262144:
                    return self.breach_result('unavailable')
                body.extend(chunk)
            lines = body.decode('ascii').splitlines()
            if not lines or len(lines) > 5000:
                return self.breach_result('unavailable')
            records = {}
            for line in lines:
                if not re.fullmatch(r'[0-9A-F]{35}:[0-9]{1,12}', line):
                    return self.breach_result('unavailable')
                record_suffix, raw_count = line.split(':')
                if record_suffix in records:
                    return self.breach_result('unavailable')
                records[record_suffix] = int(raw_count)
            # Padding records have count zero and are not evidence of exposure.
            count = records.get(suffix, 0)
            return self.breach_result('found', count) if count > 0 else self.breach_result('not_found', 0)
        except Exception:
            # Request errors can contain URLs/hash prefixes; keep them out of logs/results.
            logger.warning('Password breach lookup unavailable')
            return self.breach_result('unavailable')
        finally:
            if response is not None:
                response.close()

    def close(self):
        self.session.close()

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
        
        if results.get('pwned', {}).get('status') in {'unavailable', 'skipped'}:
            recommendations.append("Breach exposure is unknown; local strength is not proof of safety.")

        if not recommendations:
            recommendations.append("✅ Your password is strong! Consider using a password manager.")
        
        return recommendations[:6]
    

    def comprehensive_analysis(self, password: str, check_breaches: bool = False) -> Dict[str, Any]:
        """Bounded local estimate; return no password, hash, tokens or examples."""
        if not isinstance(password, str) or not password or len(password) > 128 or type(check_breaches) is not bool:
            return {'error': 'Enter 1-128 characters and valid boolean options'}
        try:
            from zxcvbn import zxcvbn
            estimate = zxcvbn(password, max_length=128)
            # zxcvbn raw output contains the secret and matched substrings: never serialize it.
            log_guesses = float(estimate['guesses_log10'])
            score = max(0, min(100, round(log_guesses / 14 * 100)))
            rank = int(estimate['score'])
            strength = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][rank]
            kinds = sorted({m.get('pattern') for m in estimate['sequence'] if m.get('pattern') in
                            {'dictionary','spatial','repeat','sequence','regex','date'}})
            descriptions = {
                'dictionary':'Recognizable words, names or common-password fragments were detected.',
                'spatial':'A keyboard path was detected.',
                'repeat':'Repeated characters or blocks were detected.',
                'sequence':'A predictable character sequence was detected.',
                'regex':'A familiar pattern such as a year was detected.',
                'date':'A date-like pattern was detected.'}
            findings = [{'code': k, 'message': descriptions[k]} for k in kinds]
            local = {'status':'completed','score':score,'strength':strength,'estimator':'zxcvbn',
                     'estimator_rank':rank,'guesses_log10':round(log_guesses,2),
                     'scope':'Model estimate of guess resistance, not entropy, crack time or a safety probability.',
                     'score_policy':'password-guess-v1: min(100, round(log10(estimated guesses)/14*100))',
                     'deductions':[{'reason':'Predictability and length under the guess model','points':100-score}],
                     'findings':findings}
        except Exception:
            logger.warning('Local password estimation unavailable')
            local = {'status':'unavailable','score':None,'strength':'Unknown','estimator':'zxcvbn',
                     'scope':'Local estimator unavailable; no strength conclusion is possible.','findings':[],'deductions':[]}
        pwned = self.check_pwned(password) if check_breaches else self.breach_result('skipped')
        verdict = 'exposed' if pwned['status']=='found' else 'weak' if local['status']=='completed' and local['estimator_rank']<3 else 'review'
        recommendations = []
        if pwned['status']=='found': recommendations.append('Replace this password wherever it is used. Do not repair an exposed password by appending characters.')
        if local['status']=='completed' and local['estimator_rank']<3:
            recommendations.append('Use a password manager to create a unique random password, or independently select several random words.')
        if local['findings']: recommendations.append('Avoid predictable names, dates, keyboard paths and repeated blocks; length alone does not remove these patterns.')
        recommendations += ['Use a unique password for every account and enable MFA or a passkey when available.',
                            'Breach exposure remains unknown.' if pwned['status'] in ('skipped','unavailable') else 'A dataset result is not proof of account security.']
        return {'schema_version':2,'policy_version':'password-guess-v1','password_length':len(password),
                'local_strength':local,'final':dict(local),'pwned':pwned,'verdict':verdict,
                'coverage':{'local_strength':local['status'],'breach_lookup':pwned['status']},
                'status':'partial' if local['status']=='unavailable' or pwned['status']=='unavailable' else 'completed',
                'recommendations':recommendations,
                'summary':['Local guess-resistance estimate: '+str(local['score'])+'/100.' if local['score'] is not None else 'Local strength could not be estimated.',
                           'Breach dataset state: '+pwned['status']+'.',
                           'Strength and exposure are separate: a strong-looking password can still be exposed.',
                           'This check does not verify account ownership, reuse or MFA protection.'],
                'privacy':{'stored':False,'returned':False,'external_request':'Only a five-character SHA-1 prefix is sent when breach lookup is selected.',
                           'server_processing':'The entered password is sent over HTTPS to this application for analysis; it is not a browser-only check.'}}
