# services/hybrid_analysis.py
# ================================================================
# Hybrid Analysis + VirusTotal + MyScanner Unified Sandbox Service
# ================================================================

import requests
import hashlib
import time
import os
import json
from datetime import datetime
from typing import Optional


HYBRID_API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

HYBRID_BASE = 'https://www.hybrid-analysis.com/api/v2'
VT_BASE = 'https://www.virustotal.com/api/v3'

ENVIRONMENTS = {
    '300': 'Windows 10 64-bit',
    '200': 'Windows 7 32-bit',
    '160': 'Windows 7 32-bit (Office)',
    '110': 'Windows XP 32-bit',
    '400': 'Android Static',
    '500': 'Linux (Ubuntu 16)',
}


class HybridAnalysisService:
    """
    خدمة تحليل موحدة تجمع:
    - Hybrid Analysis API  → تحليل سلوكي / Sandbox
    - VirusTotal API       → فحص محركات الكشف
    - MyScanner Static     → تحليل ثابت محلي
    """

    def __init__(self):
        self.ha_key = HYBRID_API_KEY
        self.vt_key = VIRUSTOTAL_API_KEY
        self.ha_headers = {
            'api-key': self.ha_key,
            'User-Agent': 'MyScanner/2.0',
            'accept': 'application/json',
        }

    # ──────────────────────────────────────────────
    #  HASH LOOKUP  (سريع - بدون رفع)
    # ──────────────────────────────────────────────
    def lookup_hash(self, file_hash: str) -> dict:
        """
        ابحث عن ملف بالـ hash في Hybrid Analysis.
        يعود بنتيجة فورية إن كان الملف محللاً مسبقاً.
        """
        results = {'ha': None, 'vt': None, 'found': False}

        # Hybrid Analysis
        if self.ha_key:
            try:
                resp = requests.post(
                    f'{HYBRID_BASE}/search/hash',
                    headers=self.ha_headers,
                    data={'hash': file_hash},
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data:
                        results['ha'] = data[0] if isinstance(data, list) else data
                        results['found'] = True
            except Exception as e:
                results['ha_error'] = str(e)

        # VirusTotal
        if self.vt_key:
            try:
                resp = requests.get(
                    f'{VT_BASE}/files/{file_hash}',
                    headers={'x-apikey': self.vt_key},
                    timeout=20
                )
                if resp.status_code == 200:
                    results['vt'] = resp.json().get('data', {})
                    results['found'] = True
            except Exception as e:
                results['vt_error'] = str(e)

        return results

    # ──────────────────────────────────────────────
    #  SUBMIT FILE  (رفع وتحليل)
    # ──────────────────────────────────────────────
    def submit_file(self, file_content: bytes, filename: str, environment_id: str = '300') -> dict:
        """
        ارفع ملفاً لـ Hybrid Analysis للتحليل السلوكي الكامل.
        """
        result = {
            'submitted': False,
            'job_id': None,
            'sha256': hashlib.sha256(file_content).hexdigest(),
            'environment': ENVIRONMENTS.get(environment_id, 'Unknown'),
            'error': None
        }

        if not self.ha_key:
            result['error'] = 'Hybrid Analysis API key not configured'
            return result

        try:
            resp = requests.post(
                f'{HYBRID_BASE}/submit/file',
                headers=self.ha_headers,
                files={'file': (filename, file_content, 'application/octet-stream')},
                data={
                    'environment_id': environment_id,
                    'allow_community_access': True,
                    'no_share_third_party': False,
                    'comment': 'Submitted via MyScanner',
                },
                timeout=60
            )

            if resp.status_code in (200, 201):
                data = resp.json()
                result['submitted'] = True
                result['job_id'] = data.get('job_id') or data.get('sha256')
                result['sha256'] = data.get('sha256', result['sha256'])
                result['environment_id'] = environment_id
            else:
                result['error'] = f'Submit failed: HTTP {resp.status_code} - {resp.text[:200]}'

        except Exception as e:
            result['error'] = str(e)

        return result

    # ──────────────────────────────────────────────
    #  GET REPORT  (استرجاع التقرير)
    # ──────────────────────────────────────────────
    def get_report(self, sha256: str, environment_id: str = '300') -> dict:
        """
        استرجع تقرير التحليل الكامل من Hybrid Analysis.
        """
        if not self.ha_key:
            return {'error': 'API key not configured', 'state': 'error'}

        try:
            resp = requests.get(
                f'{HYBRID_BASE}/report/{sha256}/summary',
                headers=self.ha_headers,
                params={'environment_id': environment_id},
                timeout=30
            )

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {'state': 'not_found'}
            else:
                return {'error': f'HTTP {resp.status_code}', 'state': 'error'}

        except Exception as e:
            return {'error': str(e), 'state': 'error'}

    # ──────────────────────────────────────────────
    #  POLL UNTIL DONE  (انتظر اكتمال التحليل)
    # ──────────────────────────────────────────────
    def poll_report(self, sha256: str, environment_id: str = '300',
                    max_wait: int = 300, interval: int = 15) -> dict:
        """
        انتظر حتى ينتهي التحليل (حد أقصى max_wait ثانية).
        """
        elapsed = 0
        while elapsed < max_wait:
            report = self.get_report(sha256, environment_id)
            state = report.get('state', '')

            if state in ('SUCCESS', 'ERROR', 'not_found'):
                return report
            if report.get('error') and 'not_found' not in report.get('error', ''):
                return report

            time.sleep(interval)
            elapsed += interval

        return {'state': 'TIMEOUT', 'error': f'Analysis did not complete within {max_wait}s'}

    # ──────────────────────────────────────────────
    #  VIRUSTOTAL SUBMIT
    # ──────────────────────────────────────────────
    def submit_to_virustotal(self, file_content: bytes, filename: str) -> dict:
        """رفع الملف لـ VirusTotal وانتظار النتيجة."""
        if not self.vt_key:
            return {'error': 'VirusTotal API key not configured'}

        try:
            headers = {'x-apikey': self.vt_key}
            resp = requests.post(
                f'{VT_BASE}/files',
                headers=headers,
                files={'file': (filename, file_content)},
                timeout=60
            )

            if resp.status_code not in (200, 201):
                return {'error': f'VT submit failed: {resp.status_code}'}

            analysis_id = resp.json()['data']['id']
            analysis_url = f'{VT_BASE}/analyses/{analysis_id}'

            for _ in range(30):
                time.sleep(5)
                r = requests.get(analysis_url, headers=headers, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    if data['data']['attributes'].get('status') == 'completed':
                        return data['data']['attributes']

            return {'error': 'VT analysis timeout'}

        except Exception as e:
            return {'error': str(e)}

    # ──────────────────────────────────────────────
    #  COMPREHENSIVE ANALYSIS  (التحليل الكامل الموحد)
    # ──────────────────────────────────────────────
    def comprehensive_analysis(self, file_content: bytes, filename: str,
                               environment_id: str = '300') -> dict:
        """
        تحليل شامل يجمع:
        1. Hash lookup (فوري)
        2. Hybrid Analysis Sandbox (سلوكي)
        3. VirusTotal (محركات الكشف)
        4. Static Analysis (محلي)
        """
        sha256 = hashlib.sha256(file_content).hexdigest()
        md5 = hashlib.md5(file_content).hexdigest()
        sha1 = hashlib.sha1(file_content).hexdigest()

        result = {
            'filename': filename,
            'file_size': len(file_content),
            'sha256': sha256,
            'md5': md5,
            'sha1': sha1,
            'environment': ENVIRONMENTS.get(environment_id, 'Windows 10 64-bit'),
            'environment_id': environment_id,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {},
            'verdict': 'unknown',
            'threat_score': 0,
            'threat_level': 'unknown',
            'behavior': {},
            'network': {},
            'processes': [],
            'signatures': [],
            'mitre_attacks': [],
            'dropped_files': [],
            'screenshots': [],
            'errors': [],
        }

        # ── 1. Hash Lookup ──
        lookup = self.lookup_hash(sha256)
        if lookup.get('found'):
            result['sources']['hash_lookup'] = 'found'
            if lookup.get('ha'):
                self._parse_ha_report(result, lookup['ha'])
            if lookup.get('vt'):
                self._parse_vt_report(result, lookup['vt'])
            result['from_cache'] = True
            return result

        result['from_cache'] = False

        # ── 2. Hybrid Analysis Submit ──
        if self.ha_key:
            submit = self.submit_file(file_content, filename, environment_id)
            if submit.get('submitted'):
                result['job_id'] = submit.get('job_id')
                result['sources']['hybrid_analysis'] = 'submitted'

                ha_report = self.poll_report(sha256, environment_id)
                if ha_report.get('state') == 'SUCCESS':
                    self._parse_ha_report(result, ha_report)
                    result['sources']['hybrid_analysis'] = 'completed'
                elif ha_report.get('state') == 'TIMEOUT':
                    result['sources']['hybrid_analysis'] = 'timeout'
                    result['errors'].append('Hybrid Analysis timed out - analysis still running')
                else:
                    result['errors'].append(ha_report.get('error', 'HA failed'))
            else:
                result['errors'].append(submit.get('error', 'HA submit failed'))

        # ── 3. VirusTotal ──
        if self.vt_key:
            vt_result = self.submit_to_virustotal(file_content, filename)
            if not vt_result.get('error'):
                self._parse_vt_attributes(result, vt_result)
                result['sources']['virustotal'] = 'completed'
            else:
                result['errors'].append(f"VT: {vt_result['error']}")

        # ── 4. حساب الحكم النهائي ──
        self._calculate_final_verdict(result)

        return result

    # ──────────────────────────────────────────────
    #  PARSERS
    # ──────────────────────────────────────────────
    def _parse_ha_report(self, result: dict, report: dict):
        """تحليل تقرير Hybrid Analysis واستخراج البيانات المهمة."""
        result['threat_score'] = max(result['threat_score'], report.get('threat_score', 0) or 0)
        result['threat_level'] = report.get('threat_level', result['threat_level']) or result['threat_level']
        result['verdict'] = report.get('verdict', result['verdict']) or result['verdict']

        # السلوك
        result['behavior'] = {
            'registry_keys': report.get('registry_keys_modified', []) or [],
            'files_created': report.get('files_created', []) or [],
            'files_deleted': report.get('files_deleted', []) or [],
            'mutexes': report.get('mutexes', []) or [],
            'services_created': report.get('services', []) or [],
        }

        # الشبكة
        result['network'] = {
            'domains': report.get('domains', []) or [],
            'hosts': report.get('hosts', []) or [],
            'http_requests': report.get('http_requests', []) or [],
            'dns_requests': report.get('dns_requests', []) or [],
            'compromised_hosts': report.get('compromised_hosts', []) or [],
        }

        # العمليات
        result['processes'] = report.get('processes', []) or []

        # التوقيعات
        result['signatures'] = [
            {
                'name': s.get('name', ''),
                'description': s.get('description', ''),
                'severity': s.get('threat_level_human', 'info'),
            }
            for s in (report.get('signatures', []) or [])
        ]

        # MITRE ATT&CK
        result['mitre_attacks'] = [
            {
                'tactic': m.get('tactic', ''),
                'technique': m.get('technique', ''),
                'attck_id': m.get('attck_id', ''),
                'attck_id_wiki': m.get('attck_id_wiki', ''),
            }
            for m in (report.get('mitre_attcks', []) or [])
        ]

        # الملفات المُسقطة
        result['dropped_files'] = report.get('dropped_files', []) or []

        # Screenshots
        result['screenshots'] = report.get('screenshots', []) or []

        # AV detections من HA
        result['av_detections'] = report.get('av_detect', 0) or 0
        result['total_engines'] = 100  # HA يستخدم ~100 محرك

    def _parse_vt_report(self, result: dict, report: dict):
        """تحليل تقرير VirusTotal من hash lookup."""
        attrs = report.get('attributes', {})
        self._parse_vt_attributes(result, attrs)

    def _parse_vt_attributes(self, result: dict, attrs: dict):
        """تحليل attributes من VirusTotal."""
        stats = attrs.get('stats', {})
        last_analysis = attrs.get('last_analysis_results', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        result['vt_stats'] = {
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'total': total,
            'detection_rate': round((malicious + suspicious) / total * 100, 1) if total > 0 else 0,
        }

        # أبرز المحركات التي اكتشفت
        result['vt_detections'] = [
            {
                'engine': engine,
                'result': data.get('result', ''),
                'category': data.get('category', ''),
                'version': data.get('engine_version', ''),
            }
            for engine, data in last_analysis.items()
            if data.get('category') in ('malicious', 'suspicious')
        ][:20]

        # تحديث threat_score من VT
        vt_score = int((malicious / total * 100)) if total > 0 else 0
        result['threat_score'] = max(result['threat_score'], vt_score)

    def _calculate_final_verdict(self, result: dict):
        """حساب الحكم النهائي الموحد بناءً على كل المصادر."""
        score = result['threat_score']
        vt_stats = result.get('vt_stats', {})
        vt_malicious = vt_stats.get('malicious', 0)
        vt_total = vt_stats.get('total', 1)

        # تطبيق قواعد الحكم
        if result.get('verdict') in ('malicious',) or vt_malicious >= 5:
            result['verdict'] = 'malicious'
            result['threat_level'] = 'malicious'
            result['threat_score'] = max(score, 80)
        elif result.get('verdict') == 'suspicious' or vt_malicious >= 2:
            result['verdict'] = 'suspicious'
            result['threat_level'] = 'suspicious'
            result['threat_score'] = max(score, 50)
        elif score >= 70:
            result['verdict'] = 'malicious'
            result['threat_level'] = 'malicious'
        elif score >= 40:
            result['verdict'] = 'suspicious'
            result['threat_level'] = 'suspicious'
        elif vt_malicious == 0 and vt_total > 0:
            result['verdict'] = 'no_threat'
            result['threat_level'] = 'no_threat'
            result['threat_score'] = min(score, 10)
        else:
            result['verdict'] = 'unknown'
            result['threat_level'] = 'unknown'

    # ──────────────────────────────────────────────
    #  URL SANDBOX
    # ──────────────────────────────────────────────
    def submit_url(self, url: str, environment_id: str = '300') -> dict:
        """إرسال URL للتحليل السلوكي في Sandbox."""
        if not self.ha_key:
            return {'error': 'API key not configured', 'submitted': False}

        try:
            resp = requests.post(
                f'{HYBRID_BASE}/submit/url-for-analysis',
                headers=self.ha_headers,
                data={
                    'url': url,
                    'environment_id': environment_id,
                    'allow_community_access': True,
                },
                timeout=30
            )

            if resp.status_code in (200, 201):
                data = resp.json()
                return {
                    'submitted': True,
                    'job_id': data.get('job_id'),
                    'sha256': data.get('sha256'),
                    'environment': ENVIRONMENTS.get(environment_id, 'Unknown'),
                }
            return {'error': f'HTTP {resp.status_code}: {resp.text[:200]}', 'submitted': False}

        except Exception as e:
            return {'error': str(e), 'submitted': False}

    # ──────────────────────────────────────────────
    #  QUICK STATS  (للـ Dashboard)
    # ──────────────────────────────────────────────
    def get_verdict_badge(self, verdict: str) -> dict:
        """إرجاع بيانات الـ badge للواجهة."""
        badges = {
            'malicious': {'color': '#ff4560', 'icon': '🚨', 'label': 'MALICIOUS', 'bg': '#2d0a0a'},
            'suspicious': {'color': '#ffd32a', 'icon': '⚠️', 'label': 'SUSPICIOUS', 'bg': '#2d250a'},
            'no_threat': {'color': '#00e676', 'icon': '✅', 'label': 'CLEAN', 'bg': '#0a2d12'},
            'unknown': {'color': '#6a6a90', 'icon': '❓', 'label': 'UNKNOWN', 'bg': '#1a1a2e'},
        }
        return badges.get(verdict, badges['unknown'])