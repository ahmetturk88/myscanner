"""Versioned evidence index: a policy score, never a probability of safety."""
import math


def assess_file(report):
    mb = report.get('malwarebazaar') or {}
    meta = report.get('metadata') or {}
    missing = report.get('missing_checks') or []
    confirmed = report.get('verdict') == 'malicious' or (mb.get('status') == 'matched' and mb.get('is_malicious') is True)
    base = report.get('security_score')
    valid = type(base) in (int, float) and math.isfinite(base) and 0 <= base <= 100
    partial = report.get('coverage_status') != 'completed' or bool(missing) or mb.get('status') not in ('matched', 'not_found')
    deductions = []
    if mb.get('status') not in ('matched', 'not_found'):
        deductions.append({'points': 15, 'reason': 'Hash reputation not verified'})
    if missing or (partial and not deductions):
        deductions.append({'points': 10, 'reason': 'Static inspection coverage limited'})
    if not valid or meta.get('error') or meta.get('metadata_error'):
        deductions.append({'points': 25, 'reason': 'Local index unavailable or metadata failed'})
    archive_limited = meta.get('is_archive') and (meta.get('error') or meta.get('encrypted') is True or any('member contents' in str(x).lower() for x in meta.get('missing_checks', [])))
    if archive_limited:
        deductions.append({'points': 30, 'reason': 'Archive contents unavailable or not inspected'})
    penalty = sum(d['points'] for d in deductions)
    # Without a local index there is no measured baseline to credit.
    score = 0 if confirmed or not valid else max(0, round(base - penalty))
    if report.get('verdict') in ('suspicious', 'high_risk'):
        score = min(score, 59 if report['verdict'] == 'suspicious' else 29)
    return {'score': score, 'local_index': base if valid else None,
            'coverage_penalty': penalty, 'deductions': deductions,
            'coverage': 'partial' if partial or not valid else 'completed',
            'policy_version': 'file-evidence-v2',
            'warning': 'Evidence and coverage index; not a safety probability. Zero may mean insufficient evidence or a confirmed threat; read the verdict.'}
