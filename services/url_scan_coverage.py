"""Distinguish a provider failure from a completed URL assessment."""
import math

PARTIAL_WARNING = 'Scan incomplete: url.vet did not provide a complete assessment. Local checks alone cannot confirm that this URL is safe.'


def urlvet_available(provider):
    if not isinstance(provider, dict) or provider.get('error') or provider.get('errors'):
        return False
    if provider.get('verdict') not in ('harmless', 'suspicious', 'malicious'):
        return False
    score = provider.get('trust_score')
    if isinstance(score, bool) or score is None:
        return False
    try:
        score = float(score)
        return math.isfinite(score) and 0 <= score <= 100
    except (ValueError, TypeError):
        return False


def apply_url_coverage(result):
    """Annotate fresh or saved analysis; preserve suspicious/malicious findings."""
    available = urlvet_available(result.get('urlvet'))
    result['assessment_status'] = 'completed' if available else 'partial'
    result['assessment_warning'] = '' if available else PARTIAL_WARNING
    result.setdefault('local_verdict', result.get('verdict', 'unknown'))
    if not available:
        if result.get('verdict') in ('safe', 'harmless'):
            result['verdict'] = 'unknown'
            result['verdict_icon'] = '❓'
        if result.get('summary', {}).get('level') == 'Low Risk':
            result['summary'] = {'level': 'Incomplete Assessment', 'color': 'yellow', 'message': PARTIAL_WARNING}
        recommendations = result.get('recommendations', [])
        result['recommendations'] = [PARTIAL_WARNING] + [r for r in recommendations if r != PARTIAL_WARNING and r != '✅ No threats detected - URL appears safe to visit']
    return result


def url_scan_outcome(local, deep):
    complete = urlvet_available(local.get('urlvet')) and urlvet_available(deep.get('urlvet'))
    verdicts = [local.get('verdict'), deep.get('verdict'), local.get('urlvet', {}).get('verdict'), deep.get('urlvet', {}).get('verdict')]
    for threat in ('malicious', 'high_risk', 'suspicious'):
        if threat in verdicts:
            return ('completed' if complete else 'partial'), threat
    return ('completed', local['urlvet']['verdict']) if complete else ('partial', 'unknown')
