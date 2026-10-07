"""Distinguish a provider failure from a completed URL assessment."""
import math

PARTIAL_WARNING = 'Scan incomplete: url.vet did not provide a complete assessment. Local checks alone cannot confirm that this URL is safe.'


EVIDENCE_WARNING = 'Unverified phishing database submission: a database entry alone does not establish phishing. Overall safety has not been confirmed.'


def apply_phishing_evidence(provider):
    """Keep source scores intact; a database report is not a verified finding."""
    if not isinstance(provider, dict):
        return provider
    phishing = provider.get('phishing')
    if not isinstance(phishing, dict):
        provider['phishing_status'] = 'unavailable'
        return provider
    listed, verified, valid = phishing.get('in_database'), phishing.get('verified'), phishing.get('valid')
    if listed is True and verified is True and valid is True:
        provider['phishing_status'] = 'verified'
        provider.setdefault('verdict_reported', provider.get('verdict'))
        provider['verdict'] = 'malicious'
        provider['evidence_warning'] = 'The provider reports a verified phishing entry. A high provider score does not override this finding.'
    elif listed is True and verified is True and valid is False:
        provider['phishing_status'] = 'not_phishing'
    elif listed is True or verified is True or (listed is not None and type(listed) is not bool) or (verified is not None and type(verified) is not bool) or (valid is not None and type(valid) is not bool):
        provider['phishing_status'] = 'unverified' if listed is True and verified is False else 'unknown'
        provider.setdefault('verdict_reported', provider.get('verdict'))
        if provider.get('verdict') not in ('malicious', 'suspicious'):
            provider['verdict'] = 'unknown'
        provider['evidence_warning'] = EVIDENCE_WARNING
    else:
        provider['phishing_status'] = 'not_found' if listed is False and verified is False else 'unavailable'
    return provider


def urlvet_available(provider):
    apply_phishing_evidence(provider)
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
    result.setdefault('local_verdict', result.get('verdict', 'unknown'))
    available = urlvet_available(result.get('urlvet'))
    result['assessment_status'] = 'completed' if available else 'partial'
    provider = result.get('urlvet') or {}
    warning = provider.get('evidence_warning', '') if isinstance(provider, dict) else ''
    result['assessment_warning'] = warning or ('' if available else PARTIAL_WARNING)
    if isinstance(provider, dict) and provider.get('verdict') in ('suspicious', 'malicious') and result.get('verdict') != 'malicious':
        result['verdict'] = provider['verdict']
        result['verdict_icon'] = '🔴' if result['verdict'] == 'malicious' else '⚠️'
        if result.get('summary', {}).get('level') == 'Low Risk':
            result['summary'] = {'level': 'Threat reported', 'color': 'red', 'message': warning or 'The provider reported a threat.'}
    if not available:
        if result.get('verdict') in ('safe', 'harmless'):
            result['verdict'] = 'unknown'
            result['verdict_icon'] = '❓'
        if result.get('summary', {}).get('level') == 'Low Risk':
            result['summary'] = {'level': 'Incomplete Assessment', 'color': 'yellow', 'message': result['assessment_warning']}
        recommendations = result.get('recommendations', [])
        result['recommendations'] = [result['assessment_warning']] + [r for r in recommendations if r not in (PARTIAL_WARNING, result['assessment_warning']) and r != '✅ No threats detected - URL appears safe to visit']
    return result


def url_scan_outcome(local, deep):
    local_available = urlvet_available(local.get('urlvet'))
    deep_available = urlvet_available(deep.get('urlvet'))
    complete = local_available and deep_available
    verdicts = [local.get('verdict'), deep.get('verdict'), local.get('urlvet', {}).get('verdict'), deep.get('urlvet', {}).get('verdict')]
    for threat in ('malicious', 'high_risk', 'suspicious'):
        if threat in verdicts:
            return ('completed' if complete else 'partial'), threat
    return ('completed', local['urlvet']['verdict']) if complete else ('partial', 'unknown')
