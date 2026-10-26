"""Versioned, deterministic evidence index. It is not an estimated probability."""
import copy
import math
from urllib.parse import urlparse

from services.web_risk import MESSAGES as WEB_RISK_MESSAGES
from services.url_scan_coverage import apply_phishing_evidence

POLICY_VERSION = 'url-evidence-v11'
PROVIDER_REVIEW = 'A provider reports a threat; confirmation details require review'
# v10: url.vet's own overall verdict is a threshold over signals we already read
# one by one (and includes a traffic-rank heuristic that flags small, honest
# sites). Without one of these visible signals it is recorded, not scored.
PROVIDER_NOTE = 'url.vet rated it a risk without a signal we could confirm; it does not change the verdict.'
# Short links whose destination we never reached cannot be called safe (v10).
SHORT_UNRESOLVED = 'Redirect destination of the short link could not be reached'
WEIGHTS = {'transport':20, 'identity':20, 'content':25, 'behavior':15, 'reputation':20}
# A browser warns before these pages, so the report never calls them clean (v6).
TRANSPORT_WARNINGS = {'tls_invalid', 'no_https'}
# An unconfirmed community phishing report counts only with one of these (v7):
# anyone can submit any URL, but a pending report plus a look-alike or
# impersonation signal is how new phishing pages usually appear.
CORROBORATING = {'typosquatting','homoglyph','punycode','brand_mismatch','hidden_iframe','ip_url','domain_randomness','domain_history'}
NOT_VISITED = 'The page was not visited because the address uses a port other than 80 or 443; only its reputation was checked.'
UNVERIFIED_REPORT = 'A community phishing database has an unconfirmed report for this URL; reviewers have not confirmed it.'
# v11: signals that are weak alone but together describe a throwaway scam site.
# Escalation needs at least one of CORE; age and traffic alone never flag a site,
# and url.vet's own rating counts but is not core (it is built on age and traffic).
CORE = {'risky_tld', 'domain_randomness', 'content_hidden'}
ESTABLISHED_DAYS = 5 * 365
TOP_RANK = 50000


def number(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)):return None
    return float(value) if math.isfinite(value) and 0<=value<=100 else None


def mapping(value):
    return value if isinstance(value, dict) else {}


def usable(value):
    return isinstance(value,dict) and bool(value) and not value.get('error')


def host(url):
    name=(urlparse(url).hostname or '').lower() if isinstance(url,str) else ''
    return name[4:] if name.startswith('www.') else name


def upgraded_to_https(behavior):
    """True when an http:// address redirected to HTTPS on the same site (v6)."""
    final=behavior.get('final_url')
    return (behavior.get('error') is None and isinstance(final,str) and final.lower().startswith('https://')
            and bool(host(final)) and host(final)==host(behavior.get('original_url')))


def age_days(local, deep, provider):
    for value in (mapping(deep.get('whois')).get('age_days'), mapping(local.get('whois')).get('age_days'),
                  mapping(provider.get('domain_info')).get('age_days')):
        if isinstance(value,int) and not isinstance(value,bool) and value>0:return value
    return None


def throwaway_signals(local, deep, provider, provider_flag, reasons, signal):
    """v11 signals for new, unlisted scams. Returns (weak codes, strong scam lure, established)."""
    age=age_days(local,deep,provider)
    rank=provider.get('rank') if isinstance(provider.get('rank'),int) and not isinstance(provider.get('rank'),bool) else None
    established=(age is not None and age>=ESTABLISHED_DAYS) or (rank is not None and 0<rank<=TOP_RANK)
    weak=set()
    if mapping(provider.get('tld_info')).get('is_risky') is True:
        weak.add('risky_tld');signal('identity','risky_tld',4,'The address ends in a domain type that is cheap and often used for scam sites.')
    if rank==0:weak.add('unranked')
    if age is not None and age<365:
        weak.add('new_domain');signal('identity','new_domain',4,'The site was registered less than a year ago.')
    if 'domain_randomness' in reasons:weak.add('domain_randomness')
    if provider_flag:weak.add('provider_flag')
    page=mapping(deep.get('page_content'))
    behavior=mapping(deep.get('behavior'))
    final=behavior.get('final_url') if isinstance(behavior.get('final_url'),str) else ''
    try:
        parts=urlparse(final or (deep.get('url') if isinstance(deep.get('url'),str) else ''))
        deep_link=parts.path not in ('','/') or bool(parts.query)
    except ValueError:
        deep_link=False
    status=page.get('status_code')
    text=page.get('visible_text_length')
    if usable(page) and deep_link and not established and (
            status in (403,404,410) or (isinstance(text,int) and not isinstance(text,bool) and text<80 and not page.get('forms'))):
        weak.add('content_hidden')
        signal('content','content_hidden',10,'The page showed our scanner an error or an empty page. Scam pages do this to hide from security checks.')
    scam=set(page.get('scam_signals') or []) if isinstance(page.get('scam_signals'),list) else set()
    strong=bool(scam&{'prize_offer','fake_comments'})
    if strong:
        signal('content','scam_content',20,'The page promises free money or prizes, or shows fake comments, the way scam pages do.')
    elif 'collects_phone_or_card' in scam:
        weak.add('collects_details')
    return weak,strong,established


def assess_url(local, deep):
    local=local if isinstance(local,dict) else {}
    deep=deep if isinstance(deep,dict) else {}
    upgraded=upgraded_to_https(mapping(deep.get('behavior')))
    components={key:{'weight':weight,'status':'unavailable','deduction':0,'reasons':[]} for key,weight in WEIGHTS.items()}
    reasons={}; missing=[]; confirmed=False; review=False; reported=False; provider_verdicts=[]; seen_provider={}
    def assessed(key):components[key]['status']='assessed'
    def signal(key,code,points,message):
        assessed(key)
        # Stable evidence codes count once across sources. Independent signals add
        # within a capped category, so repeated source scores never add penalties.
        prior=reasons.get(code)
        if prior is None or points>prior['deduction']:
            reasons[code]={'category':key,'code':code,'deduction':points,'message':message}
    sources=[]
    for label,data in [('local',local),('deep',deep)]:
        if not usable(data):missing.append(label+' analysis unavailable');continue
        structure=mapping(data.get('structure'))
        if usable(structure) and type(structure.get('is_https')) is bool:
            assessed('transport');assessed('identity')
            if structure['is_https'] is False and not upgraded:signal('transport','no_https',20,'The URL does not use HTTPS.')
            if structure.get('contains_ip') is True:signal('identity','ip_url',8,'The URL uses an IP address instead of a domain.')
        ssl=mapping(data.get('ssl'))
        if usable(ssl) and type(ssl.get('valid')) is bool:
            assessed('transport')
            if ssl['valid'] is False:signal('transport','tls_invalid',20,'Certificate validation failed.')
        elif structure.get('is_https') is True:missing.append(label+' certificate check unavailable')
        headers=mapping(data.get('security_headers'))
        score=number(headers.get('score')) if usable(headers) else None
        if score is not None:
            assessed('transport')
            if score<50:signal('transport','headers_weak',5,'Some defensive HTTP headers are absent.')
        elif label=='local':missing.append('HTTP header check unavailable')
        phishing=mapping(data.get('phishing'))
        risk=number(phishing.get('risk_score')) if usable(phishing) else None
        if risk is not None:
            assessed('identity')
            if risk>0:signal('identity','url_phishing_patterns',min(15,round(risk*.15,1)),'URL naming patterns resemble phishing heuristics; this is not confirmation.')
        whois=mapping(data.get('whois'))
        age_risk=number(whois.get('whois_risk_score')) if usable(whois) else None
        if age_risk is not None and age_risk>0:signal('identity','domain_history',min(8,round(age_risk*.08,1)),'Domain history contains risk indicators.')
        provider=copy.deepcopy(mapping(data.get('urlvet')))
        if not isinstance(provider,dict):provider={}
        apply_phishing_evidence(provider)
        errors=provider.get('errors')
        # A known WHOIS-only failure leaves the other provider checks usable.
        # Never render upstream error text, which may contain private data.
        whois_only=(usable(provider) and isinstance(errors,list) and bool(errors)
                    and all(isinstance(error,str) and error.startswith('whois_lookup:') for error in errors))
        if whois_only:
            missing.append('URLVet domain registration (WHOIS) check unavailable')
            provider.pop('domain_info',None)
        if not usable(provider) or ((errors or provider.get('incomplete') is True) and not whois_only):
            missing.append(label+' URLVet assessment unavailable or incomplete')
        else:
            sources.append('url.vet')
            provider_verdicts.append(provider.get('verdict'))
            seen_provider=provider
            features=mapping(provider.get('url_features'))
            for field,code,points,message in [('uses_ip','ip_url',8,'The URL uses an IP address instead of a domain.'),('contains_punycode','punycode',3,'Internationalized domain spelling requires review.'),('has_homoglyph','homoglyph',8,'The domain contains look-alike characters.'),('has_keywords','url_phishing_patterns',5,'URL naming patterns resemble phishing heuristics; this is not confirmation.')]:
                if features.get(field) is True:signal('identity',code,points,message)
            if features.get('url_shortener') is True:
                signal('identity','shortener',5,'A URL shortener hides the destination in the original URL.')
            if mapping(provider.get('typosquatting')).get('is_suspicious') is True:
                signal('identity','typosquatting',8,'The domain resembles another domain; verify its spelling independently.')
            if mapping(provider.get('domain_randomness')).get('is_suspicious') is True:
                signal('identity','domain_randomness',3,'The domain naming pattern is unusually random.')
            provider_content=mapping(provider.get('content'))
            if provider_content.get('brand_mismatch') is True:
                signal('content','brand_mismatch',10,'The page brand differs from its domain; review for impersonation.')
            if provider_content.get('has_hidden_iframe') is True:
                signal('content','hidden_iframe',5,'The provider reports hidden embedded content.')
            provider_behavior=mapping(provider.get('analysis'))
            redirects=provider_behavior.get('chain_length')
            if isinstance(redirects,int) and not isinstance(redirects,bool) and redirects>2:
                signal('behavior','redirect_behavior',3 if redirects>4 else 1.5,'Redirect behavior contains risk indicators.')
            tls=mapping(provider.get('ssl_info'))
            if type(tls.get('chain_valid')) is bool:
                assessed('transport')
                if tls['chain_valid'] is False:signal('transport','tls_invalid',20,'Certificate validation failed.')
            evidence=provider.get('phishing_status')
            if evidence=='verified':
                confirmed=True;signal('reputation','verified_phishing',20,'The provider reports a verified, valid phishing match.')
            elif evidence in ('not_found','not_phishing'):assessed('reputation')
            elif evidence=='unverified':
                assessed('reputation');reported=True;signal('reputation','unverified_report',0,UNVERIFIED_REPORT)
            else:
                review=True;missing.append('Phishing database evidence is unverified or unavailable')
        sources.append(label)
    content=mapping(deep.get('page_content'))
    risk=number(content.get('content_risk_score')) if usable(content) else None
    if risk is not None and 'title' in content and mapping(deep.get('behavior')).get('error') is None:
        assessed('content')
        if type(content.get('has_password_field')) is bool:
            # v10: the analyzer's subtotal counts security vocabulary and outbound
            # links, which every security or news site has. Only a form that asks
            # for credentials counts; scam wording adds weight to such a form.
            password=content['has_password_field'];login=content.get('has_login_form') is True
            words=bool(content.get('suspicious_keywords_found'))
            points=(10 if password else 3 if login else 0)+(5 if (password or login) and words else 0)
            if points:signal('content','content_indicators',points,'The page asks for a password or login; forms alone do not prove a threat.')
        elif risk>0:signal('content','content_indicators',round(risk*.25,1),'Page content contains risk heuristics; forms or keywords alone do not prove a threat.')
    else:missing.append('Deep page content was not assessed')
    behavior=mapping(deep.get('behavior'))
    risk=number(behavior.get('behavior_risk_score')) if usable(behavior) else None
    if risk is not None:
        assessed('behavior')
        # The old behavior subtotal includes the URL-shortener penalty. Remove
        # it here and assign that signal once to identity.
        adjusted=max(0,risk-(15 if behavior.get('is_shortened') is True else 0))
        if adjusted:signal('behavior','redirect_behavior',round(adjusted*.15,1),'Redirect behavior contains risk indicators.')
    else:missing.append('Redirect behavior was not assessed')
    if local.get('is_shortened') is True or behavior.get('is_shortened') is True:
        signal('identity','shortener',5,'A URL shortener hides the destination in the original URL.')
        # Some shorteners answer automated visits with their own preview page, so
        # the scan stays on the shortener and never sees the real destination.
        ends=[host(behavior.get(k)) for k in ('original_url','final_url')]
        if risk is not None and all(ends) and ends[0]==ends[1]:
            missing.append(SHORT_UNRESOLVED)
    osint=mapping(deep.get('osint'))
    if usable(osint) and osint.get('urlhaus') is True:
        confirmed=True;signal('reputation','urlhaus_match',20,'URLhaus reports a malware URL match.')
    # Legacy reports did not preserve URLhaus availability: never infer success
    # from their default false/zero values.
    if osint.get('urlhaus_status') not in ('matched','not_found'):
        reason={'not_configured':'authentication is not configured','authentication_rejected':'authentication was rejected','rate_limited':'provider rate limit reached','configuration_error':'credential configuration could not be read','connection_or_response_error':'connection or response failed','http_error':'provider returned an HTTP error'}.get(osint.get('urlhaus_reason'),'check unavailable or not recorded')
        missing.append('URLhaus: '+reason)
    elif osint.get('urlhaus_status')=='not_found':assessed('reputation')
    # v9: a Google Web Risk match confirms a threat. The source is optional, so a missing key
    # or an unavailable lookup is not a coverage gap; URLhaus and URLVet still cover reputation.
    web_risk=mapping(osint.get('web_risk'))
    if web_risk.get('status')=='matched' and isinstance(web_risk.get('threat_types'),list) and web_risk['threat_types']:
        confirmed=True
        for kind in web_risk['threat_types']:
            if kind in WEB_RISK_MESSAGES:signal('reputation','web_risk_'+kind.lower(),20,WEB_RISK_MESSAGES[kind])
        sources.append('google_web_risk')
    elif web_risk.get('status')=='not_found':
        assessed('reputation');sources.append('google_web_risk')
    # v5: analyzer thresholds (local/deep verdicts) are not evidence of a threat.
    # Only a verified phishing entry or a URLhaus match confirms one; any other
    # provider threat verdict asks for review.
    provider_flag=any(v in ('malicious','suspicious','high_risk') for v in provider_verdicts)
    weak,strong_scam,established=throwaway_signals(local,deep,seen_provider,provider_flag,reasons,signal)
    for item in reasons.values():components[item['category']]['reasons'].append(item['code'])
    for key,component in components.items():
        component['deduction']=min(component['weight'],round(sum(v['deduction'] for v in reasons.values() if v['category']==key),1))
        if component['status']=='unavailable':missing.append(key+' evidence unavailable')
    count=sum(c['status']=='assessed' for c in components.values())
    provider_note=provider_flag and not confirmed and not CORROBORATING&set(reasons)
    missing=list(dict.fromkeys(missing))
    score=round(100-sum(c['deduction'] for c in components.values())) if count else None
    deducted=sum(c['deduction'] for c in components.values())>0
    if confirmed:
        score=min(score if score is not None else 100,10);verdict='malicious'
    elif score is not None and deducted and score<75:
        verdict='high_risk' if score<40 else 'suspicious'
    elif provider_flag and not provider_note:verdict='suspicious'
    elif missing or review:verdict='unknown'
    else:verdict='harmless'
    if verdict in ('harmless','unknown') and TRANSPORT_WARNINGS & set(reasons):verdict='suspicious'
    if reported and verdict in ('harmless','unknown') and CORROBORATING & set(reasons):verdict='suspicious'
    # v11: one verdict from all evidence. A scam lure on the page, or several weak
    # signs including one that throwaway scam sites typically show, raise it.
    escalated=None
    if not confirmed and not established:
        if strong_scam and weak:escalated='high_risk'
        elif len(weak)>=4 and CORE&weak:escalated='high_risk'
        elif strong_scam or (len(weak)>=3 and CORE&weak):escalated='suspicious'
    rank_order=['harmless','unknown','suspicious','high_risk','malicious']
    if escalated and rank_order.index(escalated)>rank_order.index(verdict):
        verdict=escalated
        score=min(score if score is not None else 100,35 if verdict=='high_risk' else 60)
    if verdict in ('suspicious','high_risk') and 'provider_flag' in weak:
        provider_note=False  # url.vet's rating counted as one of the signs
    # Coverage deductions are separate from threat evidence. Missing categories
    # use their full weight; missing checks within an assessed category cost 5
    # each, deduplicated across quick/deep sources and capped by that category.
    coverage_codes={key:set() for key in WEIGHTS}
    for message in missing:
        normalized=message.removeprefix('local ').removeprefix('deep ')
        key='identity' if 'WHOIS' in message else 'transport' if 'certificate' in message or 'header' in message else 'content' if 'content' in message else 'behavior' if 'Redirect' in message else 'reputation'
        if normalized in ('analysis unavailable','evidence unavailable') or message==PROVIDER_REVIEW:
            continue
        coverage_codes[key].add(normalized)
    coverage_deductions={}
    for key,component in components.items():
        requested=component['weight'] if component['status']=='unavailable' else 5*len(coverage_codes[key])
        coverage_deductions[key]=min(max(0,component['weight']-component['deduction']),requested)
    coverage_penalty=sum(coverage_deductions.values())
    final_score=max(0,score-coverage_penalty) if score is not None else None
    if local.get('reputation_only') is True:
        # One plain reason replaces the page checks that were never meant to run (v8).
        missing=[NOT_VISITED]+[m for m in missing if m.startswith('URLhaus')]
    return {'policy_version':POLICY_VERSION,'score':final_score,
            'coverage_penalty':coverage_penalty,'coverage_deductions':coverage_deductions,
            'evidence_score':score,'verdict':verdict,
            'coverage':'partial' if missing else 'completed','provisional':bool(missing),
            'assessed_categories':count,'total_categories':len(WEIGHTS),
            'components':components,'reasons':list(reasons.values()),'missing_checks':missing,
            'sources':list(dict.fromkeys(sources)),
            'threat_override':bool(confirmed),
            'provider_note':PROVIDER_NOTE if provider_note else None,
            'warning':'Heuristic evidence index, not a probability or a guarantee of safety.'}


def saved_assessment(saved, local, deep):
    """Return the verdict recorded at scan time; never re-score it silently.

    Reports saved before an assessment was stored are scored with the current
    policy and marked as such. When the stored policy is older, the current
    policy's result is attached separately so readers can see both.
    """
    stored = saved.get('aggregate_assessment') if isinstance(saved, dict) else None
    if not isinstance(stored, dict) or not isinstance(stored.get('policy_version'), str):
        current = assess_url(local, deep)
        current['assessed_at_read_time'] = True
        return current
    result = copy.deepcopy(stored)
    if stored['policy_version'] != POLICY_VERSION:
        current = assess_url(local, deep)
        result['current_policy'] = {'policy_version': POLICY_VERSION, 'verdict': current['verdict'],
                                    'score': current['score'], 'coverage': current['coverage']}
    return result
