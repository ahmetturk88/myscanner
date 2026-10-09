"""Versioned, deterministic evidence index. It is not an estimated probability."""
import copy
import math
from services.url_scan_coverage import apply_phishing_evidence

POLICY_VERSION = 'url-evidence-v4'
WEIGHTS = {'transport':20, 'identity':20, 'content':25, 'behavior':15, 'reputation':20}


def number(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)):return None
    return float(value) if math.isfinite(value) and 0<=value<=100 else None


def mapping(value):
    return value if isinstance(value, dict) else {}


def usable(value):
    return isinstance(value,dict) and bool(value) and not value.get('error')


def assess_url(local, deep):
    local=local if isinstance(local,dict) else {}
    deep=deep if isinstance(deep,dict) else {}
    components={key:{'weight':weight,'status':'unavailable','deduction':0,'reasons':[]} for key,weight in WEIGHTS.items()}
    reasons={}; missing=[]; confirmed=False; review=False
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
            if structure['is_https'] is False:signal('transport','no_https',20,'The URL does not use HTTPS.')
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
            else:
                review=True;missing.append('Phishing database evidence is unverified or unavailable')
        sources.append(label)
    content=mapping(deep.get('page_content'))
    risk=number(content.get('content_risk_score')) if usable(content) else None
    if risk is not None and 'title' in content and mapping(deep.get('behavior')).get('error') is None:
        assessed('content')
        if risk>0:signal('content','content_indicators',round(risk*.25,1),'Page content contains risk heuristics; forms or keywords alone do not prove a threat.')
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
    osint=mapping(deep.get('osint'))
    if usable(osint) and osint.get('urlhaus') is True:
        confirmed=True;signal('reputation','urlhaus_match',20,'URLhaus reports a malware URL match.')
    # Legacy reports did not preserve URLhaus availability: never infer success
    # from their default false/zero values.
    if osint.get('urlhaus_status') not in ('matched','not_found'):
        reason={'not_configured':'authentication is not configured','authentication_rejected':'authentication was rejected','rate_limited':'provider rate limit reached','configuration_error':'credential configuration could not be read','connection_or_response_error':'connection or response failed','http_error':'provider returned an HTTP error'}.get(osint.get('urlhaus_reason'),'check unavailable or not recorded')
        missing.append('URLhaus: '+reason)
    elif osint.get('urlhaus_status')=='not_found':assessed('reputation')
    reported=[data.get('verdict') for data in (local,deep)]
    reported += [(mapping(data.get('urlvet'))).get('verdict') for data in (local,deep) if isinstance(mapping(data.get('urlvet')),dict)]
    reported_threat='malicious' in reported
    for item in reasons.values():components[item['category']]['reasons'].append(item['code'])
    for key,component in components.items():
        component['deduction']=min(component['weight'],round(sum(v['deduction'] for v in reasons.values() if v['category']==key),1))
        if component['status']=='unavailable':missing.append(key+' evidence unavailable')
    count=sum(c['status']=='assessed' for c in components.values())
    missing=list(dict.fromkeys(missing))
    score=round(100-sum(c['deduction'] for c in components.values())) if count else None
    if confirmed or reported_threat:
        score=min(score if score is not None else 100,10);verdict='malicious'
        if reported_threat and not confirmed:missing.append('An analyzer reports a threat; confirmation details require review')
    elif score is not None and (score<75 or any(v in ('suspicious','high_risk') for v in reported)):
        verdict='high_risk' if score<40 else 'suspicious'
    elif missing or review:verdict='unknown'
    else:verdict='harmless'
    # Coverage deductions are separate from threat evidence. Missing categories
    # use their full weight; missing checks within an assessed category cost 5
    # each, deduplicated across quick/deep sources and capped by that category.
    coverage_codes={key:set() for key in WEIGHTS}
    for message in missing:
        normalized=message.removeprefix('local ').removeprefix('deep ')
        key='identity' if 'WHOIS' in message else 'transport' if 'certificate' in message or 'header' in message else 'content' if 'content' in message else 'behavior' if 'Redirect' in message else 'reputation'
        if normalized in ('analysis unavailable','evidence unavailable') or 'confirmation details' in message:
            continue
        coverage_codes[key].add(normalized)
    coverage_deductions={}
    for key,component in components.items():
        requested=component['weight'] if component['status']=='unavailable' else 5*len(coverage_codes[key])
        coverage_deductions[key]=min(max(0,component['weight']-component['deduction']),requested)
    coverage_penalty=sum(coverage_deductions.values())
    final_score=max(0,score-coverage_penalty) if score is not None else None
    return {'policy_version':POLICY_VERSION,'score':final_score,
            'coverage_penalty':coverage_penalty,'coverage_deductions':coverage_deductions,
            'evidence_score':score,'verdict':verdict,
            'coverage':'partial' if missing else 'completed','provisional':bool(missing),
            'assessed_categories':count,'total_categories':len(WEIGHTS),
            'components':components,'reasons':list(reasons.values()),'missing_checks':missing,
            'sources':list(dict.fromkeys(sources)),
            'threat_override':bool(confirmed or reported_threat),
            'warning':'Heuristic evidence index, not a probability or a guarantee of safety.'}
