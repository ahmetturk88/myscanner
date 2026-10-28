"""Email evidence index; not a safety probability or delivery guarantee."""
import math

POLICY_VERSION = 'email-evidence-v4'
# v4: what the domain name and Google say about it. Scam senders set up SPF and DMARC
# like anyone else, so a copied brand name or a Web Risk listing decides on its own.
DECEPTION = {
    'homograph_name': 'The domain uses letters from another alphabet that look like normal ones.',
    'lookalike_name': 'The domain copies a well-known name with swapped letters or numbers.',
    'brand_in_subdomain': 'The domain puts a well-known site’s address in front of a different domain to fool you.',
    'scheme_in_name': 'The domain starts with “http” or “https” to look official.',
}
ESTABLISHED_DAYS = 5 * 365

def assess_email(report):
    report=report if isinstance(report,dict) else {}
    dns=report.get('dns') if isinstance(report.get('dns'),dict) else {}
    smtp=report.get('smtp') if isinstance(report.get('smtp'),dict) else {}
    reputation=report.get('blacklist') if isinstance(report.get('blacklist'),dict) else {}
    domain=report.get('domain_info') if isinstance(report.get('domain_info'),dict) else {}
    categories=[];findings=[];missing=[]
    if dns.get('domain_status')=='not_found':
        # A domain absent from DNS cannot receive mail; partial-coverage scoring would understate that.
        weights=(('routing','Mail routing',20),('authentication','Sender authentication',25),('reputation','Domain reputation',25),('mailbox','Mailbox acceptance',15),('identity','Domain history',15))
        return {'policy_version':POLICY_VERSION,'score':0,'evidence_score':0,'risk_deduction':100,'coverage_penalty':0,'verdict':'no_domain','coverage':'completed',
                'categories':[{'key':k,'label':l,'weight':w,'risk_deduction':w,'coverage_deduction':0,'status':'assessed'} for k,l,w in weights],
                'findings':[{'category':'routing','deduction':100,'message':'The domain does not exist in DNS (NXDOMAIN), so this address cannot receive email.'}],
                'missing_checks':[],'not_checked':['Blocklist, registration and mailbox checks were skipped because there is no domain to check.'],
                'warning':'Evidence and coverage index, not a probability or a guarantee of safety or delivery.'}
    def category(key,label,weight,checks,risks):
        gaps=[label+': '+item for item in checks if item]
        risk=min(weight,sum(points for points,message in risks));coverage=min(weight-risk,5*len(gaps))
        categories.append({'key':key,'label':label,'weight':weight,'risk_deduction':risk,'coverage_deduction':coverage,'status':'partial' if gaps else 'assessed'})
        missing.extend(gaps)
        findings.extend({'category':key,'deduction':points,'message':message} for points,message in risks)
    mx=dns.get('mx',{});mx=mx if isinstance(mx,dict) else {}
    routing=[]
    if mx.get('status')=='not_found':routing.append((20,'No MX record was found; implicit routing was not tested.'))
    elif any(isinstance(r,dict) and r.get('exchange') in ('','.') for r in (mx.get('records') if isinstance(mx.get('records'),list) else [])):
        routing.append((20,'The domain declares a null MX and does not accept email.'))
    infrastructure=mx.get('infrastructure') if isinstance(mx.get('infrastructure'),list) else []
    if any(isinstance(host,dict) and host.get('unsafe_addresses') for host in infrastructure):
        routing.append((20,'An MX hostname resolves to a non-public address; direct connections are blocked.'))
    routing_gaps=[None if mx.get('status') in ('found','not_found') else 'MX lookup unavailable']
    if any(isinstance(host,dict) and host.get('status')!='assessed' for host in infrastructure):
        routing_gaps.append('Sampled MX address discovery incomplete')
    category('routing','Mail routing',20,routing_gaps,routing)
    auth=[];gaps=[]
    for name,points in (('spf',10),('dmarc',10)):
        value=dns.get(name,{});value=value if isinstance(value,dict) else {}
        if value.get('status')=='not_found':auth.append((points,name.upper()+' record not found.'))
        elif value.get('status')!='found':gaps.append(name.upper()+' lookup unavailable')
        audit=value.get('audit',{})
        if isinstance(audit,dict) and audit.get('configuration_valid') is False:
            auth.append((points,name.upper()+' configuration issues: '+'; '.join(audit.get('issues',[]))))
        if isinstance(audit,dict) and audit.get('status')=='partial':
            gaps.append(name.upper()+' dependency audit limited')
    dmarc=dns.get('dmarc',{})
    # A monitoring or test-mode DMARC policy describes the domain owner's anti-spoofing
    # setup, not a risk of this address; gmail.com itself uses p=none (email-evidence-v3).
    if isinstance(dmarc,dict) and dmarc.get('status')=='found' and dmarc.get('policy')=='none' and dmarc.get('audit',{}).get('configuration_valid') is not False:auth.append((0,'DMARC uses a monitoring policy (p=none), not enforcement.'))
    if isinstance(dmarc,dict) and dmarc.get('audit',{}).get('test_mode') is True and dmarc.get('policy') != 'none':
        auth.append((0,'DMARC test mode requests a less strict effective policy.'))
    category('authentication','Sender authentication',25,gaps,auth)
    rep=[]
    if reputation.get('is_blacklisted') is True:rep.append((20,'A DNS blocklist reports a sampled mail-infrastructure IP; this does not prove that the mailbox is malicious.'))
    if report.get('is_disposable') is True:rep.append((10,'The domain appears in the local disposable-domain dataset.'))
    # One blocklist that answered covers reputation; ones that refused are listed, not counted as a gap (v3).
    answered=reputation.get('coverage_status')=='completed' or bool(reputation.get('clean_on')) or reputation.get('is_blacklisted') is True
    category('reputation','Domain reputation',25,[None if answered else 'DNS blocklist coverage incomplete'],rep)
    unanswered=[s for s in reputation.get('unavailable_on') or [] if isinstance(s,str)] if answered else []
    mailbox=[]
    if smtp.get('coverage_status')=='checked' and smtp.get('valid') is False:mailbox.append((15,'The SMTP server rejected this recipient probe.'))
    # A probe that was not requested (or is disabled) is out of scope, not a coverage gap (v3).
    probed=smtp.get('coverage_status') in ('checked','skipped','not_applicable')
    category('mailbox','Mailbox acceptance',15,[None if probed else 'SMTP acceptance not verified'],mailbox)
    age=domain.get('age_days');known=isinstance(age,(int,float)) and not isinstance(age,bool) and math.isfinite(age) and age>=0 and not domain.get('error')
    category('identity','Domain history',15,[None if known else 'Registration age unavailable'],[(5,'The domain was registered less than 30 days ago.')] if known and age<30 else [])
    names=[n for n in report.get('name_signals') or [] if isinstance(n,dict)]
    codes={n.get('code') for n in names}
    new=known and age<365;established=known and age>=ESTABLISHED_DAYS
    dangerous=False;name_risks=[]
    for item in names:
        code=item.get('code')
        if code=='lookalike_name' and item.get('tld_swap') and established:continue  # an old defensive registration
        if code in DECEPTION and (item.get('strong') or new):
            dangerous=True;name_risks.append((15,DECEPTION[code]))
        elif code=='lookalike_name' and not established:
            name_risks.append((10,'The domain is one letter away from a well-known brand’s name.'))
        elif code=='brand_in_name' and not established:
            brand=item.get('brand_name') or item.get('brand') or 'a brand'
            if new or 'risky_tld' in codes:
                dangerous=True;name_risks.append((15,f'The domain uses {brand}’s name but isn’t one of its known domains, and it is new or uses a cheap ending.'))
            else:
                name_risks.append((10,f'The domain uses {brand}’s name but isn’t one of its known domains.'))
    if 'risky_tld' in codes and new and not name_risks:
        name_risks.append((5,'The domain is new and uses a cheap ending that scam sites use most.'))
    web_risk=report.get('web_risk') if isinstance(report.get('web_risk'),dict) else {}
    listed=[t for t in web_risk.get('threat_types') or [] if isinstance(t,str)] if web_risk.get('status')=='matched' else []
    if listed:
        dangerous=True
    added=[('identity',points,message) for points,message in name_risks]
    if listed:
        added.append(('reputation',25,'Google Web Risk lists this domain’s website for '+('phishing' if 'SOCIAL_ENGINEERING' in listed else 'malware')+'.'))
    for item in categories:
        extra=sum(points for key,points,message in added if key==item['key'])
        if extra:
            item['risk_deduction']=min(item['weight'],item['risk_deduction']+extra)
            item['coverage_deduction']=min(item['coverage_deduction'],item['weight']-item['risk_deduction'])
    findings.extend({'category':key,'deduction':points,'message':message} for key,points,message in added)
    risk=sum(c['risk_deduction'] for c in categories);coverage=sum(c['coverage_deduction'] for c in categories)
    score=max(0,100-risk-coverage)
    if dangerous:score=min(score,20)
    verdict='dangerous' if dangerous else 'review' if risk else 'unknown' if missing else 'no_indicators'
    return {'policy_version':POLICY_VERSION,'score':score,'evidence_score':100-risk,'risk_deduction':risk,'coverage_penalty':coverage,'verdict':verdict,'copies_brand':any(m.startswith('The domain') and 'new and uses' not in m for p,m in name_risks),'coverage':'partial' if missing else 'completed','categories':categories,'findings':findings,'missing_checks':missing,'not_checked':['DKIM signature verification requires a message and selector; it was not performed.','Breach exposure and mailbox ownership were not checked.']
                   +(['Mailbox acceptance (SMTP) was not probed.'] if smtp.get('coverage_status')=='skipped' else [])
                   +(['Blocklists that did not answer: '+', '.join(unanswered)+'.'] if unanswered else []),'warning':'Evidence and coverage index, not a probability or a guarantee of safety or delivery.'}
