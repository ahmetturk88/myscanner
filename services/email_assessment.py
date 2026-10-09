"""Email evidence index; not a safety probability or delivery guarantee."""
import math

def assess_email(report):
    report=report if isinstance(report,dict) else {}
    dns=report.get('dns') if isinstance(report.get('dns'),dict) else {}
    smtp=report.get('smtp') if isinstance(report.get('smtp'),dict) else {}
    reputation=report.get('blacklist') if isinstance(report.get('blacklist'),dict) else {}
    domain=report.get('domain_info') if isinstance(report.get('domain_info'),dict) else {}
    categories=[];findings=[];missing=[]
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
    category('routing','Mail routing',20,[None if mx.get('status') in ('found','not_found') else 'MX lookup unavailable'],routing)
    auth=[];gaps=[]
    for name,points in (('spf',10),('dmarc',10)):
        value=dns.get(name,{});value=value if isinstance(value,dict) else {}
        if value.get('status')=='not_found':auth.append((points,name.upper()+' record not found.'))
        elif value.get('status')!='found':gaps.append(name.upper()+' lookup unavailable')
    dmarc=dns.get('dmarc',{})
    if isinstance(dmarc,dict) and dmarc.get('status')=='found' and dmarc.get('policy')=='none':auth.append((5,'DMARC uses a monitoring policy (p=none), not enforcement.'))
    category('authentication','Sender authentication',25,gaps,auth)
    rep=[]
    if reputation.get('is_blacklisted') is True:rep.append((20,'A DNS blocklist reports the domain IP; this is not proof that this mailbox is malicious.'))
    if report.get('is_disposable') is True:rep.append((10,'The domain appears in the local disposable-domain dataset.'))
    category('reputation','Domain reputation',25,[None if reputation.get('coverage_status')=='completed' else 'DNS blocklist coverage incomplete'],rep)
    mailbox=[]
    if smtp.get('coverage_status')=='checked' and smtp.get('valid') is False:mailbox.append((15,'The SMTP server rejected this recipient probe.'))
    category('mailbox','Mailbox acceptance',15,[None if smtp.get('coverage_status')=='checked' else 'SMTP acceptance not verified'],mailbox)
    age=domain.get('age_days');known=isinstance(age,(int,float)) and not isinstance(age,bool) and math.isfinite(age) and age>=0 and not domain.get('error')
    category('identity','Domain history',15,[None if known else 'Registration age unavailable'],[(5,'The domain was registered less than 30 days ago.')] if known and age<30 else [])
    risk=sum(c['risk_deduction'] for c in categories);coverage=sum(c['coverage_deduction'] for c in categories)
    score=max(0,100-risk-coverage)
    verdict='review' if risk else 'unknown' if missing else 'no_indicators'
    return {'policy_version':'email-evidence-v1','score':score,'evidence_score':100-risk,'risk_deduction':risk,'coverage_penalty':coverage,'verdict':verdict,'coverage':'partial' if missing else 'completed','categories':categories,'findings':findings,'missing_checks':missing,'not_checked':['DKIM signature verification requires a message and selector; it was not performed.','Breach exposure and mailbox ownership were not checked.'],'warning':'Evidence and coverage index, not a probability or a guarantee of safety or delivery.'}
