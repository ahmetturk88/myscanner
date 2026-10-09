"""Bounded DNS policy auditing; does not authenticate a message or sender IP."""
import ipaddress
import re


def audit_spf(domain, records, lookup, budget=10):
    result={'status':'assessed','issues':[],'dependencies':[], 'dns_terms':0,
            'scope':'Static policy and literal include/redirect graph; no sender IP evaluation.'}
    def issue(message):
        if message not in result['issues']:result['issues'].append(message)
    def walk(name, texts, path):
        policies=[r for r in texts if isinstance(r,str) and re.match(r'^v=spf1(?:\s|$)',r,re.I)]
        if len(policies)!=1:issue('Expected exactly one SPF policy at '+name);return
        terms=policies[0].split()[1:];seen=set();all_seen=False
        for term in terms:
            if all_seen:
                if not term.startswith(('redirect=','exp=')):issue('Unreachable mechanism after all at '+name)
                continue
            body=term[1:] if term[:1] in '+-~?' else term
            kind=re.split(r'[:/=]',body,1)[0].lower()
            if '=' in body:
                if body!=term:issue('SPF modifiers cannot have a qualifier at '+name)
                key,value=body.split('=',1)
                key=key.lower()
                if key in seen:issue('Duplicate SPF modifier at '+name)
                seen.add(key)
                if key not in ('redirect','exp'):continue
            if kind=='all':
                all_seen=True
                if term[0] not in '-~':issue('Permissive SPF all mechanism at '+name)
            elif kind in ('ip4','ip6'):
                try:
                    network=ipaddress.ip_network(body.split(':',1)[1],strict=False)
                    if network.version!=(4 if kind=='ip4' else 6):raise ValueError()
                except (ValueError,IndexError):issue('Invalid SPF IP network at '+name)
            elif kind not in ('include','redirect','a','mx','ptr','exists','exp'):
                issue('Unknown SPF mechanism at '+name)
            if kind in ('include','redirect','a','mx','ptr','exists'):
                result['dns_terms']+=1
                if result['dns_terms']>budget:
                    issue('SPF DNS term budget exceeded');return
            if kind=='ptr':issue('SPF ptr mechanism is discouraged')
            if kind in ('include','redirect'):
                target=body.split('=',1)[1] if kind=='redirect' else body.partition(':')[2]
                if '%' in target:
                    result['status']='partial';issue('SPF macros require sender context; dependency not expanded');continue
                if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?',target) or '.' not in target:
                    issue('Invalid SPF dependency domain');continue
                target=target.lower().rstrip('.')
                if target in path:issue('SPF dependency cycle at '+target);continue
                texts,state=lookup(target,'TXT')
                result['dependencies'].append({'domain':target,'status':state})
                if state=='unavailable':result['status']='partial';continue
                walk(target,texts,path|{target})
    walk(domain,records,{domain.lower()})
    # Structural issues are observations, not a claim of message SPF pass/fail.
    result['configuration_valid']=not result['issues'] if result['status']=='assessed' else None
    return result


def audit_dmarc(records):
    selected=[r for r in records if isinstance(r,str) and r.lower().startswith('v=dmarc1')]
    result={'status':'assessed','configuration_valid':False,'issues':[], 'tags':{},
            'scope':'Published exact-domain policy; no message alignment or organizational-domain fallback.'}
    if len(selected)!=1:
        result['issues'].append('Expected exactly one DMARC record');return result
    tags={}
    for part in selected[0].split(';'):
        if not part.strip():continue
        if '=' not in part:result['issues'].append('Malformed DMARC tag');continue
        key,value=(s.strip() for s in part.split('=',1));key=key.lower()
        if key in tags:result['issues'].append('Duplicate DMARC tag: '+key)
        tags[key]=value
    if next(iter(tags),None)!='v' or tags.get('v','').upper()!='DMARC1':result['issues'].append('DMARC version must be first')
    for key in ('p','sp','np'):
        if key in tags and tags[key] not in ('none','quarantine','reject'):result['issues'].append('Invalid DMARC '+key+' policy')
    for key in ('adkim','aspf'):
        if key in tags and tags[key] not in ('r','s'):result['issues'].append('Invalid DMARC alignment mode')
    if 't' in tags and tags['t'] not in ('y','n'):result['issues'].append('Invalid DMARC test mode')
    result['policy']=tags.get('p','none')
    result['test_mode']=tags.get('t','n')=='y'
    result['standard']='RFC 9989; exact-domain static audit'
    result['tags']=tags;result['configuration_valid']=not result['issues']
    result['alignment']={'dkim':tags.get('adkim','r'),'spf':tags.get('aspf','r')}
    result['reporting_destinations']=[v.strip() for v in tags.get('rua','').split(',') if v.strip()][:10]
    result['note']='Reporting destination authorization and message alignment were not verified.'
    return result
