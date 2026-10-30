"""Site report assembly over the shared pinned, read-only web assessment."""
import time
from urllib.parse import urlsplit
from xml.etree import ElementTree
import requests
from services.safe_http import PublicHTTPSession, TargetResolutionError, UnsafeTargetError
from services.web_assessment import WebAssessment, response_chain
from services.active_scan_policy import skipped_active_analysis

HEADER_NOTES = {
    'Strict-Transport-Security':'HTTPS transport policy. Presence alone does not validate its directives.',
    'Content-Security-Policy':'Browser content policy. Presence alone does not establish a restrictive or effective policy.',
    'X-Content-Type-Options':'nosniff prevents MIME type guessing in supported contexts.',
    'Referrer-Policy':'Controls referrer information sent by browsers.',
    'X-Frame-Options':'Framing control; CSP frame-ancestors can provide the alternative.'}

def header_observations(http):
    values = http.get('security_headers', {})
    completed = http.get('status') == 'completed'
    https = urlsplit(http.get('final_url', '')).scheme == 'https'
    rows = []
    for name, note in HEADER_NOTES.items():
        value = values.get(name, '')
        status = 'present' if value else 'missing'
        if not completed: status = 'unavailable'
        elif name == 'Strict-Transport-Security' and not https: status = 'not_applicable'
        elif name == 'X-Frame-Options' and not value and any(part.strip().lower().startswith('frame-ancestors ') for part in str(values.get('Content-Security-Policy', '')).split(';')): status = 'alternative_present'
        rows.append({'name':name,'status':status,'value':value,'note':note})
    return rows

def discovery_documents(url):
    parsed = urlsplit(url)
    origin = parsed.scheme+'://'+parsed.netloc
    deadline = time.monotonic()+7
    results = {}
    with PublicHTTPSession(response_limit=128*1024, deadline=deadline) as session:
        for name, path in [('robots','/robots.txt'),('sitemap','/sitemap.xml')]:
            response = None
            try:
                response, chain, reason = response_chain(session, origin+path, deadline)
                if response is None:
                    results[name]={'status':'unavailable','reason':'Document response unavailable','chain':chain}
                    continue
                row={'status':'observed','http_status':response.status_code,'url':chain[-1]['url'],'chain':chain}
                if response.status_code in (404,410):row['status']='not_found'
                elif response.status_code != 200:row.update(status='unavailable',reason='Document did not return HTTP 200')
                elif name == 'robots':
                    if 'html' in response.headers.get('Content-Type','').lower():
                        row.update(status='unavailable',reason='An HTML page was returned instead of robots text')
                    else:
                        directives=[]
                        for line in response.text.splitlines()[:1000]:
                            line=line.split('#',1)[0].strip()
                            if ':' in line:
                                key,value=line.split(':',1)
                                if key.lower() in ('user-agent','allow','disallow','sitemap','crawl-delay'):
                                    directives.append({'name':key[:40],'value':value.strip()[:512]})
                        row['directives']=directives[:50];row['note']='Discovery text only; disallowed paths are not secrets or access controls. Listed paths are not requested.'
                else:
                    body=response.content
                    if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ValueError()
                    root=ElementTree.fromstring(body)
                    kind=root.tag.rsplit('}',1)[-1]
                    if kind not in ('urlset','sitemapindex'):raise ValueError()
                    row['document_type']=kind;row['entries_observed']=min(len(root),100);row['limited']=len(root)>100
                    row['note']='XML structure observed only. Listed URLs are not fetched.'
                results[name]=row
            except TargetResolutionError:
                results[name]={'status':'unavailable','reason':'Document destination DNS unavailable'}
            except UnsafeTargetError:
                results[name]={'status':'blocked','reason':'Document request blocked by public-network or response-size policy'}
            except (requests.RequestException, ValueError, ElementTree.ParseError):
                results[name]={'status':'unavailable','reason':'Document retrieval or structure validation failed'}
            finally:
                if response is not None:response.close()
    return results

def assess_site(value, include_provider=False, include_discovery=False):
    if type(include_provider) is not bool or type(include_discovery) is not bool:raise ValueError()
    started=time.monotonic()
    report=WebAssessment().analyze(value,include_provider=include_provider)
    report['site_schema_version']=2
    if report['http']['status']=='completed' and report['content']['status']=='completed':
        # site-crawl-v1: walk the site's own pages and check what they link to and offer.
        from services import site_crawl
        found=site_crawl.crawl(report['http']['final_url'])
        age=((report.get('trust') or {}).get('domain_age') or {}).get('age_days')
        crawl,crawl_findings=site_crawl.assess(found, age)
        report['crawl']=crawl
        report['findings'].extend(crawl_findings)
        report['checks'].append({'name':'Site pages','status':'completed' if crawl['pages_read'] else 'unavailable'})
        if any(f['code'] in ('crawl_page_listed','crawl_malware_download') for f in crawl_findings):
            report['verdict']='malicious'
        elif any(f['severity']=='warning' for f in crawl_findings) and report['verdict']!='malicious':
            report['verdict']='suspicious'
    else:
        report['crawl']={'policy':'site-crawl-v1','status':'not_performed','pages_read':0}
    if report['http']['status']=='completed':
        # site-posture-v1: hosting, email in its name, software, outside scripts, cookies.
        from services import site_posture
        posture,posture_findings=site_posture.assess(report)
        report['posture']=posture
        report['findings'].extend(posture_findings)
        report['checks'].append({'name':'Site setup','status':'completed'})
        if any(f['severity']=='warning' for f in posture_findings) and report['verdict']!='malicious':
            report['verdict']='suspicious'
    else:
        report['posture']={'policy':'site-posture-v1','status':'not_performed'}
    report['domain']=report['structure']['hostname']
    report['analysis_mode']='passive';report['active_scan_performed']=False
    report['from_cache']=False;report['evidence_policy']='site-passive-v3'
    report['vulnerabilities']={'dynamic':skipped_active_analysis(),'static':{'status':'not_performed','note':'Static HTML observations are not confirmed SQL injection or XSS vulnerabilities.'}}
    report['security_score']=None;report['risk_score']=None
    report['header_observations']=header_observations(report['http'])
    # Header presence is a configuration observation, never a malware verdict.
    if report['http']['status']=='completed':
        report['checks'].append({'name':'Security headers','status':'completed'})
        for row in report['header_observations']:
            if row['status'] == 'missing':
                report['findings'].append({'code':'missing_'+row['name'].lower().replace('-','_'), 'severity':'info',
                    'title':'Header not observed: '+row['name'],
                    'detail':'The final HTTP response did not publish this header. This is a configuration observation, not a confirmed vulnerability. '+row['note']})
            if row['name']=='X-Content-Type-Options' and row['status']=='present' and row['value'].strip().lower()!='nosniff':
                report['findings'].append({'code':'nosniff_value','severity':'info','title':'Review MIME-sniffing policy','detail':'X-Content-Type-Options is present but its value is not nosniff.'})
    else:report['checks'].append({'name':'Security headers','status':'unavailable'})
    if include_discovery and report['http']['status']!='blocked':
        report['discovery']=discovery_documents(report['http'].get('final_url',report['url']))
    else:
        report['discovery']={name:{'status':'not_requested','reason':'Optional documents were not requested' if not include_discovery else 'Skipped after a blocked destination'} for name in ('robots','sitemap')}
    for name,row in report['discovery'].items():
        report['checks'].append({'name':'robots.txt' if name=='robots' else 'sitemap.xml','status':'completed' if row['status'] in ('observed','not_found') else row['status']})
    selected=[c for c in report['checks'] if c['status'] not in ('not_requested','not_applicable')]
    completed=sum(c['status'] in ('completed','invalid') for c in selected)
    total=len(selected)
    report['assessment']={'score':round(100*completed/total) if total else 0,'checks_completed':completed,'checks_total':total,'label':'Inspection coverage','warning':'Coverage is not a safety score; optional checks not requested are excluded.'}
    report['coverage_status']='completed' if completed==total and total else 'partial'
    report['assessment_status']=report['coverage_status']
    report['status']='success' if report['coverage_status']=='completed' else 'partial'
    report['stats'].update(checks_completed=completed, checks_total=total,
        checks_not_requested=sum(c['status']=='not_requested' for c in report['checks']),
        warning_count=sum(f['severity']=='warning' for f in report['findings']),
        observation_count=len(report['findings']))
    report['performance']={'elapsed_ms':round((time.monotonic()-started)*1000),'scope':'Whole assessment elapsed time, not browser load time or a performance grade.'}
    report['missing_checks']=[c['name'] for c in selected if c['status'] not in ('completed','invalid')]
    report['scope']='Read-only public HTTP, DNS, TLS and static HTML observations. No exploit attempts, JavaScript execution, form submission or downloads.'
    report['report_brief']=[f"Read-only inspection of {report['domain']}.",f"Final HTTP response: {report['http'].get('status_code','unavailable')}; {report['stats']['redirect_count']} redirects observed.",f"TLS certificate state: {report['tls']['status']}; static page: {report['content']['status']}.",f"{completed} of {total} selected checks returned usable observations; {len(report['findings'])} review observations.", 'Review the evidence and missing checks. This report does not establish that the site is safe.']
    return report
