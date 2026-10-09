"""Bounded domain metadata lookup, with per-source coverage."""
import os
import time
from urllib.parse import urlsplit
from services.safe_http import PublicHTTPSession, normalize_url

class DomainAnalyzer:
    def __init__(self):
        self.session=PublicHTTPSession(response_limit=1024*1024,deadline=time.monotonic()+30)
        self.timeout=5
    def analyze_domain(self, domain):
        try:
            normalized=normalize_url(domain)
            parts=urlsplit(normalized)
            if parts.path!='/' or parts.query:raise ValueError()
            domain=parts.hostname
        except Exception:return {'error':'A valid domain name is required','verdict':'unknown'}
        result={'domain':domain,'registrar':'N/A','created':'N/A','expires':'N/A','ip':'N/A','country':'N/A','isp':'N/A','nameservers':[],'dns':[],'whois_updated':'N/A','status':'N/A','verdict':'unknown','coverage':{},'scope':'Domain metadata only; no malware, mailbox or website safety conclusion.'}
        try:
            result.update(self._get_whois_info(domain))
            result['coverage']['whois']=result.pop('_whois_status')
            result.update(self._get_ip_info(domain));result['coverage']['geolocation']=result.pop('_ip_status')
            result['dns'],result['coverage']['dns']=self._get_dns_records(domain)
            result['coverage_status']='completed' if all(v=='assessed' for v in result['coverage'].values()) else 'partial'
            return result
        finally:self.session.close()
    def _json(self,url,params):
        response=self.session.get(url,params=params,timeout=self.timeout,allow_redirects=False)
        response.raise_for_status()
        if response.status_code!=200:raise ValueError()
        data=response.json()
        if not isinstance(data,dict):raise ValueError()
        return data
    def _get_whois_info(self,domain):
        key=os.environ.get('WHOISXML_API_KEY')
        if not key:return {'_whois_status':'not_configured'}
        try:
            record=self._json('https://www.whoisxmlapi.com/whoisserver/WhoisService',{'domainName':domain,'apiKey':key,'outputFormat':'JSON'})['WhoisRecord']
            if not isinstance(record,dict) or not record or record.get('dataError'):raise ValueError()
            result={'_whois_status':'assessed','nameservers':record.get('nameServers',{}).get('hostNames',[])[:5]}
            for key,source in {'registrar':'registrarName','created':'createdDate','expires':'expiresDate','whois_updated':'updatedDate','status':'status'}.items():result[key]=record.get(source) or 'N/A'
            return result
        except Exception:return {'_whois_status':'unavailable'}
    def _get_ip_info(self,domain):
        try:
            data=self._json('http://ip-api.com/json/'+domain,{})
            if data.get('status')!='success':raise ValueError()
            return {'_ip_status':'assessed','ip':data.get('query','N/A'),'country':data.get('country','N/A'),'isp':data.get('isp','N/A')}
        except Exception:return {'_ip_status':'unavailable'}
    def _get_dns_records(self,domain):
        records=[];unavailable=False
        for kind in ('A','AAAA','MX','NS','TXT','CNAME','SOA'):
            try:
                data=self._json('https://dns.google/resolve',{'name':domain,'type':kind})
                if type(data.get('Status')) is not int or data['Status'] not in (0,3):raise ValueError()
                answers=data.get('Answer',[])
                if not isinstance(answers,list):raise ValueError()
                for answer in answers[:3]:
                    if not isinstance(answer,dict) or not isinstance(answer.get('data'),str):raise ValueError()
                    records.append({'type':kind,'value':answer['data']})
            except Exception:unavailable=True
        return records,'unavailable' if unavailable else 'assessed'
    def analyze_with_tip(self,domain,user_id=None):
        from services.ioc_lookup import IoCLookup
        result=self.analyze_domain(domain)
        if result.get('error'):return result
        try:
            tip=IoCLookup().lookup_domain(domain=result['domain'],context='domain_lookup',user_id=user_id);result['tip']=tip
            if tip.get('found') and tip.get('highest_severity') in ('critical','high'):result['reputation']='malicious';result['verdict']='malicious'
        except Exception:result['tip_status']='unavailable'
        return result
