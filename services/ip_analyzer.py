"""IP metadata and reputation: unavailable evidence is never a clean match."""
import ipaddress
from services.safe_http import PublicHTTPSession, _public_address

class IPAnalyzer:
    def __init__(self):
        self.session = PublicHTTPSession(response_limit=1024*1024)
        self.timeout = 10

    def analyze_ip(self, ip, abuseipdb_api_key=None):
        try:
            ip = str(ipaddress.ip_address(ip))
            if not _public_address(ip): raise ValueError()
        except (ValueError, TypeError):
            return {'error':'A public IP address is required', 'verdict':'unknown'}
        result = {'ip':ip,'verdict':'unknown','is_proxy':None,'is_hosting':None,
                  'is_mobile':None,'blacklist_count':None,'blacklist_results':[],
                  'coverage':{},'scope':'IP metadata and AbuseIPDB reports; not a guarantee of safety.'}
        try:
            result.update(self._get_ip_info(ip))
            reputation = self._check_abuseipdb(ip, abuseipdb_api_key) if abuseipdb_api_key else {'status':'not_configured'}
            result['coverage']['reputation'] = reputation['status']
            result['reputation_status'] = reputation['status']
            if reputation['status'] in ('matched','not_found'):
                result['blacklist_count'] = int(reputation['status']=='matched')
                result['blacklist_results'] = [{'name':'AbuseIPDB','listed':reputation['status']=='matched',
                                               'detail':f"Reported score: {reputation['score']} / 100"}]
                result['abuse_score'] = reputation['score']
                # Geography, proxy and hosting flags alone do not prove maliciousness.
                result['verdict'] = ('blacklisted' if reputation['score']>=50 else 'suspicious') if reputation['score']>0 else 'not_found'
            result['coverage_status'] = 'completed' if all(s in ('assessed','matched','not_found') for s in result['coverage'].values()) else 'partial'
            return result
        finally:
            self.session.close()

    def _get_ip_info(self, ip):
        try:
            response=self.session.get('http://ip-api.com/json/'+ip,timeout=self.timeout,allow_redirects=False)
            response.raise_for_status();data=response.json()
            if not isinstance(data,dict) or data.get('status')!='success' or data.get('query')!=ip:raise ValueError()
            result={'coverage':{'metadata':'assessed'}}
            for key,source in {'country':'country','country_code':'countryCode','city':'city','region':'regionName','timezone':'timezone','isp':'isp','org':'org','lat':'lat','lon':'lon'}.items():result[key]=data.get(source)
            for key,source in {'is_proxy':'proxy','is_hosting':'hosting','is_mobile':'mobile'}.items():result[key]=data.get(source) if type(data.get(source)) is bool else None
            return result
        except Exception:
            return {'coverage':{'metadata':'unavailable'}}

    def _check_abuseipdb(self, ip, key):
        try:
            response=self.session.get('https://api.abuseipdb.com/api/v2/check',params={'ipAddress':ip,'maxAgeInDays':90},headers={'Key':key,'Accept':'application/json'},timeout=self.timeout,allow_redirects=False)
            response.raise_for_status();data=response.json()['data']
            score=data['abuseConfidenceScore'];reports=data['totalReports']
            if data.get('ipAddress')!=ip or type(score) is not int or not 0<=score<=100 or type(reports) is not int or reports<0:raise ValueError()
            return {'status':'matched' if score>0 else 'not_found','score':score,'reports':reports}
        except Exception:return {'status':'unavailable'}

    def analyze_with_tip(self, ip, user_id=None):
        from services.ioc_lookup import IoCLookup
        result=self.analyze_ip(ip)
        if result.get('error'):return result
        try:
            tip=IoCLookup().lookup_ip(ip=ip,context='ip_check',user_id=user_id)
            result['tip']=tip
            if tip.get('found') and tip.get('highest_severity') in ('critical','high'):result['verdict']='malicious'
        except Exception:result['tip_status']='unavailable'
        return result
