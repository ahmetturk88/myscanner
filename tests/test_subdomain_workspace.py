import unittest
from unittest.mock import patch
from services.subdomain_finder import SubdomainFinder, discovery_coverage


def records(host,types,deadline):
    return {k:{'status':'completed' if k=='A' else 'no_record','values':['8.8.8.8'] if k=='A' else []} for k in types}


class WorkspaceTests(unittest.TestCase):
    def test_ct_and_common_candidates_share_budget_and_provenance(self):
        f=SubdomainFinder();f.COMMON_SUBDOMAINS=['www','api','www']
        with patch.object(f,'certificate_names',return_value=({'api.example.com','a.example.com','b.example.com','c.example.com'},{'status':'completed'})),patch('services.subdomain_finder.dns_records',side_effect=records),patch.object(f,'probe_web',side_effect=lambda r,d:r):
            r=f.find_subdomains('example.com',max_subdomains=4)
        hosts={row['full_domain']:row for row in r['results']}
        self.assertIn('www.example.com',hosts);self.assertIn('api.example.com',hosts)
        self.assertEqual(set(hosts['api.example.com']['sources']),{'common_name','certificate_transparency'})
        self.assertEqual(r['candidates_selected'],4)

    def test_partial_record_not_hidden_by_successful_a_record(self):
        def partial(host,types,deadline):
            r=records(host,types,deadline);r['AAAA']={'status':'unavailable','values':[]};return r
        f=SubdomainFinder();f.COMMON_SUBDOMAINS=['www']
        with patch('services.subdomain_finder.dns_records',side_effect=partial),patch.object(f,'probe_web',side_effect=lambda r,d:r):
            r=f.find_subdomains('example.com',include_ct=False)
        self.assertEqual(r['total_found'],1)
        self.assertEqual(r['dns_error_count'],1)
        self.assertEqual(r['verification_coverage']['parts'][0]['completed'],0)
        self.assertIsNone(r['wildcard']['detected'])

    def test_cname_wildcard_is_flagged(self):
        def cname(host,types,deadline):return {k:{'status':'completed' if k=='CNAME' else 'no_record','values':['edge.example.net.'] if k=='CNAME' else []} for k in types}
        f=SubdomainFinder()
        with patch('services.subdomain_finder.dns_records',side_effect=cname):
            w=f.wildcard_probe('example.com',float('inf'))
            r=f.resolve_candidate(('www.example.com',['common_name']),'example.com',float('inf'),w)
        self.assertTrue(w['detected']);self.assertTrue(r['possible_wildcard'])
        self.assertFalse(r['public_addresses'])

    def test_coverage_is_verification_not_safety(self):
        row={'dns_complete':True,'http':{'status':'completed'},'tls':{'status':'invalid'}}
        r=discovery_coverage([row],[row],[{'status':'unavailable'}],{'status':'completed'})
        self.assertEqual(r['score'],100)
        self.assertEqual(r['source_gaps'],1)
        self.assertIn('not a safety',r['warning'])
        self.assertEqual(discovery_coverage([{'dns_complete':True}],[],[],{})['score'],100)
        self.assertIsNone(discovery_coverage([],[],[],{})['score'])

    def test_private_and_mixed_addresses_never_probe(self):
        f=SubdomainFinder()
        for addresses in (['127.0.0.1'],['169.254.169.254'],['8.8.8.8','10.0.0.1'],['::1']):
            def dns(host,types,deadline):return {k:{'status':'completed','values':addresses if k=='A' else []} for k in types}
            with patch('services.subdomain_finder.dns_records',side_effect=dns),patch('services.subdomain_finder.PublicHTTPSession') as session:
                row=f.resolve_candidate(('www.example.com',['common_name']),'example.com',float('inf'),{'detected':False,'addresses':[]})
                f.probe_web(row,float('inf'));session.assert_not_called()
            self.assertEqual(row['http']['status'],'blocked')

    def test_deadline_prevents_probe_and_options_are_typed(self):
        f=SubdomainFinder()
        with patch('services.subdomain_finder.PublicHTTPSession') as session:
            row=f.probe_web({'public_addresses':True,'full_domain':'www.example.com','http':{}},0)
            session.assert_not_called();self.assertEqual(row['http']['status'],'unavailable')
        with self.assertRaises(ValueError):f.find_subdomains('example.com',include_ct='yes')

    def test_truncated_ct_source_is_partial(self):
        from test_web_assessment import page
        import json
        r=page();r._content=json.dumps([{'name_value':'api.example.com'}]*2001).encode()
        with patch('services.subdomain_finder.PublicHTTPSession.get',return_value=r):
            names,source=SubdomainFinder().certificate_names('example.com',float('inf'))
        self.assertEqual(names,{'api.example.com'});self.assertEqual(source['status'],'partial')


if __name__=='__main__':unittest.main()
