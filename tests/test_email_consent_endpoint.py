"""Execute the real endpoint body with isolated dependencies and request contexts."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from flask import Flask, request, jsonify

class ConsentEndpointTests(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__);self.checker=Mock()
        self.checker.check_all.return_value={'valid':False,'error':'Invalid email format'}
        self.factory=Mock(return_value=self.checker)
        tree=ast.parse((Path(__file__).resolve().parents[1]/'app.py').read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='api_check_email')
        function.decorator_list=[]
        scope={'app':self.app,'request':request,'jsonify':jsonify,'current_user':SimpleNamespace(username='test'),'AdvancedEmailChecker':self.factory,'redis_client':None,'log_activity':Mock()}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'app.py','exec'),scope)
        self.endpoint=scope['api_check_email']
    def test_invalid_consent_and_payload_do_not_start_analysis(self):
        for payload in ([],{'email':42},{'email':'u@example.org','verify_smtp':'true'}):
            with self.app.test_request_context(json=payload):self.assertEqual(self.endpoint()[1],400)
        self.factory.assert_not_called()
    def test_default_and_explicit_consent_are_forwarded(self):
        for consent in (False,True):
            payload={'email':'u@example.org'}
            if consent:payload['verify_smtp']=True
            with self.app.test_request_context(json=payload):self.endpoint()
            self.checker.check_all.assert_called_with('u@example.org',verify_smtp=consent)
    def test_success_response_uses_one_score_and_verdict(self):
        self.checker.check_all.return_value={
            'email':'u@example.org','domain':'example.org','verdict':'review','valid':True,
            'is_disposable':False,'is_free':False,'deliverability':'PROBE_ACCEPTED',
            'quality_score':85,'assessment':{'score':85,'verdict':'review'},
            'domain_info':{'age_days':100,'registrar':'Example'},
            'dns':{'mx':{'exists':True,'status':'found'},'spf':{'record':'v=spf1 -all','exists':True,'audit':{'configuration_valid':True}},'dmarc':{'record':'v=DMARC1; p=none','exists':True,'audit':{'configuration_valid':True}}},
            'smtp':{'valid':True,'coverage_status':'checked'},'blacklist':{'is_blacklisted':False}}
        with self.app.test_request_context(json={'email':'u@example.org'}):r=self.endpoint().get_json()
        self.assertEqual(r['quality_score']*100,r['assessment']['score'])
        self.assertEqual(r['verdict'],r['assessment']['verdict']);self.assertEqual(r['address_risk'],'review')
        self.assertIsNone(r['total_breaches']);self.assertIsNone(r['dkim_valid'])

if __name__=='__main__':unittest.main()
