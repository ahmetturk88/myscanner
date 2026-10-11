"""Offline guess-model, privacy, endpoint and template checks."""
import ast
import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from flask import Flask,request,jsonify,render_template
from jinja2 import ChoiceLoader,DictLoader,FileSystemLoader
from bs4 import BeautifulSoup
from services.password_analyzer import PasswordAnalyzer
ROOT=Path(__file__).resolve().parents[1]

class EstimatorTests(unittest.TestCase):
    def setUp(self):self.a=PasswordAnalyzer();self.addCleanup(self.a.close)
    def test_common_decorated_and_repeated_passwords_stay_weak(self):
        for value in ('password','Password123!','qwertyqwertyqwertyqwerty','aaaaaaaaaaaaaaaaaaaaaaaa'):
            r=self.a.comprehensive_analysis(value)
            self.assertLess(r['final']['score'],50);self.assertTrue(r['local_strength']['findings'])
    def test_long_random_style_and_passphrase_are_not_penalized_for_missing_symbols(self):
        for value in ('7u@T3h!J4qW9z#K2n^L8','mango orbit tapestry cedar fossil'):
            self.assertGreater(self.a.comprehensive_analysis(value)['final']['score'],80)
    def test_no_secret_hash_or_matched_fragments_returned(self):
        value='Private-Unmistakable-Secret!782'
        with patch.object(self.a,'check_pwned',return_value=self.a.breach_result('not_found',0)):
            r=self.a.comprehensive_analysis(value,True)
        raw=json.dumps(r);self.assertNotIn(value,raw);self.assertNotIn(hashlib.sha1(value.encode()).hexdigest(),raw.lower())
        self.assertNotIn('sequence',r['local_strength']);self.assertNotIn('examples',r)
    def test_exposure_does_not_change_strength_and_always_requires_replacement(self):
        local=self.a.comprehensive_analysis('Complex-Sample!782')
        with patch.object(self.a,'check_pwned',return_value=self.a.breach_result('found',10)):
            exposed=self.a.comprehensive_analysis('Complex-Sample!782',True)
        self.assertEqual(exposed['final']['score'],local['final']['score']);self.assertEqual(exposed['verdict'],'exposed')
        self.assertIn('Replace',exposed['recommendations'][0])
    def test_unavailable_estimator_does_not_claim_strength(self):
        with patch('zxcvbn.zxcvbn',side_effect=RuntimeError('secret')):
            r=self.a.comprehensive_analysis('An-input-value')
        self.assertIsNone(r['final']['score']);self.assertEqual(r['status'],'partial');self.assertNotIn('secret',str(r))
    def test_strict_bounds_and_boolean(self):
        for value,flag in [('',False),('x'*129,False),(None,False),('valid',1)]:
            self.assertIn('error',self.a.comprehensive_analysis(value,flag))
    def test_spaces_and_unicode_are_not_modified(self):
        import zxcvbn
        original=zxcvbn.zxcvbn
        with patch('zxcvbn.zxcvbn',wraps=original) as estimate:
            self.a.comprehensive_analysis(' كلمة عربية طويلة ')
        estimate.assert_called_once_with(' كلمة عربية طويلة ',max_length=128)

class EndpointTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse((ROOT/'app.py').read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='api_check_password');fn.decorator_list=[]
        self.app=Flask(__name__);self.factory=Mock();self.quota=Mock(return_value=None);self.log=Mock()
        ns={'request':request,'jsonify':jsonify,'PasswordAnalyzer':self.factory,'reserve_request_quota':self.quota,'log_activity':self.log,'current_user':SimpleNamespace(username='tester'),'app':self.app}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'endpoint','exec'),ns)
        self.app.add_url_rule('/api/check-password',view_func=ns['api_check_password'],methods=['POST']);self.client=self.app.test_client()
    def test_valid_request_no_store_session_close_and_generic_activity(self):
        self.factory.return_value.comprehensive_analysis.return_value={'local_strength':{},'password':'secret'}
        r=self.client.post('/api/check-password',json={'password':'private!'})
        self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertNotIn('secret',r.get_data(as_text=True))
        self.factory.return_value.close.assert_called_once();self.assertNotIn('private!',str(self.log.call_args))
    def test_bad_payload_does_not_consume_quota_or_start(self):
        for value in ({},[],{'password':'x'*129},{'password':'x','check_breaches':'yes'}):
            self.assertEqual(self.client.post('/api/check-password',json=value).status_code,400)
        self.quota.assert_not_called();self.factory.assert_not_called()
    def test_exception_does_not_echo_secret_and_closes(self):
        self.factory.return_value.comprehensive_analysis.side_effect=RuntimeError('private!')
        r=self.client.post('/api/check-password',json={'password':'private!'})
        self.assertEqual(r.status_code,503);self.assertNotIn('private!',r.get_data(as_text=True));self.factory.return_value.close.assert_called_once()

class TemplateTests(unittest.TestCase):
    def test_private_input_assets_and_opt_in(self):
        app=Flask(__name__);app.jinja_loader=ChoiceLoader([DictLoader({'base.html':'{% block head_extra %}{% endblock %}{% block content %}{% endblock %}'}),FileSystemLoader(str(ROOT/'templates'))])
        with app.test_request_context('/'):soup=BeautifulSoup(render_template('password_check.html'),'html.parser')
        self.assertEqual(soup.select_one('#password-input')['type'],'password');self.assertFalse(soup.select_one('#password-breach').has_attr('checked'))
        self.assertTrue(soup.find('script',src='/static/password_workspace.js'));self.assertFalse(soup.select('[onclick]'))
