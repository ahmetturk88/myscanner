"""Execute the real endpoint body with isolated authentication/database fixtures."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from flask import Flask, request, jsonify

class IPEndpointTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse((Path(__file__).resolve().parents[1]/'app.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='api_check_ip')
        fn.decorator_list=[]
        self.app=Flask(__name__);self.analyzer=Mock();self.factory=Mock(return_value=self.analyzer)
        scope={'app':self.app,'request':request,'jsonify':jsonify,'IPAnalyzer':self.factory,'ABUSEIPDB_API_KEY':'private-key','current_user':SimpleNamespace(username='test'),'log_activity':Mock()}
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'endpoint','exec'),scope)
        self.app.add_url_rule('/api/check-ip',view_func=scope['api_check_ip'],methods=['POST'])
        self.client=self.app.test_client()
    def test_bad_json_never_constructs_analyzer(self):
        for value in [None,[],{'ip':5},{'ip':None}]:
            r=self.client.post('/api/check-ip',json=value);self.assertEqual(r.status_code,400)
        self.factory.assert_not_called()
    def test_success_is_not_cached_and_key_stays_server_side(self):
        self.analyzer.analyze_ip.return_value={'ip':'8.8.8.8','verdict':'unknown'}
        r=self.client.post('/api/check-ip',json={'ip':'8.8.8.8'});self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertNotIn('private-key',r.get_data(as_text=True));self.analyzer.analyze_ip.assert_called_once_with('8.8.8.8','private-key')
    def test_unexpected_failure_is_generic(self):
        self.analyzer.analyze_ip.side_effect=RuntimeError('private-key')
        r=self.client.post('/api/check-ip',json={'ip':'8.8.8.8'});self.assertEqual(r.status_code,503);self.assertNotIn('private-key',r.get_data(as_text=True))
if __name__=='__main__':unittest.main()
