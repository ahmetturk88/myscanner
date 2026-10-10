import os
import io
import zipfile
import subprocess
import unittest
from unittest.mock import patch
from services.file_deep_analyzer import FileDeepAnalyzer
from test_archive_directory import rar_fixture

class IntegrationTests(unittest.TestCase):
    def test_detected_rar_routes_to_bounded_parser(self):
        a=FileDeepAnalyzer()
        with patch('services.file_deep_analyzer.archive_observations',return_value={'type':'rar','is_archive':True,'coverage_status':'partial','missing_checks':['Contents not inspected'],'suspicious':[]}) as reader:
            with patch.object(a,'check_hash_reputation',return_value={'status':'not_found','risk_score':0,'is_malicious':False}):
                r=a.comprehensive_analysis(rar_fixture(),'password.rar')
        reader.assert_called_once_with(rar_fixture(),'rar')
        self.assertIn('Contents not inspected',r['missing_checks'])
        self.assertEqual(r['verdict'],'unknown')
    def test_exiftool_timeout_removes_input(self):
        seen=[]
        def timeout(args,**kwargs):
            seen.append(args[-1]);self.assertTrue(os.path.exists(args[-1]))
            raise subprocess.TimeoutExpired(args,10)
        with patch('services.file_deep_analyzer.subprocess.run',side_effect=timeout):
            r=FileDeepAnalyzer(use_exiftool=True).extract_metadata_via_exiftool(b'fixture','test.rar')
        self.assertFalse(r['available']);self.assertIn('error',r)
        self.assertFalse(os.path.exists(seen[0]))
    def test_exiftool_nonzero_is_not_success(self):
        with patch('services.file_deep_analyzer.subprocess.run',return_value=subprocess.CompletedProcess([],1,stdout='',stderr='private fixture')):
            r=FileDeepAnalyzer(use_exiftool=True).extract_metadata_via_exiftool(b'fixture','test.rar')
        self.assertFalse(r['available']);self.assertIn('error',r)
        self.assertNotIn('private',r['error'])

    def test_zip_payload_is_partial_and_filenames_are_not_domain_iocs(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            archive.writestr('main.pyUT', 'print("fixture")')
        a=FileDeepAnalyzer()
        with patch.object(a,'check_hash_reputation',return_value={'status':'not_found','risk_score':0,'is_malicious':False}):
            r=a.comprehensive_analysis(output.getvalue(),'fixture.zip')
        self.assertEqual(r['coverage_status'],'partial')
        self.assertTrue(all(not values for values in r['iocs'].values()))
        self.assertIn('Archive member contents and nested archives were not inspected',r['missing_checks'])
        from services.file_assessment import assess_file
        r['malwarebazaar']={'status':'not_found'}
        self.assertEqual(assess_file(r)['score'],60)
