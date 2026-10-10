import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
from services.file_deep_analyzer import FileDeepAnalyzer
from services.file_structure import zip_observations
from services.file_threat_intel import FileThreatIntel
from services.malwarebazaar_client import MalwareBazaarClient


def archive(items):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in items:
            z.writestr(name, data)
    return stream.getvalue()


class FileEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.analyzer = FileDeepAnalyzer(cache_dir=self.directory.name, use_exiftool=False)

    def test_plain_script_is_text_and_uppercase_extension_is_parsed(self):
        with patch.object(self.analyzer, 'check_hash_reputation', return_value={'status':'not_found','is_malicious':False}):
            result = self.analyzer.comprehensive_analysis(b'print("hello")', 'TEST.PY')
        self.assertEqual(result['filename'], 'TEST.PY')
        self.assertEqual(result['file_type']['actual_type'], 'txt')
        self.assertFalse(result['file_type']['is_spoofed'])
        self.assertTrue(result['metadata']['is_script'])

    def test_office_directory_after_large_first_member_and_macro_project(self):
        data = archive([('padding.bin', os.urandom(4096)), ('[Content_Types].xml','<Types/>'), ('word/document.xml','<document/>'), ('word/vbaProject.bin',b'compressed macro bytes')])
        self.assertEqual(self.analyzer.detect_file_type(data,'resume.docx')['actual_type'], 'docx')
        metadata = self.analyzer.extract_metadata_office(data,'resume.docx')
        self.assertTrue(metadata['has_macros'])
        self.assertFalse(self.analyzer._is_likely_benign(data,'resume.docx')[0])

    def test_arbitrary_bin_is_not_a_macro(self):
        data=archive([('[Content_Types].xml','<Types/>'), ('word/document.xml','<d/>'), ('word/printerSettings/printerSettings1.bin',b'normal')])
        self.assertFalse(self.analyzer.extract_metadata_office(data,'test.docx')['has_macros'])

    def test_external_template_relationship_and_paths_remain_inert(self):
        xml='<Relationships><Relationship TargetMode="External" Type="x/attachedTemplate" Target="http://127.0.0.1/template"/></Relationships>'
        data=archive([('[Content_Types].xml','<Types/>'), ('word/document.xml','<d/>'), ('word/_rels/document.xml.rels',xml), ('../RUN.EXE',b'MZ')])
        result=zip_observations(data,office=True)
        self.assertTrue(result['has_path_traversal'])
        self.assertTrue(result['contains_executable'])
        self.assertEqual(result['external_relationships'][0]['type'],'attachedTemplate')
        self.assertTrue(any('External Office' in s for s in result['suspicious']))

    def test_oversized_xml_is_skipped_before_decompression(self):
        data=archive([('docProps/core.xml',b'x'*(1024*1024+1))])
        with patch.object(zipfile.ZipFile,'read',side_effect=AssertionError('must not expand')):
            result=zip_observations(data,office=True)
        self.assertEqual(result['coverage_status'],'partial')
        self.assertTrue(result['missing_checks'])

    def test_malformed_or_unsupported_archive_never_looks_assessed(self):
        for data,name in [(b'PK\x03\x04broken','bad.zip'),(b'7z\xbc\xaf\x27\x1c','bad.7z')]:
            self.assertEqual(self.analyzer.extract_metadata_archive(data,name)['coverage_status'],'partial')
        self.assertIsNone(self.analyzer.extract_metadata_office(b'legacy','old.doc')['has_macros'])

    def test_local_failure_has_no_invented_score(self):
        scanner=FileThreatIntel.__new__(FileThreatIntel);scanner.mb_client=None
        result=scanner._merge_results({'error':'failed','security_score':None,'verdict':'unknown'},{'status':'not_found','is_malicious':False},'test.py',b'test')
        self.assertIsNone(result['security_score'])
        self.assertEqual(result['verdict'],'unknown')

    def test_familiar_name_or_domain_does_not_suppress_observations(self):
        self.assertFalse(self.analyzer._is_likely_benign(b'https://google.com','resume.pdf')[0])
        self.assertFalse(self.analyzer._is_false_positive('PDF_URI_Action',b'/URI',b'/URI https://google.com', 'cv.pdf'))

    def test_archive_entry_limit_does_not_report_unchecked_absence(self):
        data=archive([('file%04d.txt'%i,b'x') for i in range(1001)])
        result=zip_observations(data)
        self.assertEqual(result['coverage_status'],'partial')
        self.assertIsNone(result['has_path_traversal'])
        self.assertIsNone(result['contains_executable'])

    def test_heuristic_low_score_is_not_a_confirmed_malware_verdict(self):
        with patch.object(self.analyzer,'scan_with_yara',return_value={'risk_score':100,'matched_rules':['fixture']}), patch.object(self.analyzer,'check_hash_reputation',return_value={'status':'not_found','is_malicious':False}):
            result=self.analyzer.comprehensive_analysis(b'print("hello")','resume.py')
        self.assertEqual(result['verdict'],'high_risk')

    def test_pdf_token_checks_disclose_unparsed_streams(self):
        result=self.analyzer.extract_metadata_pdf(b'%PDF-1.4 /Launch')
        self.assertTrue(result['has_launch'])
        self.assertEqual(result['coverage_status'],'partial')
        self.assertTrue(result['missing_checks'])


class ReputationCredentialTests(unittest.TestCase):
    def test_no_key_means_not_configured_without_network(self):
        with patch.dict(os.environ,{},clear=True):
            client=MalwareBazaarClient();client.session=Mock()
            result=client.check_hash('a'*64)
        self.assertEqual(result['status'],'not_configured');client.session.post.assert_not_called()

    def test_mounted_key_is_used_only_in_header_for_hash_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'key';p.write_text('test-private-key-value\n')
            with patch.dict(os.environ,{'MALWAREBAZAAR_AUTH_KEY_FILE':str(p)},clear=True):
                client=MalwareBazaarClient();client.session=Mock()
                client.session.post.return_value=Mock(status_code=200,json=lambda:{'query_status':'hash_not_found'})
                result=client.check_hash('a'*64)
        self.assertEqual(result['status'],'not_found')
        args=client.session.post.call_args.kwargs
        self.assertEqual(args['headers']['Auth-Key'],'test-private-key-value')
        self.assertEqual(set(args['data']),{'query','hash'})
        self.assertFalse(args['allow_redirects'])
        self.assertNotIn('test-private-key-value',str(result))

    def test_auth_rate_limit_and_malformed_evidence_are_distinct(self):
        for code,reason in [(401,'authentication_rejected'),(429,'rate_limited'),(503,'provider_http_error')]:
            client=MalwareBazaarClient(auth_key='test-private-key-value');client.session=Mock()
            client.session.post.return_value=Mock(status_code=code)
            result=client.check_hash('a'*64)
            self.assertEqual(result['reason'],reason);self.assertIsNone(result['is_malicious'])
        client.session.post.return_value=Mock(status_code=200,json=lambda:['unexpected'])
        self.assertEqual(client.check_hash('a'*64)['status'],'unavailable')

if __name__=='__main__':unittest.main()
