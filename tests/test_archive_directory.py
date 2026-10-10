import io
import base64
import os
import ctypes.util
import json
import struct
import unittest
import zlib
from unittest.mock import patch
from services.archive_directory import archive_observations
from services.file_assessment import assess_file


def rar_fixture(filename='note.txt', encrypted=False):
    def header(kind,flags,body=b''):
        raw=struct.pack('<BHH',kind,flags,7+len(body))+body
        return struct.pack('<H',zlib.crc32(raw)&0xffff)+raw
    data=b'fixture';name=filename.encode()
    main=header(0x73,0,b'\0'*6)
    body=struct.pack('<IIBIIBBHI',len(data),len(data),3,zlib.crc32(data),0,20,0x30,len(name),0)+name
    return b'Rar!\x1a\x07\x00'+main+header(0x74,0x8000|(4 if encrypted else 0),body)+data+header(0x7b,0)

class ArchiveTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed; run inside scanner environment')
    def test_rar_directory_and_flags(self):
        r=archive_observations(rar_fixture('../payload.ps1'),'rar')
        self.assertEqual(r['num_files'],1,r)
        self.assertTrue(r['contains_script']);self.assertTrue(r['has_path_traversal'])
        self.assertEqual(r['coverage_status'],'partial')
        self.assertIn('member contents',r['missing_checks'][0])
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed; run inside scanner environment')
    def test_rar_encryption_is_reported_from_headers(self):
        r=archive_observations(rar_fixture('secret.txt',True),'rar')
        self.assertTrue(r['encrypted'],r)
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed; run inside scanner environment')
    def test_corrupt_archive_never_claims_empty_clean_directory(self):
        r=archive_observations(b'Rar!\x1a\x07\x00broken','rar')
        self.assertIn('error',r);self.assertIsNone(r['num_files'])
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed')
    def test_entry_limit_keeps_negative_flags_unknown(self):
        fixture=rar_fixture()
        raw=fixture[:20]+fixture[20:-7]*1001+fixture[-7:]
        r=archive_observations(raw,'rar')
        self.assertEqual(r['inspected_entries'],1000,r)
        self.assertEqual(len(r['files']),100)
        self.assertIsNone(r['num_files']);self.assertIsNone(r['contains_executable'])
        self.assertIn('Archive entry limit reached',r['missing_checks'])
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed')
    def test_long_names_are_checked_before_display_truncation(self):
        r=archive_observations(rar_fixture('a'*600+'.exe'),'rar')
        self.assertTrue(r['contains_executable'])
        self.assertEqual(len(r['files'][0]['name']),500)
    @unittest.skipUnless(os.name == 'posix', 'Bounded native parser runs on Linux')
    def test_timeout_and_input_limit_are_partial(self):
        import subprocess
        with patch('services.archive_directory.subprocess.run',side_effect=subprocess.TimeoutExpired('fixture',6)):
            self.assertIn('timed out',archive_observations(rar_fixture(),'rar')['error'])
        self.assertIn('error',archive_observations(b'x'*(10*1024*1024+1),'7z'))
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed; run inside scanner environment')
    def test_archive_contents_penalty_and_confirmed_threat(self):
        r={'security_score':100,'coverage_status':'partial','missing_checks':['directory only'],'malwarebazaar':{'status':'not_found'},'metadata':archive_observations(rar_fixture(),'rar')}
        self.assertEqual(assess_file(r)['score'],60)
        self.assertEqual(assess_file({**r,'verdict':'malicious'})['score'],0)
    @unittest.skipUnless(os.name == 'posix' and ctypes.util.find_library('archive'), 'Linux libarchive needed; run inside scanner environment')
    def test_7z_directory_and_encrypted_headers(self):
        fixtures = ['N3q8ryccAASTEruUagAAAAAAAAAUAAAAAAAAAPw47N0BAAZmaXh0dXJlAOAAXABXXQAAgTMHrg/Oha6S93rumjUv7rdNwiI3CmzB6h7KGIu42HXlcFKZX9uc4H93zq84DDfOH1YSZydRktMSEBUnfh6w7yA/SGF8G2KXRkf7uWlaJGDuLQAAAAAAFwYLAQlfAAcLAQABISEBGAxdAAA=', 'N3q8ryccAAT4jw3ukAAAAAAAAAApAAAAAAAAAKfY60HsY8JhxTOtvCqUfcxfoTFwTJTQjTrQrCPDZfbqLMK9v/bu/fnPPUJeA/yeyd1L78BvfY01BuVkxLLqoP1ta2x+V6U8w4gQQkQZlm2EKPWK/NSA+ozjN8qfIKk6nxCIWyrfaLDp216JWt/ThVfLZuRE8W2X2EaUzrSc+6Lb6R6RKZzhGz8b9EhNB/U2Qi0hdggXBhABCYCAAAcLAQABJAbxBwESUw/7iM9M+sKepG8slckljJ1xDHEAAA==']
        for encrypted, raw in zip((False, True), fixtures):
            r=archive_observations(base64.b64decode(raw),'7z')
            if encrypted:
                self.assertEqual(r['coverage_status'],'partial');self.assertTrue(r.get('error') or r.get('encrypted'))
            else:
                self.assertEqual(r['num_files'],1,r);self.assertTrue(r['contains_executable'])
