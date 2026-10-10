import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from services.provider_credentials import abuseipdb_key
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('configure_abuseipdb',ROOT/'scripts/configure_abuseipdb.py');config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)
class AbuseIPDBConfigurationTests(unittest.TestCase):
    def prepare(self,root):
        (root/'.env.vps.rehearsal').write_text('test');(root/'.deploy/rehearsal').mkdir(parents=True)
    def test_save_and_preserve_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.prepare(root);key='private-test-key-'+'a'*40;config.save_key(key,root);path=root/'.deploy/rehearsal/abuseipdb_api_key';self.assertEqual(path.read_text().strip(),key)
            with self.assertRaises(RuntimeError):config.save_key('b'*64,root)
            self.assertEqual(path.read_text().strip(),key)
    def test_invalid_key_never_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.prepare(root)
            for key in ('short','a'*20+'\n'+'b'*20,'a'*5000):
                with self.assertRaises(RuntimeError):config.save_key(key,root)
            self.assertFalse((root/'.deploy/rehearsal/abuseipdb_api_key').exists())
    def test_file_wins_over_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'secret';path.write_text('file-key-'+'a'*40)
            with patch.dict(os.environ,{'ABUSEIPDB_API_KEY_FILE':str(path),'ABUSEIPDB_API_KEY':'env-key-'+'b'*40},clear=True):self.assertEqual(abuseipdb_key(),path.read_text())
    def test_bad_or_empty_file_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'secret'
            for value in ('','bad','a'*5000):
                path.write_text(value)
                with patch.dict(os.environ,{'ABUSEIPDB_API_KEY_FILE':str(path),'ABUSEIPDB_API_KEY':'b'*64},clear=True):self.assertIsNone(abuseipdb_key())
    def test_legacy_environment_supported(self):
        with patch.dict(os.environ,{'ABUSEIPDB_API_KEY':'a'*64},clear=True):self.assertEqual(abuseipdb_key(),'a'*64)
    def test_only_web_mounts_provider_key(self):
        import yaml
        compose=yaml.safe_load((ROOT/'compose.vps.yml').read_text());self.assertIn('abuseipdb_api_key',compose['services']['web']['secrets'])
        for name in ('worker','tip-worker','beat','bootstrap-roles','migrate'):self.assertNotIn('abuseipdb_api_key',compose['services'][name]['secrets'])
if __name__=='__main__':unittest.main()
