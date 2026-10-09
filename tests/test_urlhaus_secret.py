from pathlib import Path
import tempfile
import unittest
from scripts.configure_urlhaus import save_key
ROOT=Path(__file__).resolve().parents[1]

class SecretTests(unittest.TestCase):
    def fixture(self,root):
        directory=Path(root)/'.deploy'/'rehearsal';directory.mkdir(parents=True)
        (Path(root)/'.env.vps.rehearsal').write_text('test')
        (directory/'urlhaus_auth_key').write_text('')
        return directory/'urlhaus_auth_key'
    def test_hidden_key_storage_and_existing_key_preservation(self):
        with tempfile.TemporaryDirectory() as root:
            path=self.fixture(root);save_key('example-private-key',root)
            self.assertEqual(path.read_text().strip(),'example-private-key')
            with self.assertRaises(RuntimeError):save_key('other-private-key',root)
            self.assertEqual(path.read_text().strip(),'example-private-key')
    def test_invalid_key_does_not_change_file(self):
        with tempfile.TemporaryDirectory() as root:
            path=self.fixture(root)
            for key in ('short','key-containing\nnewline','key-containing\x00control'):
                with self.assertRaises(RuntimeError):save_key(key,root)
                self.assertEqual(path.read_text(),'')
    def test_uninitialized_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(RuntimeError):save_key('example-private-key',root)
            self.assertFalse((Path(root)/'.deploy').exists())
    def test_compose_mounts_provider_key_only_in_application_services(self):
        source=(ROOT/'compose.urlvet.yml').read_text()
        self.assertEqual(source.count('URLHAUS_AUTH_KEY_FILE: /run/secrets/urlhaus_auth_key'),2)
        self.assertEqual(source.count('secrets: [urlhaus_auth_key]'),2)
        self.assertIn('/.deploy/',(ROOT/'.gitignore').read_text())
        self.assertNotIn('example-private-key',source)
if __name__=='__main__':unittest.main()
