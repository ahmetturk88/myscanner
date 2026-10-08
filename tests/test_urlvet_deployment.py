from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ProviderDeploymentTests(unittest.TestCase):
    def test_image_copies_only_binary_assets_and_entrypoint(self):
        source=(ROOT/'deploy/urlvet.Dockerfile').read_text()
        copies=[line for line in source.splitlines() if line.startswith('COPY ')]
        self.assertEqual(len(copies),3)
        self.assertTrue(all('.env' not in line and 'COPY . .' not in line for line in copies))
        self.assertIn('657a8dafeb9c9109a339087ea07cf922aaddc52a',source)
        self.assertIn('USER 10001:10001',source)
    def test_secrets_are_read_from_files_without_echo(self):
        entry=(ROOT/'deploy/urlvet-entrypoint.sh').read_text()
        self.assertIn('/run/secrets/urlvet_cache_password',entry)
        self.assertIn('/run/secrets/urlvet_jwt_secret',entry)
        self.assertNotIn('echo',entry);self.assertNotIn('set -x',entry)
    def test_provider_has_no_host_ports_or_database_network(self):
        source=(ROOT/'compose.urlvet.yml').read_text()
        self.assertNotRegex(source,r'(?m)^\s+ports:')
        self.assertNotIn('host.docker.internal',source)
        self.assertNotIn('DATABASE_URL',source)
        self.assertNotIn('db_app_password',source)
        self.assertEqual(source.count('URLVET_URL: http://urlvet:8080'),2)
    def test_cache_and_browser_images_are_digest_locked(self):
        source=(ROOT/'compose.urlvet.yml').read_text()
        self.assertIn('valkey/valkey@sha256:4436c94fc34ce4af0354b9379d433a1f258998fb955f995c89822f98c14a8cab',source)
        self.assertIn('chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04',source)
        self.assertNotIn(':latest',source)
    def test_build_context_excludes_host_files(self):
        source=(ROOT/'deploy/.dockerignore').read_text().splitlines()
        self.assertEqual(source,['**','!urlvet.Dockerfile','!urlvet-entrypoint.sh'])
if __name__=='__main__':unittest.main()
