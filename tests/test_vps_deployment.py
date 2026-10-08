import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import json
import subprocess
import os
try:
    import yaml
except ImportError:
    yaml=None
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('vps_setup',ROOT/'scripts/init_vps_stack.py');setup=importlib.util.module_from_spec(spec);spec.loader.exec_module(setup)
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        if yaml is not None:
            self.config=yaml.safe_load((ROOT/'compose.vps.yml').read_text())
        else:
            with tempfile.TemporaryDirectory() as directory:
                setup.initialize(Path(directory))
                env=dict(os.environ,SECRET_DIRECTORY=str(Path(directory)/'.deploy/rehearsal'),VPS_IMAGE='myscanner-vps:rehearsal',SITE_DOMAIN='localhost')
                result=subprocess.run(['docker','compose','-f',str(ROOT/'compose.vps.yml'),'config','--format','json'],env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
                if result.returncode:raise RuntimeError('Compose validation failed; output withheld.')
                self.config=json.loads(result.stdout)
                for service in self.config['services'].values():
                    if isinstance(service.get('networks'),dict) and set(service['networks'])=={'data'}:service['networks']=['data']
                    service['secrets']=[v['source'] if isinstance(v,dict) else v for v in service.get('secrets',[])]
    def test_secrets_are_independent_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);setup.initialize(root)
            before={p.name:p.read_bytes() for p in (root/'.deploy/rehearsal').iterdir()}
            setup.initialize(root)
            self.assertEqual(before,{p.name:p.read_bytes() for p in (root/'.deploy/rehearsal').iterdir()})
            self.assertEqual(len({before[n] for n in ('db_admin_password','db_app_password','db_migration_password','redis_password','session_key')}),5)
            self.assertNotIn(before['db_admin_password'].decode().strip(),(root/'.env.vps.rehearsal').read_text())
    def test_bad_existing_secret_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);setup.initialize(root);p=root/'.deploy/rehearsal/db_admin_password';p.chmod(0o600);p.write_text('bad')
            with self.assertRaises(RuntimeError):setup.initialize(root)
            self.assertEqual(p.read_text(),'bad')
    def test_runtime_never_mounts_schema_or_administrator_credentials(self):
        for name in ('web','worker','beat','seed'):
            service=self.config['services'][name]
            self.assertEqual(set(service['secrets']),{'db_app_password','redis_password','session_key'})
            self.assertTrue(service['read_only']);self.assertIn('ALL',service['cap_drop'])
        self.assertEqual(self.config['services']['migrate']['secrets'],['db_migration_password'])
    def test_only_proxy_publishes_ports_and_data_is_private(self):
        self.assertTrue(self.config['networks']['data']['internal'])
        for name,service in self.config['services'].items():
            if name!='proxy':self.assertNotIn('ports',service)
        for name in ('redis','postgres','migrate','bootstrap-roles','beat'):
            self.assertEqual(self.config['services'][name]['networks'],['data'])
    def test_redis_health_strips_windows_line_endings(self):
        command=self.config['services']['redis']['healthcheck']['test'][1]
        self.assertIn("tr -d '\\r\\n'",command)
    def test_tmpfs_options_remain_one_absolute_mount(self):
        for name in ('web','worker','beat','seed','migrate','bootstrap-roles'):
            self.assertEqual(self.config['services'][name]['tmpfs'],['/tmp:uid=10001,gid=10001,mode=1770'])
    def test_ordered_migration_before_runtime(self):
        services=self.config['services']
        for child,parent in [('migrate','bootstrap-roles'),('seed','migrate'),('web','seed'),('worker','seed'),('beat','seed')]:
            self.assertEqual(services[child]['depends_on'][parent]['condition'],'service_completed_successfully')
    def test_frontend_static_addresses_cannot_collide(self):
        addresses=[self.config['services'][name]['networks']['frontend']['ipv4_address'] for name in ('proxy','web')]
        self.assertEqual(addresses,['172.31.240.2','172.31.240.3'])
    def test_proxy_replaces_untrusted_headers(self):
        caddy=(ROOT/'deploy/Caddyfile').read_text()
        self.assertIn('header_up X-Forwarded-For {remote_host}',caddy)
        self.assertIn('header_up -CF-Connecting-IP',caddy)
        self.assertEqual(self.config['services']['proxy']['networks']['frontend']['ipv4_address']+'/32',self.config['services']['web']['environment']['TRUSTED_PROXY_CIDRS'])
    def test_account_creation_requires_rehearsal_before_prompt(self):
        spec=importlib.util.spec_from_file_location('vps_account',ROOT/'scripts/vps_runtime.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
        with patch.dict('os.environ',{},clear=True),patch('getpass.getpass') as prompt:
            with self.assertRaisesRegex(RuntimeError,'Explicit rehearsal'):runtime.create_rehearsal_user()
            prompt.assert_not_called()
        with patch.dict('os.environ',{'VPS_REHEARSAL':'1'},clear=True),patch('getpass.getpass',side_effect=['short','short']):
            with self.assertRaises(ValueError):runtime.create_rehearsal_user()
    def test_queue_smoke_requires_explicit_rehearsal(self):
        spec=importlib.util.spec_from_file_location('vps_smoke',ROOT/'scripts/vps_runtime.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
        with patch.dict('os.environ',{},clear=True):
            with self.assertRaisesRegex(RuntimeError,'Explicit rehearsal'):runtime.smoke_queue()
    def test_production_guard_runs_before_secret_read(self):
        spec=importlib.util.spec_from_file_location('vps_runtime',ROOT/'scripts/vps_runtime.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
        with patch.dict('os.environ',{},clear=True),patch.object(runtime,'secret') as read:
            with self.assertRaises(RuntimeError):runtime.configure('web')
            read.assert_not_called()
if __name__=='__main__':unittest.main()
