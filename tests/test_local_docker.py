"""Local secrets/DB isolation plus actual Compose normalization when its CLI exists."""
import contextlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.init_local_stack import initialize
from scripts.local_runtime import require_local_stack, main

ROOT = Path(__file__).resolve().parents[1]
VALID = {'LOCAL_STACK':'1','APP_ENV':'development',
         'DATABASE_URL':'postgresql+psycopg2://myscanner_app:private@postgres:5432/myscanner_local'}

class LocalSetupTests(unittest.TestCase):
    def test_credentials_are_random_and_existing_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(initialize(directory));path=Path(directory,'.env.docker.local')
            first=path.read_text(encoding='utf-8')
            self.assertFalse(initialize(directory));self.assertEqual(first,path.read_text(encoding='utf-8'))
            lines=dict(line.split('=',1) for line in first.splitlines() if '=' in line)
            self.assertEqual(len(lines['LOCAL_SECRET_KEY']),96);self.assertEqual(len(lines['LOCAL_DB_PASSWORD']),64)
            self.assertTrue(all(c in '0123456789abcdef' for value in lines.values() for c in value))
    def test_setups_do_not_share_credentials(self):
        with tempfile.TemporaryDirectory() as first,tempfile.TemporaryDirectory() as second:
            initialize(first);initialize(second)
            self.assertNotEqual(Path(first,'.env.docker.local').read_bytes(),Path(second,'.env.docker.local').read_bytes())
    def test_existing_host_environment_file_is_not_read_or_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            existing=Path(directory,'.env');existing.write_text('DATABASE_URL=remote-private-database\nSECRET_KEY=remote-private-key\n')
            initialize(directory);self.assertEqual(existing.read_text(),'DATABASE_URL=remote-private-database\nSECRET_KEY=remote-private-key\n')
            self.assertNotIn('remote-private',Path(directory,'.env.docker.local').read_text())
    def test_local_database_is_the_only_allowed_target(self):
        require_local_stack(VALID)
        cases=[{}, {'LOCAL_STACK':'0'}, {'APP_ENV':'production'}, {'APP_ENV':'testing'},
               {'DATABASE_URL':'sqlite:///site.db'},
               {'DATABASE_URL':'postgresql+psycopg2://myscanner_local:secret@render.example/myscanner_local'},
               {'DATABASE_URL':'postgresql+psycopg2://myscanner_local:secret@postgres/production'},
               {'DATABASE_URL':'postgresql+psycopg2://production:secret@postgres/myscanner_local'}]
        for change in cases:
            env={} if not change else dict(VALID,**change)
            with self.subTest(fields=list(change)),self.assertRaises(RuntimeError) as error:require_local_stack(env)
            self.assertNotIn('secret',str(error.exception));self.assertNotIn('render.example',str(error.exception))
    def test_runtime_refuses_before_importing_application(self):
        with patch.dict(os.environ,{},clear=True),patch('scripts.local_runtime.dependencies_ready') as ready,self.assertRaises(RuntimeError):
            from scripts.local_runtime import run
            run('init-db')
        ready.assert_not_called()
    def test_runtime_error_does_not_print_credentials(self):
        output=StringIO()
        with patch('sys.argv',['local_runtime.py','init-db']),patch('scripts.local_runtime.run',side_effect=RuntimeError('credential=private-secret')),contextlib.redirect_stderr(output):
            self.assertEqual(main(),1)
        self.assertNotIn('private-secret',output.getvalue())
    def test_password_prompt_rejects_mismatch_before_application_import(self):
        from scripts.local_runtime import create_local_user
        with patch('getpass.getpass',side_effect=['long-local-password','different-password']),self.assertRaises(ValueError):create_local_user()
    def test_generated_credentials_are_excluded_from_git_and_docker_context(self):
        self.assertIn('/.env.docker.local',(ROOT/'.gitignore').read_text(encoding='utf-8'))
        source=(ROOT/'.dockerignore').read_text(encoding='utf-8')
        self.assertIn('\n**\n',source);self.assertIn('**/.env*',source)
        for line in ['!.env','!logs/','!cache/','!instance/','!.git/']:self.assertNotIn(line,source)
    def test_image_is_non_root_and_copies_source_without_host_credentials(self):
        source=(ROOT/'Dockerfile.local').read_text(encoding='utf-8')
        self.assertIn('USER 10001:10001',source);self.assertNotIn('COPY . .',source)
        self.assertNotIn('ARG SECRET',source);self.assertNotIn('COPY .env',source)
        self.assertIn("decode('utf-16')",source)

@unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI is needed for normalized configuration checks')
class ComposeConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();initialize(cls.tmp.name)
        cls.addClassCleanup(cls.tmp.cleanup)
        env=dict(os.environ)
        for key in ['LOCAL_SECRET_KEY','LOCAL_DB_PASSWORD','LOCAL_APP_DB_PASSWORD','LOCAL_MIGRATION_DB_PASSWORD']:env.pop(key,None)
        result=subprocess.run([shutil.which('docker'),'compose','--env-file',str(Path(cls.tmp.name,'.env.docker.local')),
            '-f',str(ROOT/'compose.local.yml'),'config','--format','json'],capture_output=True,text=True,encoding='utf-8',env=env,timeout=20)
        if result.returncode:raise AssertionError('Docker Compose could not normalize the local configuration; no secrets printed.')
        cls.config=json.loads(result.stdout)
    def test_only_loopback_web_port_is_published(self):
        services=self.config['services']
        for name in ['postgres','redis','worker','beat','init-db','bootstrap-roles']:self.assertFalse(services[name].get('ports'))
        port=services['web']['ports'][0]
        self.assertEqual(port['host_ip'],'127.0.0.1');self.assertEqual(str(port['published']),'8000');self.assertEqual(port['target'],8000)
    def test_all_application_processes_share_isolated_database_and_queue(self):
        values=[]
        for name in ['web','worker','beat','init-db']:
            env=self.config['services'][name]['environment'];require_local_stack(env)
            self.assertEqual(env['CELERY_BROKER_URL'],'redis://redis:6379/0');self.assertEqual(env['CELERY_RESULT_BACKEND'],'redis://redis:6379/1')
            values.append((env['DATABASE_URL'],env['SECRET_KEY']))
        self.assertEqual(len(set(values)),1)
    def test_migration_credentials_are_absent_from_runtime_processes(self):
        services=self.config['services']
        for name in ['web','worker','beat']:
            env=services[name]['environment']
            self.assertNotIn('MIGRATION_DATABASE_URL',env)
            self.assertNotIn('LOCAL_DB_PASSWORD',env)
            self.assertNotIn('LOCAL_MIGRATION_DB_PASSWORD',env)
        env=services['init-db']['environment']
        self.assertIn('myscanner_migrator:',env['MIGRATION_DATABASE_URL'])
        self.assertEqual(env['MIGRATION_ROLE'],'myscanner_schema_owner')
        self.assertEqual(set(services['bootstrap-roles']['networks']),{'data'})
        self.assertEqual(services['init-db']['depends_on']['bootstrap-roles']['condition'],'service_completed_successfully')
    def test_existing_urlvet_service_uses_host_gateway_without_new_8080_binding(self):
        for name in ['web','worker','beat']:
            service=self.config['services'][name];self.assertEqual(service['environment']['URLVET_URL'],'http://host.docker.internal:8080')
            self.assertIn('host.docker.internal',str(service['extra_hosts']))
    def test_persistence_and_queue_eviction_policy_are_explicit(self):
        services=self.config['services'];command=services['redis']['command']
        self.assertIn('--appendonly',command);self.assertIn('noeviction',command)
        self.assertIn('/var/lib/postgresql',[v['target'] for v in services['postgres']['volumes']])
        self.assertIn('/data',[v['target'] for v in services['redis']['volumes']])
        self.assertIn('/state',[v['target'] for v in services['beat']['volumes']])
    def test_schema_init_precedes_web_and_workers(self):
        services=self.config['services']
        for name in ['postgres','redis']:self.assertEqual(services['init-db']['depends_on'][name]['condition'],'service_healthy')
        for name in ['web','worker','beat']:self.assertEqual(services[name]['depends_on']['init-db']['condition'],'service_completed_successfully')
    def test_application_security_and_resource_limits(self):
        for name in ['web','worker','beat','init-db']:
            service=self.config['services'][name];self.assertTrue(service['read_only']);self.assertIn('ALL',service['cap_drop'])
            self.assertTrue(service['init'])
            # Compose versions expose byte counts as either numbers or strings.
            self.assertIn(str(service['mem_limit']).lower(), {'1073741824', '1g', '1024m'})
            self.assertGreater(int(service['pids_limit']),0)
    def test_database_network_is_internal_and_worker_queues_are_explicit(self):
        self.assertTrue(self.config['networks']['data']['internal'])
        for name in ['postgres','redis']:self.assertEqual(set(self.config['services'][name]['networks']),{'data'})
        command=self.config['services']['worker']['command']
        self.assertIn('celery_worker:celery',command);self.assertIn('scans,tip,celery',command);self.assertIn('--pool=prefork',command)
    def test_upload_volume_is_shared_between_web_and_worker(self):
        services=self.config['services']
        sources=[]
        for name in ['web','worker']:
            sources.append(next(v['source'] for v in services[name]['volumes'] if v['target']=='/app/temp_uploads'))
        self.assertEqual(sources[0],sources[1])

if __name__=='__main__':unittest.main()
