import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import local_backup as backup

class BackupTests(unittest.TestCase):
    def test_only_known_legacy_allowance_column_is_retained(self):
        from types import SimpleNamespace
        legacy=('remove_column',None,'user',SimpleNamespace(name='sandbox_remaining'))
        other=('remove_column',None,'user',SimpleNamespace(name='unexpected'))
        missing=('add_column',None,'user',SimpleNamespace(name='email'))
        nullable=('modify_nullable',None,'user','email',{},True,False)
        self.assertEqual(backup.unexpected_schema_differences([legacy]),[])
        self.assertEqual(backup.unexpected_schema_differences([legacy,other,missing,[nullable]]),[other,missing,nullable])
    def test_legacy_name_in_another_table_is_not_accepted(self):
        from types import SimpleNamespace
        change=('remove_column',None,'scan',SimpleNamespace(name='sandbox_remaining'))
        self.assertEqual(backup.unexpected_schema_differences([change]),[change])
    def archive(self,directory):
        path=Path(directory,'test.dump');path.write_bytes(b'PGDMP-test')
        path.with_suffix('.dump.json').write_text(json.dumps({'format':'postgresql-custom-local-v1','filename':path.name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
        return path
    def test_corruption_fails_before_docker_or_database_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.archive(directory);path.write_bytes(b'changed')
            with patch.object(backup,'invoke') as invoke,self.assertRaises(RuntimeError):backup.restore_check(path)
            invoke.assert_not_called()
    def test_manifest_identity_must_match_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.archive(directory)
            self.assertEqual(backup.verify_archive(path),path.resolve())
            path.rename(Path(directory,'other.dump'))
            with self.assertRaises(FileNotFoundError):backup.verify_archive(Path(directory,'other.dump'))
    def test_restore_uses_new_database_and_cleans_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.archive(directory)
            with patch.object(backup,'sql') as sql,patch.object(backup,'invoke',side_effect=[None,RuntimeError('restore failure'),None]),self.assertRaises(RuntimeError):backup.restore_check(path)
            create,drop=[call.args[0] for call in sql.call_args_list]
            self.assertRegex(create,r'^CREATE DATABASE myscanner_rehearsal_[0-9a-f]{24} TEMPLATE template0$')
            self.assertEqual(drop,'DROP DATABASE '+create.split()[2]+' WITH (FORCE)')
    def test_successful_rehearsal_uses_transactional_restore_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.archive(directory)
            def invoke(args,*unused):
                if args[0]=='run':return 'PASS: archive restored and migrated; all restored table data unchanged.\nUsers: 1 Scans: 6\n'
                return ''
            with patch.object(backup,'sql') as sql,patch.object(backup,'invoke',side_effect=invoke) as calls:
                backup.restore_check(path)
            restore=next(call.args[0] for call in calls.call_args_list if 'pg_restore' in call.args[0])
            for flag in ['--single-transaction','--exit-on-error','--no-owner','--no-privileges']:self.assertIn(flag,restore)
            self.assertTrue(sql.call_args_list[-1].args[0].startswith('DROP DATABASE myscanner_rehearsal_'))
    def test_failed_creation_never_drops_any_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.archive(directory)
            with patch.object(backup,'sql',side_effect=RuntimeError('create failure')) as sql,patch.object(backup,'invoke'),self.assertRaises(RuntimeError):backup.restore_check(path)
            self.assertEqual(sql.call_count,1)
    def test_backup_generates_verified_archive_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            def invoke(args,*unused):
                if args[0]=='cp':Path(args[2]).write_bytes(b'PGDMP-test')
            with patch.object(backup,'backup_directory',return_value=Path(directory)),patch.object(backup,'invoke',side_effect=invoke):path=backup.create_backup()
            self.assertEqual(backup.verify_archive(path),path.resolve())
            self.assertFalse(list(Path(directory).glob('*.partial')))
    def test_subprocess_failure_does_not_expose_output(self):
        from unittest.mock import Mock
        with patch('subprocess.run',return_value=Mock(returncode=1,stdout='private rows',stderr='password=secret')),self.assertRaises(RuntimeError) as error:backup.invoke(['exec'])
        self.assertNotIn('secret',str(error.exception));self.assertNotIn('private',str(error.exception))

if __name__=='__main__':unittest.main()
