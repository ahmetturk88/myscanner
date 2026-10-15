"""The VPS backup script: validated archive, checksum, bounded retention, encrypted off-site copy."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts'/'vps_backup.sh'
FAKE_DOCKER = '''#!/usr/bin/env bash
case "$*" in
  *pg_dump*) [ -n "$FAIL_DUMP" ] && exit 1; printf 'PGDMP-fixture' ;;
  *pg_restore*) cat > /dev/null; [ -n "$FAIL_LIST" ] && exit 1; exit 0 ;;
  *) exit 3 ;;
esac
'''
# Stand-ins: age "encrypts" by prefixing, rclone maps REMOTE:path onto a local directory.
FAKE_AGE = '''#!/usr/bin/env bash
[ "$1" = -R ] && [ -s "$2" ] && [ "$3" = -o ] || exit 9
{ printf 'AGE:'; cat "$5"; } > "$4"
'''
FAKE_RCLONE = '''#!/usr/bin/env bash
echo "$*" >> "$RCLONE_LOG"
path() { echo "$REMOTE_DIR/${1#remote:}"; }
case "$1" in
  copyto) [ -n "$FAIL_UPLOAD" ] && exit 1; mkdir -p "$(dirname "$(path "$3")")"; cp "$2" "$(path "$3")" ;;
  lsf) [ -n "$SHORT_UPLOAD" ] && { echo 1; exit 0; }; stat -c %s "$(path "${@: -1}")" ;;
  delete) exit 0 ;;
  *) exit 4 ;;
esac
'''


@unittest.skipUnless(shutil.which('bash') and shutil.which('sha256sum'), 'needs bash and coreutils')
class VPSBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp/'bin';bin_dir.mkdir()
        (bin_dir/'docker').write_text(FAKE_DOCKER);os.chmod(bin_dir/'docker', 0o755)
        self.backups = self.tmp/'backups'
        for name, body in (('age', FAKE_AGE), ('rclone', FAKE_RCLONE)):
            (bin_dir/name).write_text(body);os.chmod(bin_dir/name, 0o755)
        self.remote, self.log = self.tmp/'remote', self.tmp/'rclone.log'
        self.recipients = self.tmp/'recipients.txt';self.recipients.write_text('age1examplepublickey\n')
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'BACKUP_DIR': str(self.backups),
                    'BACKUP_CONFIG': str(self.tmp/'absent.env'), 'REMOTE_DIR': str(self.remote), 'RCLONE_LOG': str(self.log)}
        self.offsite = {'OFFSITE_REMOTE': 'remote:bucket', 'AGE_RECIPIENTS': str(self.recipients)}

    def run_script(self, **extra):
        return subprocess.run(['bash', str(SCRIPT)], env={**self.env, **extra}, capture_output=True, text=True, timeout=30)

    def test_backup_is_private_and_has_a_matching_checksum(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        dumps = list(self.backups.glob('myscanner-*.dump'))
        self.assertEqual(len(dumps), 1)
        self.assertEqual(dumps[0].read_bytes(), b'PGDMP-fixture')
        self.assertEqual(self.backups.stat().st_mode & 0o777, 0o700)
        self.assertEqual(dumps[0].stat().st_mode & 0o777, 0o600)
        check = subprocess.run(['sha256sum', '-c', dumps[0].name + '.sha256'], cwd=self.backups, capture_output=True)
        self.assertEqual(check.returncode, 0)

    def test_failed_dump_or_validation_publishes_nothing(self):
        for failure in ('FAIL_DUMP', 'FAIL_LIST'):
            result = self.run_script(**{failure: '1'})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual([p.name for p in self.backups.iterdir()], [])

    def test_retention_removes_only_old_archives(self):
        self.backups.mkdir(mode=0o700)
        old, unrelated = self.backups/'myscanner-20000101-000000.dump', self.backups/'keep-me.dump'
        for path in (old, unrelated):
            path.write_text('x');os.utime(path, (0, 0))
        self.assertEqual(self.run_script(KEEP_DAYS='14').returncode, 0)
        self.assertFalse(old.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(len(list(self.backups.glob('myscanner-*.dump'))), 1)

    def test_invalid_retention_is_rejected(self):
        self.assertEqual(self.run_script(KEEP_DAYS='0').returncode, 2)
        self.assertFalse(self.backups.exists())

    def test_offsite_copy_is_encrypted_uploaded_and_pruned(self):
        result = self.run_script(**self.offsite, OFFSITE_KEEP_DAYS='30')
        self.assertEqual(result.returncode, 0, result.stderr)
        name = next(self.backups.glob('myscanner-*.dump')).name
        uploaded = self.remote/'bucket'/(name + '.age')
        self.assertEqual(uploaded.read_bytes(), b'AGE:PGDMP-fixture')
        self.assertTrue((self.remote/'bucket'/(name + '.sha256')).exists())
        self.assertIn('delete --min-age 30d', self.log.read_text())
        self.assertEqual([p.name for p in self.backups.iterdir() if p.name.startswith('.')], [])
        self.assertIn('PASS: off-site', result.stdout)

    def test_offsite_failures_are_reported_and_leave_no_partial_files(self):
        for failure in ('FAIL_UPLOAD', 'SHORT_UPLOAD'):
            result = self.run_script(**self.offsite, **{failure: '1'})
            self.assertNotEqual(result.returncode, 0, failure)
            self.assertEqual([p.name for p in self.backups.iterdir() if p.name.startswith('.')], [])
            self.assertGreaterEqual(len(list(self.backups.glob('myscanner-*.dump'))), 1)

    def test_offsite_needs_a_recipient_key_and_valid_retention(self):
        self.recipients.write_text('')
        self.assertEqual(self.run_script(**self.offsite).returncode, 2)
        self.recipients.write_text('age1examplepublickey\n')
        self.assertEqual(self.run_script(**self.offsite, OFFSITE_KEEP_DAYS='x').returncode, 2)
        self.assertFalse(self.backups.exists())

    def test_settings_can_come_from_the_config_file(self):
        config = self.tmp/'backup.env'
        config.write_text(f"OFFSITE_REMOTE=remote:bucket\nAGE_RECIPIENTS={self.recipients}\n")
        result = self.run_script(BACKUP_CONFIG=str(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list((self.remote/'bucket').glob('*.age'))), 1)


if __name__ == '__main__':
    unittest.main()
