"""The restore rehearsal: checksum, isolated throwaway database, table comparison, cleanup."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts'/'vps_restore_check.sh'
FAKE_DOCKER = '''#!/usr/bin/env bash
echo "$*" >> "$DOCKER_LOG"
case "$*" in
  compose*psql*) cat "$LIVE_COUNTS" ;;
  "run -d"*) exit 0 ;;
  exec*pg_isready*) [ -n "$FAIL_START" ] && exit 2; exit 0 ;;
  exec*pg_restore*) cat > /dev/null; [ -n "$FAIL_RESTORE" ] && exit 1; exit 0 ;;
  exec*psql*) cat "$RESTORED_COUNTS" ;;
  "rm -f"*) exit 0 ;;
  *) exit 3 ;;
esac
'''
FAKE_SLEEP = '#!/usr/bin/env bash\nexit 0\n'


@unittest.skipUnless(shutil.which('bash') and shutil.which('sha256sum'), 'needs bash and coreutils')
class VPSRestoreCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp/'bin';bin_dir.mkdir()
        for name, body in (('docker', FAKE_DOCKER), ('sleep', FAKE_SLEEP)):
            (bin_dir/name).write_text(body);os.chmod(bin_dir/name, 0o755)
        self.backups = self.tmp/'backups';self.backups.mkdir()
        for stamp in ('20261017-031700', '20261018-031700'):
            dump = self.backups/f'myscanner-{stamp}.dump';dump.write_bytes(b'PGDMP-' + stamp.encode())
            subprocess.run(f'sha256sum {dump.name} > {dump.name}.sha256', shell=True, cwd=self.backups, check=True)
        self.live, self.restored, self.log = self.tmp/'live', self.tmp/'restored', self.tmp/'docker.log'
        self.live.write_text('public.alembic_version\t1\npublic.scan_reports\t12\npublic.users\t5\n')
        self.restored.write_text('public.alembic_version\t1\npublic.scan_reports\t10\npublic.users\t5\n')
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'BACKUP_DIR': str(self.backups),
                    'BACKUP_CONFIG': str(self.tmp/'absent.env'), 'DOCKER_LOG': str(self.log),
                    'LIVE_COUNTS': str(self.live), 'RESTORED_COUNTS': str(self.restored)}

    def run_script(self, *args, **extra):
        return subprocess.run(['bash', str(SCRIPT), *args], env={**self.env, **extra},
                              capture_output=True, text=True, timeout=30)

    def calls(self):
        return self.log.read_text().splitlines()

    def test_newest_dump_restores_into_an_offline_throwaway_database(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS: checksum myscanner-20261018-031700.dump', result.stdout)
        self.assertIn('live has more', result.stdout)
        self.assertIn('PASS: restore rehearsal myscanner-20261018-031700.dump: 3 tables, 16 rows', result.stdout)
        run = next(c for c in self.calls() if c.startswith('run -d'))
        self.assertIn('--network none', run)
        self.assertIn('--tmpfs /var/lib/postgresql', run)
        restore = next(c for c in self.calls() if 'pg_restore' in c)
        self.assertIn('--no-owner --no-privileges', restore)
        self.assertNotIn('postgres pg_restore', restore)  # never into the live postgres service
        self.assertTrue(self.calls()[-1].startswith('rm -f myscanner-restore-check-'))

    def test_a_specific_dump_can_be_chosen(self):
        result = self.run_script(str(self.backups/'myscanner-20261017-031700.dump'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('myscanner-20261017-031700.dump', result.stdout)

    def test_checksum_mismatch_fails_before_anything_starts(self):
        (self.backups/'myscanner-20261018-031700.dump').write_bytes(b'tampered')
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('checksum does not match', result.stderr)
        self.assertFalse(any(c.startswith('run -d') for c in self.calls()))

    def test_table_missing_from_the_backup_fails(self):
        self.restored.write_text('public.alembic_version\t1\npublic.users\t5\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('MISSING FROM BACKUP', result.stdout)
        self.assertIn('1 live table(s) missing', result.stderr)

    def test_empty_restore_of_a_populated_database_fails(self):
        self.restored.write_text('public.alembic_version\t0\npublic.scan_reports\t0\npublic.users\t0\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('restored no rows', result.stderr)

    def test_restore_error_fails_and_the_container_is_still_removed(self):
        result = self.run_script(FAIL_RESTORE='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('pg_restore reported an error', result.stderr)
        self.assertTrue(self.calls()[-1].startswith('rm -f myscanner-restore-check-'))

    def test_database_that_never_starts_fails(self):
        result = self.run_script(FAIL_START='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('did not start', result.stderr)

    def test_no_dump_at_all_fails_clearly(self):
        for path in self.backups.iterdir():
            path.unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('no dump found', result.stderr)


if __name__ == '__main__':
    unittest.main()
