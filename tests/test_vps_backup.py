"""The VPS backup script: validated archive, checksum, bounded retention."""
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


@unittest.skipUnless(shutil.which('bash') and shutil.which('sha256sum'), 'needs bash and coreutils')
class VPSBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp/'bin';bin_dir.mkdir()
        (bin_dir/'docker').write_text(FAKE_DOCKER);os.chmod(bin_dir/'docker', 0o755)
        self.backups = self.tmp/'backups'
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'BACKUP_DIR': str(self.backups)}

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


if __name__ == '__main__':
    unittest.main()
