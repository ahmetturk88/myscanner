"""Boot autostart: a systemd unit that brings the whole compose stack back after a host restart."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts'/'vps_autostart.sh'
FAKE_DOCKER = '''#!/usr/bin/env bash
echo "$*" >> "$DOCKER_LOG"
case "$1" in
  info) [ -n "$DOCKER_DOWN" ] && exit 1; exit 0 ;;
  compose) n=$(grep -c ' up -d' "$DOCKER_LOG"); [ "$n" -le "${FAIL_UPS:-0}" ] && exit 1; exit 0 ;;
esac
exit 3
'''
FAKE_SYSTEMCTL = '#!/usr/bin/env bash\necho "$*" >> "$SYSTEMCTL_LOG"\n'
FAKE_SLEEP = '#!/usr/bin/env bash\nexit 0\n'


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class VPSAutostartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp/'bin';bin_dir.mkdir()
        for name, body in (('docker', FAKE_DOCKER), ('systemctl', FAKE_SYSTEMCTL), ('sleep', FAKE_SLEEP)):
            (bin_dir/name).write_text(body);os.chmod(bin_dir/name, 0o755)
        self.units = self.tmp/'units';self.units.mkdir()
        self.docker_log, self.systemctl_log = self.tmp/'docker.log', self.tmp/'systemctl.log'
        self.docker_log.write_text('')
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'UNIT_DIR': str(self.units),
                    'DOCKER_LOG': str(self.docker_log), 'SYSTEMCTL_LOG': str(self.systemctl_log)}

    def run_script(self, *args, **extra):
        return subprocess.run(['bash', str(SCRIPT), *args], env={**self.env, **extra},
                              capture_output=True, text=True, timeout=30)

    def up_calls(self):
        return [line for line in self.docker_log.read_text().splitlines() if ' up -d' in line]

    def test_start_recreates_the_stack_from_the_production_files_without_building(self):
        result = self.run_script('start')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.up_calls()[0]
        files = [part.rsplit('/', 1)[-1] for part in call.split() if part.endswith('.yml')]
        self.assertEqual(files, ['compose.vps.yml', 'compose.urlvet.yml', 'compose.egress.yml',
                                 'compose.app-egress.yml', 'compose.launch.yml'])
        self.assertIn('.env.vps.rehearsal', call)
        self.assertTrue(call.endswith('up -d --no-build --force-recreate'))

    def test_start_retries_a_slow_first_start(self):
        result = self.run_script('start', FAIL_UPS='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.up_calls()), 3)
        self.assertIn('attempt 3', result.stdout)

    def test_start_gives_up_after_three_attempts(self):
        result = self.run_script('start', FAIL_UPS='9')
        self.assertEqual(result.returncode, 1)
        self.assertIn('did not start after 3 attempts', result.stderr)

    def test_start_fails_clearly_without_docker(self):
        result = self.run_script('start', DOCKER_DOWN='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Docker is not running', result.stderr)
        self.assertEqual(self.up_calls(), [])

    def test_install_writes_an_enabled_unit_after_docker(self):
        result = self.run_script('install')
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = (self.units/'myscanner.service').read_text()
        self.assertIn('Requires=docker.service', unit)
        self.assertIn('After=docker.service', unit)
        self.assertIn(f'ExecStart={ROOT}/scripts/vps_autostart.sh start', unit)
        self.assertIn('WantedBy=multi-user.target', unit)
        self.assertEqual(self.systemctl_log.read_text().splitlines(), ['daemon-reload', 'enable myscanner.service'])

    def test_unknown_command_is_rejected(self):
        self.assertEqual(self.run_script('restart-everything').returncode, 2)


class RestartPolicyTests(unittest.TestCase):
    ONE_SHOT = {'bootstrap-roles', 'migrate', 'seed'}

    def test_every_long_running_production_service_restarts_itself(self):
        # A container without a restart policy stays down after a host reboot, and
        # every service sharing or resolving its network fails with it.
        loader = type('Loader', (yaml.SafeLoader,), {})
        loader.add_constructor('!reset', lambda loader, node: None)
        policies = {}
        files = ('compose.vps.yml', 'compose.urlvet.yml', 'compose.egress.yml', 'compose.app-egress.yml', 'compose.launch.yml')
        for name in files:
            services = yaml.load((ROOT/name).read_text(encoding='utf-8'), Loader=loader).get('services') or {}
            for service, config in services.items():
                policies.setdefault(service, None)
                if (config or {}).get('restart'):
                    policies[service] = config['restart']
        missing = sorted(s for s, policy in policies.items() if s not in self.ONE_SHOT and policy != 'unless-stopped')
        self.assertEqual(missing, [])
        self.assertIn('urlvet-egress', policies)


if __name__ == '__main__':
    unittest.main()
