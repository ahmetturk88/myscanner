"""In-app update prompts: the build policy and its public endpoint."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from services.app_release import policy
import test_task_ownership


class PolicyTests(unittest.TestCase):
    def test_prompts_are_off_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MOBILE_LATEST_BUILD', None); os.environ.pop('MOBILE_MIN_BUILD', None)
            self.assertEqual(policy(5)['update'], 'none')

    def test_builds_below_the_minimum_must_update_and_below_latest_may(self):
        with patch.dict(os.environ, {'MOBILE_LATEST_BUILD': '14', 'MOBILE_MIN_BUILD': '12'}):
            self.assertEqual([policy(b)['update'] for b in (11, 12, 13, 14, 15)], ['required', 'available', 'available', 'none', 'none'])
            self.assertEqual(policy(None)['update'], 'none')
            self.assertIn('com.myscanners.app', policy(11)['store_url'])

    def test_a_minimum_above_latest_counts_as_latest_and_bad_values_are_off(self):
        with patch.dict(os.environ, {'MOBILE_LATEST_BUILD': 'x', 'MOBILE_MIN_BUILD': '12'}):
            self.assertEqual(policy(11), {**policy(11), 'update': 'required', 'latest_build': 12})


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.client = test_task_ownership.TaskOwnershipTests.production.app.test_client()

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def test_the_version_check_needs_no_sign_in(self):
        with patch.dict(os.environ, {'MOBILE_LATEST_BUILD': '12', 'MOBILE_MIN_BUILD': '11'}):
            response = self.client.get('/api/mobile/v1/app/version?build=10')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['update'], 'required')
            self.assertEqual(self.client.get('/api/mobile/v1/app/version?build=11').get_json()['update'], 'available')
            self.assertEqual(self.client.get('/api/mobile/v1/app/version?build=abc').get_json()['update'], 'none')
            self.assertEqual(response.headers['Cache-Control'], 'no-store')


class ScriptTests(unittest.TestCase):
    def run_script(self, folder, *args):
        script = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'app_release.py')
        copy = os.path.join(folder, 'scripts', 'app_release.py')
        os.makedirs(os.path.dirname(copy), exist_ok=True)
        with open(script) as src, open(copy, 'w') as dst:
            dst.write(src.read())
        return subprocess.run([sys.executable, copy, *args], capture_output=True, text=True)

    def test_the_script_writes_env_keeps_other_lines_and_refuses_min_above_latest(self):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, '.env'), 'w') as handle:
                handle.write('URLVET_URL=http://x\nMOBILE_LATEST_BUILD=11')
            self.assertEqual(self.run_script(folder, '--latest', '12', '--min', '12').returncode, 0)
            with open(os.path.join(folder, '.env')) as handle:
                self.assertEqual(handle.read(), 'URLVET_URL=http://x\nMOBILE_LATEST_BUILD=12\nMOBILE_MIN_BUILD=12\n')
            refused = self.run_script(folder, '--min', '13')
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('above the latest', refused.stderr)
