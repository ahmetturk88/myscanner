import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('egress_fixture',ROOT/'deploy/egress-check.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

class FixtureTests(unittest.TestCase):
    def response(self):
        opener=MagicMock();opener.open.return_value.__enter__.return_value.status=200
        return patch.object(fixture.urllib.request,'build_opener',return_value=opener)
    def test_existing_address_is_never_changed(self):
        with self.response(),patch.object(fixture,'command',return_value='[{"addr_info":[{"local":"10.254.254.254"}]}]') as command:
            with self.assertRaises(RuntimeError):fixture.check()
            self.assertEqual(command.call_count,1)
    def test_added_addresses_removed_even_when_listener_fails(self):
        with self.response(),patch.object(fixture,'command',return_value='[]') as command,patch.object(fixture.socket,'socket',side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):fixture.check()
            self.assertEqual([call.args for call in command.call_args_list[-2:]],
                             [('address','del','169.254.254.254/32','dev','lo'),('address','del','10.254.254.254/32','dev','lo')])
    def test_successful_connection_fails_check_and_cleans(self):
        sock=MagicMock();sock.__enter__.return_value=sock;sock.connect_ex.return_value=0
        with self.response(),patch.object(fixture,'command',return_value='[]') as command,patch.object(fixture.socket,'socket',return_value=sock):
            with self.assertRaises(RuntimeError):fixture.check()
            self.assertEqual(command.call_args.args,('address','del','10.254.254.254/32','dev','lo'))

if __name__=='__main__':unittest.main()
