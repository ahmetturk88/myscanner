import unittest
from unittest.mock import patch,Mock
from test_scanner_egress import egress
from pathlib import Path

class ApplicationEgressTests(unittest.TestCase):
    def test_app_dependency_exceptions_are_port_specific(self):
        for role in ('web','worker'):
            rules=egress.rules([('172.20.0.2',5432),('172.20.0.3',6379),('172.21.0.2',8080)],role)
            self.assertIn(['-P','OUTPUT','DROP'],rules)
            self.assertTrue(all('/32' in r[r.index('-d')+1] for r in rules if '--dport' in r))
            for port in (80,443,8000,9222,22):
                with self.assertRaises(ValueError):egress.rules([('172.20.0.2',port)],role)
            self.assertIn('80,443,43,25',rules[-1])
    def test_worker_has_no_loopback_dependency_exception(self):
        worker=egress.rules([], 'worker');web=egress.rules([], 'web')
        rule=['-A','OUTPUT','-d','127.0.0.1/32','-p','tcp','--dport','8000','-j','ACCEPT']
        self.assertIn(rule,web);self.assertNotIn(rule,worker)
        self.assertFalse(any('--dport' in r and '443' in r and '127.0.0.1/32' in r for r in web))
    def test_overlay_moves_only_runtime_namespaces_without_caps_or_secrets(self):
        source=(Path(__file__).resolve().parents[1]/'compose.app-egress.yml').read_text()
        self.assertEqual(source.count('cap_add: [NET_ADMIN]'),2)
        self.assertEqual(source.count('network_mode: service:'),2)
        self.assertNotIn('ports:',source);self.assertNotIn('secrets:',source)
        self.assertIn('aliases: [web]',source);self.assertIn('172.31.240.3',source)
    def test_resolution_failure_prevents_ready_and_ipv4_is_closed_first(self):
        commands=[]
        with patch.dict('os.environ',{'SCANNER_ROLE':'worker'}),patch.object(egress.subprocess,'run',side_effect=lambda command,**kw:commands.append(command)),patch.object(egress.socket,'getaddrinfo',side_effect=RuntimeError),patch.object(egress.Path,'touch') as ready,patch.object(egress.Path,'unlink'):
            with self.assertRaises(RuntimeError):egress.install()
            ready.assert_not_called()
        self.assertTrue(any(command[:2]==['iptables','-w'] and '-P' in command for command in commands))
        self.assertTrue(any('--ctorigdstport' in command for command in commands))

if __name__=='__main__':unittest.main()
