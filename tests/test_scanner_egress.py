import importlib.util
import ipaddress
from pathlib import Path
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scanner_egress',ROOT/'deploy/scanner-egress.py')
egress=importlib.util.module_from_spec(spec);spec.loader.exec_module(egress)

class EgressTests(unittest.TestCase):
    def test_non_public_targets_are_rejected_before_public_ports(self):
        rules=egress.rules()
        last=rules[-1]
        self.assertEqual(last[-1],'ACCEPT')
        for address in ('0.0.0.0','10.2.3.4','100.100.100.200','127.0.0.1','169.254.169.254','172.31.240.2','192.168.1.1','198.18.1.1','224.0.0.1','255.255.255.255'):
            self.assertTrue(any(ipaddress.ip_address(address) in ipaddress.ip_network(cidr) for cidr in egress.BLOCKED),address)
        self.assertIn(['-P','OUTPUT','DROP'],rules)
        self.assertNotIn('INPUT',str(rules))
    def test_exceptions_are_exact_service_ip_and_port_only(self):
        rules=egress.rules([('172.20.0.3',6379)])
        exception=next(r for r in rules if '--dport' in r and '6379' in r)
        self.assertIn('172.20.0.3/32',exception)
        self.assertLess(rules.index(exception),next(i for i,r in enumerate(rules) if 'REJECT' in r))
        for address,port in [('8.8.8.8',6379),('127.0.0.1',9222),('169.254.1.1',6379),('172.20.0.3',80),('::1',6379)]:
            with self.assertRaises(ValueError):egress.rules([(address,port)])
    def test_ipv6_rule_failure_never_creates_ready_marker(self):
        with patch.object(egress.subprocess,'run',side_effect=RuntimeError),patch.object(egress.Path,'touch') as touch:
            with self.assertRaises(RuntimeError):egress.install()
            touch.assert_not_called()
    def test_namespace_overlay_has_no_published_ports_or_privileged_scanner(self):
        text=(ROOT/'compose.egress.yml').read_text()
        self.assertNotIn('ports:',text);self.assertNotIn('privileged:',text)
        self.assertEqual(text.count('network_mode: service:'),2)
        self.assertEqual(text.count('networks: !reset []'),2)
        self.assertEqual(text.count('cap_add: [NET_ADMIN]'),2)
        self.assertEqual(text.count('condition: service_healthy'),4)
    def test_dns_only_exception_does_not_allow_loopback_web(self):
        rules=egress.rules()
        loopback=[r for r in rules if '127.0.0.11/32' in r]
        self.assertEqual(len(loopback),2)
        self.assertTrue(all(r[r.index('--dport')+1]=='53' for r in loopback))

if __name__=='__main__':unittest.main()
