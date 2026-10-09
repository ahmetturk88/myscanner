import unittest
from unittest.mock import Mock,patch
from scripts.rehearsal_performance import memory_bytes,percentile,valid_base,compose,RehearsalHTTPSConnection,fetch_local
class MeasurementTests(unittest.TestCase):
    def test_ipv4_connection_retains_sni_without_resolving_localhost(self):
        context=Mock();sock=Mock()
        connection=RehearsalHTTPSConnection('localhost',8443,timeout=10,context=context)
        with patch('scripts.rehearsal_performance.socket.socket',return_value=sock),patch('scripts.rehearsal_performance.socket.getaddrinfo') as dns:
            connection.connect()
        sock.connect.assert_called_once_with(('127.0.0.1',8443))
        context.wrap_socket.assert_called_once_with(sock,server_hostname='localhost');dns.assert_not_called()
    def test_http_measurement_keeps_host_and_never_follows_redirects(self):
        connection=Mock(connect_ms=1,tls_ms=2)
        connection.getresponse.return_value=Mock(status=302)
        with patch('scripts.rehearsal_performance.RehearsalHTTPSConnection',return_value=connection) as factory:
            result=fetch_local('https://localhost:8443','/health/live')
        self.assertEqual(factory.call_args.args[:2],('localhost',8443))
        connection.request.assert_called_once_with('GET','/health/live',headers={'Connection':'close'})
        connection.close.assert_called_once();self.assertFalse(result['ok']);self.assertIn('response_wait_ms',result)
    def test_docker_memory_units(self):
        self.assertEqual(memory_bytes('1.5GiB'),1610612736);self.assertEqual(memory_bytes('512MiB'),536870912);self.assertEqual(memory_bytes('1GB'),1000000000)
        with self.assertRaises(ValueError):memory_bytes('unknown')
    def test_percentiles_and_no_success_do_not_fabricate_latency(self):
        self.assertEqual(percentile(list(range(1,101)),95),95);self.assertIsNone(percentile([],95))
    def test_measurement_refuses_remote_or_authenticated_urls(self):
        for url in ('https://example.com:8443','http://localhost:8443','https://user:secret@localhost:8443','https://localhost:8443/path','https://localhost:8443?key=x'):
            with self.assertRaises(ValueError):valid_base(url)
        self.assertEqual(valid_base('https://localhost:8443/'),'https://localhost:8443')
        self.assertIn('compose.app-egress.yml',compose())
if __name__=='__main__':unittest.main()
