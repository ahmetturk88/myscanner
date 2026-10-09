import socket
import unittest
from unittest.mock import MagicMock,patch
from services.public_smtp import PublicSMTP
from services.safe_http import UnsafeTargetError

class PublicSMTPTests(unittest.TestCase):
    def records(self,addresses):
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(address,443)) for address in addresses]
    def test_private_and_mixed_dns_fail_before_socket_creation(self):
        for addresses in (['127.0.0.1'],['10.1.2.3'],['169.254.169.254'],['8.8.8.8','192.168.1.1']):
            with patch('services.safe_http.socket.getaddrinfo',return_value=self.records(addresses)),patch('services.public_smtp.socket.socket') as sock:
                with self.assertRaises(UnsafeTargetError):PublicSMTP()._get_socket('mx.example',25,2)
                sock.assert_not_called()
    def test_connection_is_pinned_without_second_lookup(self):
        sock=MagicMock()
        with patch('services.safe_http.socket.getaddrinfo',return_value=self.records(['8.8.8.8'])) as dns,patch('services.public_smtp.socket.socket',return_value=sock):
            self.assertIs(PublicSMTP()._get_socket('mx.example',25,2),sock)
            dns.assert_called_once();sock.connect.assert_called_once_with(('8.8.8.8',25))
    def test_failed_connection_closes_socket(self):
        sock=MagicMock();sock.connect.side_effect=OSError('private data')
        with patch('services.safe_http.socket.getaddrinfo',return_value=self.records(['8.8.8.8'])),patch('services.public_smtp.socket.socket',return_value=sock):
            with self.assertRaises(OSError):PublicSMTP()._get_socket('mx.example',25,2)
            sock.close.assert_called_once()
    def test_arbitrary_ports_and_url_syntax_rejected_before_dns(self):
        for host,port in [('mx.example',443),('user@mx.example',25),('mx.example/path',25)]:
            with patch('services.safe_http.socket.getaddrinfo') as dns:
                with self.assertRaises(UnsafeTargetError):PublicSMTP()._get_socket(host,port,2)
                dns.assert_not_called()

if __name__=='__main__':unittest.main()
