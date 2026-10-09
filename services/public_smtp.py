"""SMTP recipient probes connect only to previously validated public addresses."""
import smtplib
import socket
from services.safe_http import validate_public_url, UnsafeTargetError

class PublicSMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        if port != 25 or not isinstance(host,str) or any(c in host for c in '/:@?#\\'):
            raise UnsafeTargetError('A public MX hostname on SMTP port 25 is required')
        target=validate_public_url('https://'+host)
        self._host = target.hostname  # STARTTLS SNI/certificate name, while socket stays pinned.
        family,kind,protocol,_,address=target.addresses[0]
        pinned=list(address);pinned[1]=25
        sock=socket.socket(family,kind,protocol)
        try:
            sock.settimeout(timeout)
            sock.connect(tuple(pinned))
        except BaseException:
            sock.close();raise
        return sock
