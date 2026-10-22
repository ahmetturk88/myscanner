"""ClamAV (clamd) antivirus scan over its INSTREAM protocol.

The scanner runs in its own container (compose service "clamav"); CLAMAV_HOST
names it. Without CLAMAV_HOST the check is reported as not configured, so local
and test setups don't claim an antivirus scan that never ran.
"""
import os
import socket
import struct

PORT = 3310
TIMEOUT = 60
CHUNK = 256 * 1024
# Detections that flag risky features rather than known malware.
SOFT_PREFIXES = ('Heuristics.', 'PUA.')


def _connect():
    host = os.environ.get('CLAMAV_HOST', '').strip()
    if not host:
        return None
    port = int(os.environ.get('CLAMAV_PORT', PORT))
    return socket.create_connection((host, port), timeout=TIMEOUT)


def _reply(sock):
    data = b''
    while not data.endswith(b'\0'):
        part = sock.recv(4096)
        if not part:
            break
        data += part
        if len(data) > 8192:
            break
    return data.rstrip(b'\0').decode('utf-8', 'replace').strip()


def _version():
    try:
        with _connect() as sock:
            sock.sendall(b'zVERSION\0')
            parts = _reply(sock).split('/')
        return {'engine': parts[0], 'database_version': parts[1] if len(parts) > 1 else None,
                'database_date': parts[2] if len(parts) > 2 else None}
    except (OSError, TypeError, AttributeError):
        return {}


def scan_bytes(content):
    """Returns {'status': 'clean' | 'found' | 'unavailable' | 'not_configured', ...}.

    'found' carries the signature name and 'kind': 'malware', or 'heuristic' for
    Heuristics.* and PUA.* names, which describe risky features, not known malware.
    """
    try:
        sock = _connect()
    except OSError:
        return {'status': 'unavailable', 'error': 'Antivirus service unreachable'}
    if sock is None:
        return {'status': 'not_configured'}
    try:
        with sock:
            sock.sendall(b'zINSTREAM\0')
            view = memoryview(content)
            for start in range(0, len(view), CHUNK):
                piece = view[start:start + CHUNK]
                sock.sendall(struct.pack('!L', len(piece)) + piece)
            sock.sendall(struct.pack('!L', 0))
            answer = _reply(sock)
    except OSError:
        return {'status': 'unavailable', 'error': 'Antivirus scan interrupted'}
    result = {'source': 'clamav', **_version()}
    if answer.endswith(' FOUND'):
        signature = answer[len('stream:'):-len(' FOUND')].strip()[:120] if answer.startswith('stream:') else answer[:-6].strip()[:120]
        return {**result, 'status': 'found', 'signature': signature,
                'kind': 'heuristic' if signature.startswith(SOFT_PREFIXES) else 'malware'}
    if answer.endswith(': OK') or answer == 'stream: OK':
        return {**result, 'status': 'clean'}
    # "INSTREAM size limit exceeded", "... ERROR" and anything unexpected.
    return {**result, 'status': 'unavailable', 'error': 'Antivirus scan did not complete'}


def selfcheck():
    """Scan the EICAR test string; a working setup reports it as found."""
    # Assembled at run time so this source file is not itself flagged.
    eicar = ('X5O!P%@AP[4\\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').encode()
    print('CLAMAV_HOST =', os.environ.get('CLAMAV_HOST', '') or '(not set)')
    print('version:', _version() or 'unreachable')
    result = scan_bytes(eicar)
    print('EICAR test:', result.get('status'), result.get('signature', ''))
    print('PASS' if result.get('status') == 'found' else 'FAIL')


if __name__ == '__main__':
    selfcheck()
