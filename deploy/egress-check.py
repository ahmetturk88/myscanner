"""Temporary namespace-only listeners prove blocked destinations are reachable without filtering."""
import json
import socket
import subprocess
import urllib.request

FIXTURES = ('10.254.254.254', '169.254.254.254')


def command(*args):
    return subprocess.run(['ip',*args],check=True,capture_output=True,text=True).stdout


def check():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('https://example.com/',timeout=15) as response:
        if response.status != 200:raise RuntimeError('Public HTTPS failed')
        print('PASS: public HTTPS works',flush=True)
    addresses=json.loads(command('-j','address','show'))
    existing={entry['local'] for interface in addresses for entry in interface.get('addr_info',[])}
    if any(address in existing for address in FIXTURES):
        raise RuntimeError('Fixture address already exists; refusing to modify it')
    added=[]
    try:
        for address in FIXTURES:
            command('address','add',address+'/32','dev','lo');added.append(address)
        for address in ('127.0.0.1',*FIXTURES):
            for port in (80,443,43,25):
                with socket.socket() as listener:
                    listener.bind((address,port));listener.listen(1)
                    with socket.socket() as client:
                        client.settimeout(3)
                        if client.connect_ex((address,port)) == 0:
                            raise RuntimeError('Blocked destination reached an active listener')
                print('PASS: active listener blocked at '+address+':'+str(port),flush=True)
    finally:
        for address in reversed(added):
            command('address','del',address+'/32','dev','lo')
    print('PASS: temporary fixture addresses removed',flush=True)

if __name__=='__main__':
    try:check()
    except Exception:
        print('FAIL: namespace egress check; no secrets or database contents printed',flush=True)
        raise SystemExit(1)
