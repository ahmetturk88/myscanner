"""Install fail-closed namespace output rules before a scanner starts."""
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import time

BLOCKED = ('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
           '169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24',
           '192.88.99.0/24','192.168.0.0/16','198.18.0.0/15',
           '198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4')


def rules(exceptions=(), role="provider"):
    if role not in ('provider','browser','web','worker'):raise ValueError('Unknown scanner role')
    allowed_ports={'provider':(6379,9222),'browser':(),'web':(5432,6379,8080),'worker':(5432,6379,8080)}[role]
    # INPUT is untouched: only new outbound connections are restricted.
    result=[['-P','OUTPUT','DROP'], ['-F','OUTPUT'],
            ['-A','OUTPUT','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']]
    for protocol in ('udp','tcp'):
        result.append(['-A','OUTPUT','-d','127.0.0.11/32','-p',protocol,
                       '-m','conntrack','--ctorigdst','127.0.0.11',
                       '--ctorigdstport','53','--ctdir','ORIGINAL','-j','ACCEPT'])
    for address,port in exceptions:
        ip=ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError('Invalid service exception')
        if port not in allowed_ports:raise ValueError('Invalid service port')
        result.append(['-A','OUTPUT','-d',str(ip)+'/32','-p','tcp','--dport',str(port),'-j','ACCEPT'])
    if role=='web':
        # Health endpoint only; user target transports allow 80/443, not 8000.
        result.append(['-A','OUTPUT','-d','127.0.0.1/32','-p','tcp','--dport','8000','-j','ACCEPT'])
    for cidr in BLOCKED:
        result.append(['-A','OUTPUT','-d',cidr,'-j','REJECT'])
    result.append(['-A','OUTPUT','-p','tcp','-m','multiport','--dports','80,443,43,25' if role in ('web','worker') else '80,443,43','-j','ACCEPT'])
    # WHOIS TCP/43 is allowed only to public IPv4. IPv6 is deliberately closed.
    return result


def install():
    Path('/tmp/egress-ready').unlink(missing_ok=True)
    # IPv6 must close successfully too; failure prevents scanner startup.
    subprocess.run(['ip6tables','-w','-P','OUTPUT','DROP'],check=True)
    subprocess.run(['ip6tables','-w','-F','OUTPUT'],check=True)
    subprocess.run(['ip6tables','-w','-A','OUTPUT','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'],check=True)
    mode=os.environ.get('SCANNER_ROLE')
    if mode not in ('browser','provider','web','worker'):raise ValueError('Unknown scanner role')
    # Close IPv4 before resolving dependencies; retain Docker DNS only.
    for rule in rules((),mode)[:5]:subprocess.run(['iptables','-w',*rule],check=True)
    exceptions=[]
    destinations={'browser':(), 'provider':(('urlvet-cache',6379),('urlvet-browser',9222)),
                  'web':(('postgres',5432),('redis',6379),('urlvet',8080)),
                  'worker':(('postgres',5432),('redis',6379),('urlvet',8080))}
    if destinations[mode]:
        for host,port in destinations[mode]:
            addresses={row[4][0] for row in socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM)}
            if not addresses:raise ValueError('Service resolution failed')
            exceptions.extend((address,port) for address in addresses)
    for rule in rules(exceptions,mode):subprocess.run(['iptables','-w',*rule],check=True)
    Path('/tmp/egress-ready').touch()
    while True:time.sleep(30)

if __name__=='__main__':
    try:install()
    except Exception:
        print('Scanner egress initialization failed; scanner must remain stopped.',flush=True)
        raise SystemExit(1)
