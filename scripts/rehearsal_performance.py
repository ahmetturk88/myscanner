"""Read-only, loopback-only rehearsal measurements; no scans or database mutations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import re
import ssl
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlsplit

ROOT=__import__('pathlib').Path(__file__).resolve().parents[1]


def compose():
    return ['docker','compose','--env-file','.env.vps.rehearsal','-f','compose.vps.yml','-f','compose.urlvet.yml','-f','compose.egress.yml','-f','compose.app-egress.yml']


def docker(command):
    r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15)
    if r.returncode:raise RuntimeError('Docker measurement failed; no command output printed')
    return r.stdout


def memory_bytes(value):
    match=re.fullmatch(r'\s*([\d.]+)\s*(B|kB|KB|KiB|MB|MiB|GB|GiB|TB|TiB)\s*',value)
    if not match:raise ValueError('Unknown memory unit')
    factors={'B':1,'kB':1000,'KB':1000,'KiB':1024,'MB':1000**2,'MiB':1024**2,'GB':1000**3,'GiB':1024**3,'TB':1000**4,'TiB':1024**4}
    return int(float(match[1])*factors[match[2]])


def percentile(values,percent):
    if not values:return None
    values=sorted(values);return round(values[max(0,math.ceil(len(values)*percent/100)-1)],2)


def valid_base(value):
    p=urlsplit(value)
    if p.scheme!='https' or p.hostname not in ('localhost','127.0.0.1') or p.port!=8443 or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:
        raise ValueError('Only https://localhost:8443 rehearsal is allowed')
    return value.rstrip('/')


def measure(args):
    base=valid_base(args.base)
    ids=docker(compose()+['ps','-q']).split()
    if not ids:raise RuntimeError('Rehearsal stack not running')
    host=json.loads(docker(['docker','info','--format','{{json .}}']))
    rows={};errors=[];stop=threading.Event()
    def sample():
        while not stop.is_set():
            try:
                for line in docker(['docker','stats','--no-stream','--format','{{json .}}',*ids]).splitlines():
                    entry=json.loads(line);name=entry['Name'];memory=memory_bytes(entry['MemUsage'].split('/')[0]);cpu=float(entry['CPUPerc'].rstrip('%'))
                    previous=rows.setdefault(name,{'peak_memory_bytes':0,'peak_cpu_percent':0,'peak_pids':0,'samples':0})
                    previous['peak_memory_bytes']=max(previous['peak_memory_bytes'],memory);previous['peak_cpu_percent']=max(previous['peak_cpu_percent'],cpu);previous['peak_pids']=max(previous['peak_pids'],int(entry['PIDs']));previous['samples']+=1
            except Exception:errors.append('Container sample unavailable')
            stop.wait(2)
    thread=threading.Thread(target=sample);thread.start()
    samples=[];mutex=threading.Lock();start=time.monotonic();deadline=start+args.seconds
    # Certificate bypass is restricted to this local rehearsal URL, never arbitrary targets.
    opener=lambda:urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    paths=('/health/live','/health/ready','/')
    def reader(index):
        client=opener();iteration=0
        while time.monotonic()<deadline:
            path=paths[(iteration+index)%len(paths)];iteration+=1;begin=time.monotonic();status=None
            try:
                with client.open(base+path,timeout=10) as response:
                    response.read(1024*1024);status=response.status
            except Exception:pass
            with mutex:samples.append({'path':path,'ms':(time.monotonic()-begin)*1000,'ok':status==200})
            # Rate-limited to at most one request/second per reader.
            stop.wait(max(0,1-(time.monotonic()-begin)))
    print('Measuring rehearsal. If testing scan load, start your own authorized scans in the browser now.',flush=True)
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:list(pool.map(reader,range(args.concurrency)))
    finally:stop.set();thread.join(timeout=20)
    successful=[item['ms'] for item in samples if item['ok']]
    result={'mode':'rehearsal-read-only','seconds':round(time.monotonic()-start,1),'concurrency':args.concurrency,'requests':len(samples),'failures':sum(not s['ok'] for s in samples),'p50_ms':percentile(successful,50),'p95_ms':percentile(successful,95),'docker_cpus':host.get('NCPU'),'docker_memory_bytes':host.get('MemTotal'),'containers':rows,'sampling_errors':len(errors),
            'limits':'Home and health reads only. External scan duration, sustained load, browser rendering and VPS hardware require separate measurements.'}
    result['by_endpoint']={path:{'requests':sum(s['path']==path for s in samples),'failures':sum(s['path']==path and not s['ok'] for s in samples),'p95_ms':percentile([s['ms'] for s in samples if s['path']==path and s['ok']],95)} for path in paths}
    # Sum of per-container peaks is a conservative envelope, not simultaneous peak RAM.
    peak=sum(row['peak_memory_bytes'] for row in rows.values())
    result['observed_memory_envelope_bytes']=peak
    result['provisional_ram_floor_gib']=math.ceil((peak*1.5+1024**3)/1024**3) if rows else None
    result['sizing_note']='Provisional RAM floor adds 50% headroom plus 1 GiB for OS. It is not a CPU recommendation or capacity guarantee; repeat under representative authorized scan load.'
    print(json.dumps(result,indent=2))
    if args.output:
        path=__import__('pathlib').Path(args.output)
        if path.exists():raise RuntimeError('Output exists; choose a new file')
        path.write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--base',default='https://localhost:8443');parser.add_argument('--seconds',type=int,default=30);parser.add_argument('--concurrency',type=int,default=2);parser.add_argument('--output')
    args=parser.parse_args()
    if not 10<=args.seconds<=60 or not 1<=args.concurrency<=4:parser.error('Seconds 10..60; concurrency 1..4')
    try:measure(args)
    except Exception:
        print('Measurement failed; no credentials or service output printed.');raise SystemExit(1)

if __name__=='__main__':main()
