"""Resource-isolated PDF object observations; no raw-byte threat matching."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_INPUT = 10 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
MAX_NODES = 10000


def unavailable(reason):
    return {'type':'pdf','is_pdf':True,'num_pages':None,'is_encrypted':None,
        'has_javascript':None,'has_actions':None,'has_launch':None,
        'has_attachments':None,'has_form_fields':None,'metadata':{},'suspicious':[],
        'uris':[], 'coverage_status':'partial','error':reason,
        'missing_checks':['PDF object inspection unavailable'],
        'scope':'Bounded PDF objects only; no execution, rendering, antivirus or content-stream analysis.'}


def pdf_observations(content):
    if os.name != 'posix' or len(content)>MAX_INPUT:
        return unavailable('PDF parser requires Linux isolation and bounded input')
    with tempfile.TemporaryDirectory(prefix='myscanner-pdf-') as directory:
        source=Path(directory)/'input.pdf';output=Path(directory)/'result.json'
        source.write_bytes(content)
        try:
            with output.open('wb') as target:
                r=subprocess.run([sys.executable,str(Path(__file__).resolve()),str(source)],
                    stdout=target,stderr=subprocess.DEVNULL,timeout=6,check=False,
                    env={'PATH':os.defpath,'LANG':'C.UTF-8'})
            if r.returncode or output.stat().st_size>MAX_OUTPUT:
                return unavailable('PDF parser failed or resource limit reached')
            result=json.loads(output.read_text())
            return result if isinstance(result,dict) else unavailable('PDF parser returned invalid data')
        except (OSError,ValueError,subprocess.TimeoutExpired):
            return unavailable('PDF parsing failed or timed out')


def inspect_pdf(content):
    from pypdf import PdfReader
    from pypdf.generic import DictionaryObject,ArrayObject,IndirectObject,TextStringObject,NameObject
    r=unavailable('')
    r.pop('error')
    r.update(is_encrypted=False,has_javascript=False,has_actions=False,has_launch=False,
        has_attachments=False,has_form_fields=False,
        missing_checks=['PDF content streams, embedded payloads and script behavior were not inspected'])
    try:
        reader=PdfReader(io.BytesIO(content),strict=True)
        r['is_encrypted']=reader.is_encrypted
        if reader.is_encrypted:
            return unavailable('Encrypted PDF objects were not inspected') | {'is_encrypted':True}
        if reader.metadata:
            r['metadata']={str(k).lstrip('/').lower():str(v)[:300] for k,v in reader.metadata.items()}
        pages=reader.pages
        if len(pages)>1000:
            return unavailable('PDF page budget reached')
        r['num_pages']=len(pages)
        stack=[(reader.trailer.raw_get('/Root'),0)]
        seen=set();nodes=0;limited=False
        while stack:
            value,depth=stack.pop()
            if depth>40 or nodes>=MAX_NODES:
                limited=True;continue
            if isinstance(value,IndirectObject):
                key=('indirect',value.idnum,value.generation)
                if key in seen:continue
                seen.add(key);value=value.get_object()
            elif isinstance(value,(DictionaryObject,ArrayObject)):
                key=('direct',id(value))
                if key in seen:continue
                seen.add(key)
            nodes+=1
            if isinstance(value,DictionaryObject):
                # Only semantic dictionaries and name values; visible text is never an action.
                action=value.get('/S')
                if isinstance(action,NameObject) and str(action)=='/JavaScript':
                    r['has_javascript']=True
                if isinstance(action,NameObject) and str(action)=='/Launch':
                    r['has_launch']=True;r['suspicious'].append('Launch action dictionary detected')
                if '/AA' in value and isinstance(value.get('/AA'),DictionaryObject):
                    r['has_actions']=True;r['suspicious'].append('Additional-action dictionary detected')
                if '/OpenAction' in value and isinstance(value.get('/OpenAction'),DictionaryObject):
                    r['has_actions']=True;r['suspicious'].append('Document open-action dictionary detected')
                if str(value.get('/Type'))=='/EmbeddedFile' or isinstance(value.get('/EF'),DictionaryObject):
                    r['has_attachments']=True
                if '/AcroForm' in value and isinstance(value.get('/AcroForm'),DictionaryObject):
                    r['has_form_fields']=True
                uri=value.get('/URI') if str(action)=='/URI' else None
                if isinstance(uri,TextStringObject) and len(r['uris'])<100:
                    r['uris'].append(str(uri)[:2000])
                stack.extend((v,depth+1) for v in value.values())
            elif isinstance(value,ArrayObject):
                stack.extend((v,depth+1) for v in value)
        if r['has_javascript']:r['suspicious'].append('JavaScript action dictionary detected')
        if r['has_attachments']:r['suspicious'].append('Embedded file dictionary detected')
        r['suspicious']=sorted(set(r['suspicious']))
        r['uris']=list(dict.fromkeys(r['uris']))
        if limited:
            r['missing_checks'].append('PDF object traversal budget reached')
            for key in ('has_javascript','has_actions','has_launch','has_attachments','has_form_fields'):
                if r[key] is False:r[key]=None
        return r
    except Exception:
        return unavailable('PDF objects unavailable or malformed')


if __name__=='__main__':
    import resource
    resource.setrlimit(resource.RLIMIT_CPU,(3,3))
    resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,)*2)
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_OUTPUT,)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with open(sys.argv[1],'rb') as source:content=source.read(MAX_INPUT+1)
    print(json.dumps(inspect_pdf(content) if len(content)<=MAX_INPUT else unavailable('PDF input limit')))
