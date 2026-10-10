"""Resource-bounded native directory inspection. No member extraction or execution."""
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_ENTRIES = 1000
MAX_OUTPUT = 1024 * 1024


def unavailable(kind, reason):
    return {'type': kind, 'is_archive': True, 'coverage_status': 'partial',
            'error': reason, 'files': [], 'suspicious': [], 'encrypted': None,
            'num_files': None, 'contains_executable': None, 'contains_script': None,
            'missing_checks': ['Archive directory unavailable; member contents not inspected']}


def archive_observations(content, kind):
    if kind not in ('rar', '7z') or len(content) > 10 * 1024 * 1024:
        return unavailable(kind, 'Archive input unsupported or exceeds limit')
    if os.name != 'posix':
        return unavailable(kind, 'Bounded archive parser requires the Linux scanner container')
    with tempfile.TemporaryDirectory(prefix='myscanner-directory-') as directory:
        source = Path(directory)/'input.bin'; output = Path(directory)/'directory.json'
        source.write_bytes(content)
        try:
            with output.open('wb') as target:
                result = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(source), kind],
                                        stdout=target, stderr=subprocess.DEVNULL, timeout=6, check=False,
                                        env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode != 0 or output.stat().st_size > MAX_OUTPUT:
                return unavailable(kind, 'Archive parser failed or resource limit reached')
            data = json.loads(output.read_text())
            return data if isinstance(data, dict) else unavailable(kind, 'Archive parser returned no directory')
        except subprocess.TimeoutExpired:
            return unavailable(kind, 'Archive directory inspection timed out')
        except (OSError, ValueError):
            return unavailable(kind, 'Archive directory inspection unavailable')


def inspect_directory(path, kind):
    from file_structure import unsafe_name
    library = ctypes.util.find_library('archive')
    if not library:
        return unavailable(kind, 'Archive parser library not installed')
    lib = C.CDLL(library)
    def bind(name, result, args):
        fn = getattr(lib, name); fn.restype = result; fn.argtypes = args; return fn
    new=bind('archive_read_new',C.c_void_p,[])
    free=bind('archive_read_free',C.c_int,[C.c_void_p])
    support=bind('archive_read_support_format_'+('7zip' if kind=='7z' else 'rar'),C.c_int,[C.c_void_p])
    open_archive=bind('archive_read_open_filename',C.c_int,[C.c_void_p,C.c_char_p,C.c_size_t])
    header=bind('archive_read_next_header',C.c_int,[C.c_void_p,C.POINTER(C.c_void_p)])
    name=bind('archive_entry_pathname',C.c_char_p,[C.c_void_p])
    size=bind('archive_entry_size',C.c_int64,[C.c_void_p])
    encrypted=bind('archive_entry_is_encrypted',C.c_int,[C.c_void_p])
    encryption=bind('archive_read_has_encrypted_entries',C.c_int,[C.c_void_p])
    a=new()
    if not a:return unavailable(kind,'Archive parser allocation failed')
    result={'type':kind,'is_archive':True,'coverage_status':'partial','files':[],
            'suspicious':[],'encrypted':None,'encrypted_members':[],
            'num_files':None,'inspected_entries':0,'total_size':0,
            'contains_executable':False,'contains_script':False,'has_path_traversal':False,
            'missing_checks':['Archive member contents and nested archives were not inspected'],
            'scope':'Bounded directory metadata only. No files extracted or executed; solid headers may require internal decoding.'}
    complete=False
    try:
        support(a)
        if kind=='rar':bind('archive_read_support_format_rar5',C.c_int,[C.c_void_p])(a)
        if open_archive(a,os.fsencode(path),10240)!=0:
            return unavailable(kind,'Archive headers unavailable, encrypted or malformed')
        for _ in range(MAX_ENTRIES+1):
            entry=C.c_void_p(); status=header(a,C.byref(entry))
            if status==1:
                complete=True;break
            if status!=0:
                result['error']='Archive directory incomplete: unsupported, encrypted or malformed headers'
                result['missing_checks'].append('Remaining archive headers unavailable');break
            if result['inspected_entries']==MAX_ENTRIES:
                result['missing_checks'].append('Archive entry limit reached');break
            full_name=(name(entry) or b'').decode('utf-8','replace')
            member=full_name[:500]
            length=max(0,size(entry));result['inspected_entries']+=1;result['total_size']+=length
            if len(result['files'])<100:result['files'].append({'name':member,'size':length})
            lower=full_name.lower()
            for field,extensions,label in [('contains_executable',('.exe','.dll','.scr','.msi'),'Executable member'),('contains_script',('.py','.js','.ps1','.bat','.vbs','.sh'),'Script member')]:
                if lower.endswith(extensions):
                    result[field]=True
                    if len(result['suspicious'])<100:result['suspicious'].append(label+': '+member[:200])
            if unsafe_name(full_name):
                result['has_path_traversal']=True
                if len(result['suspicious'])<100:result['suspicious'].append('Unsafe member path: '+member[:200])
            if encrypted(entry)>0:
                result['encrypted']=True
                if len(result['encrypted_members'])<100:result['encrypted_members'].append(member)
        state=encryption(a)
        if state>0:result['encrypted']=True
        elif state==0 and complete:result['encrypted']=False
        if complete:result['num_files']=result['inspected_entries']
        else:
            for field in ('contains_executable','contains_script','has_path_traversal'):
                if result[field] is False:result[field]=None
        if result['encrypted']:result['missing_checks'].append('Encrypted archive contents were not inspected')
        if result['total_size']>100*1024*1024:result['suspicious'].append('Large declared uncompressed content; no member extraction performed')
        return result
    finally:
        free(a)


if __name__=='__main__':
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,256*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(3,3))
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_OUTPUT,MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    print(json.dumps(inspect_directory(sys.argv[1],sys.argv[2]),ensure_ascii=True))
