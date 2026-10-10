"""Save an optional rehearsal provider credential through a hidden local prompt."""
from pathlib import Path
import getpass
import os
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]


def save_key(key,root=ROOT):
    directory=Path(root)/'.deploy'/'rehearsal'
    path=directory/'abuseipdb_api_key'
    if not (Path(root)/'.env.vps.rehearsal').is_file() or not directory.is_dir():
        raise RuntimeError('Prepare the VPS rehearsal configuration first.')
    if any(p.is_symlink() for p in (directory,directory.parent,path)):
        raise RuntimeError('Secret path must not be a symbolic link.')
    if path.exists() and path.read_text(encoding='utf-8').strip():
        raise RuntimeError('An existing key was preserved; no replacement performed.')
    key=key.strip()
    if not 16<=len(key)<=4095 or any(not 33<=ord(c)<=126 for c in key):
        raise RuntimeError('Invalid key format; no key saved.')
    os.chmod(directory,0o700)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=directory,delete=False) as output:
            temporary=Path(output.name);os.chmod(temporary,0o600);output.write(key+'\n')
        os.chmod(temporary,0o444)
        if path.exists():os.chmod(path,0o600)
        try:
            os.replace(temporary,path)
        finally:
            if path.exists():os.chmod(path,0o444)
    finally:
        if temporary and temporary.exists():temporary.unlink()


def main():
    if not sys.stdin.isatty():
        raise RuntimeError('Use an interactive terminal for the hidden prompt.')
    key=getpass.getpass('Paste AbuseIPDB API key (hidden): ')
    save_key(key)
    print('AbuseIPDB key saved privately. No key printed.')

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):raise SystemExit('AbuseIPDB setup failed or cancelled; no key printed. Existing keys preserved.')

