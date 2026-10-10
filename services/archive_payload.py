"""Bounded ZIP payload observations in a disposable Linux subprocess.

No member paths are written to disk and no uploaded code is executed.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile

MAX_INPUT = 10 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_MEMBERS = 100
MAX_DEPTH = 2
MAX_OUTPUT = 1024 * 1024


def unavailable(reason):
    return {'status': 'unavailable', 'members': [], 'inspected_members': 0,
            'expanded_bytes': 0, 'findings': [], 'missing_checks': [reason],
            'scope': 'Bounded static ZIP payload inspection; no execution or antivirus verdict.'}


def payload_observations(content):
    if os.name != 'posix' or len(content) > MAX_INPUT:
        return unavailable('Archive member contents unavailable: Linux or input limit required')
    with tempfile.TemporaryDirectory(prefix='myscanner-payload-') as directory:
        source = Path(directory) / 'input.zip'
        output = Path(directory) / 'result.json'
        source.write_bytes(content)
        try:
            with output.open('wb') as target:
                process = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(source)],
                    stdout=target, stderr=subprocess.DEVNULL, timeout=6,
                    env={'PATH': os.defpath, 'LANG': 'C.UTF-8'}, check=False)
            if process.returncode or output.stat().st_size > MAX_OUTPUT:
                return unavailable('Archive member contents unavailable: parser or resource limit')
            result = json.loads(output.read_text())
            return result if isinstance(result, dict) else unavailable('Archive member contents unavailable: invalid result')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return unavailable('Archive member contents unavailable: parser failed or timed out')


def inspect_zip(content):
    result = unavailable('')
    result.update(status='assessed', missing_checks=[], limits={
        'member_bytes': MAX_MEMBER, 'total_bytes': MAX_TOTAL,
        'members': MAX_MEMBERS, 'nested_depth': MAX_DEPTH})
    visited = 0

    def skip(reason):
        result['missing_checks'].append('Archive member contents limited: ' + reason)

    def walk(data, depth=0, prefix=''):
        nonlocal visited
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if visited >= MAX_MEMBERS:
                        skip('member count budget reached'); break
                    visited += 1
                    if member.is_dir():
                        continue
                    name = (prefix + member.filename)[:500]
                    if member.flag_bits & 1:
                        skip('encrypted member'); continue
                    if stat.S_ISLNK(member.external_attr >> 16):
                        skip('symbolic link'); continue
                    remaining = MAX_TOTAL - result['expanded_bytes']
                    if member.file_size > MAX_MEMBER or member.file_size > remaining:
                        skip('expanded size budget'); continue
                    if member.file_size / max(1, member.compress_size) > 100:
                        skip('compression ratio budget'); continue
                    try:
                        with archive.open(member) as stream:
                            raw = stream.read(min(MAX_MEMBER, remaining) + 1)
                        if len(raw) > min(MAX_MEMBER, remaining):
                            skip('actual expanded size budget'); continue
                        result['expanded_bytes'] += len(raw)
                        if len(raw) != member.file_size:
                            skip('member size mismatch'); continue
                    except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                        skip('unreadable or corrupt member'); continue
                    kind = 'zip' if raw.startswith((b'PK\x03\x04', b'PK\x05\x06')) else 'pe' if raw.startswith(b'MZ') else 'elf' if raw.startswith(b'\x7fELF') else 'rar' if raw.startswith(b'Rar!') else '7z' if raw.startswith(b'7z\xbc\xaf\x27\x1c') else 'data'
                    row = {'name': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'observed_type': kind}
                    try:
                        text = raw.decode('utf-8')
                        if '\x00' not in text:
                            row['observed_type'] = kind if kind != 'data' else 'utf8_text'
                            # Literal indicators only, never classify these as confirmed malware.
                            markers = [s for s in ('-EncodedCommand', 'Invoke-Expression', 'eval(', 'exec(', 'subprocess.', 'CreateObject(', 'WScript.Shell') if s.casefold() in text.casefold()]
                            if markers:
                                row['static_indicators'] = markers
                                result['findings'].append({'member': name, 'indicators': markers,
                                    'meaning': 'Code-related text patterns; context required, not a malware verdict.'})
                    except UnicodeError:
                        pass
                    result['members'].append(row)
                    result['inspected_members'] += 1
                    if kind == 'zip':
                        if depth < MAX_DEPTH:
                            walk(raw, depth + 1, name + '!/')
                        else:
                            skip('nested depth budget')
                    elif kind in ('rar', '7z'):
                        skip('nested format has directory-only support')
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
            skip('malformed ZIP structure')
    walk(content)
    result['missing_checks'] = sorted(set(result['missing_checks']))
    if result['missing_checks']:
        result['status'] = 'partial'
    return result


if __name__ == '__main__':
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with open(sys.argv[1], 'rb') as source:
        content = source.read(MAX_INPUT + 1)
    print(json.dumps(inspect_zip(content) if len(content) <= MAX_INPUT else unavailable('Archive member contents unavailable: input limit')))
