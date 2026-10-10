"""Bounded static container observations. No member paths written or code executed."""
import io
import re
import zipfile
import xml.etree.ElementTree as ET

MAX_ENTRIES = 1000
MAX_XML = 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024


def container_type(content):
    if not content.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            for prefix, kind in [('word/', 'docx'), ('xl/', 'xlsx'), ('ppt/', 'pptx')]:
                if '[Content_Types].xml' in names and any(n.startswith(prefix) for n in names):
                    return kind
    except (ValueError, zipfile.BadZipFile):
        pass
    return 'zip'


def unsafe_name(name):
    normalized = name.replace('\\', '/')
    return normalized.startswith('/') or bool(re.match(r'^[a-zA-Z]:', normalized)) or '..' in normalized.split('/')


def zip_observations(content, office=False):
    result = {'type': 'openxml' if office else 'zip', 'suspicious': [], 'coverage_status': 'assessed',
              'scope': 'Container directory and bounded XML inspection; members were not extracted or executed.',
              'num_files': None, 'total_size': None, 'files': [], 'encrypted_members': [],
              'has_path_traversal': None, 'contains_executable': None, 'contains_script': None,
              'contains_office': None, 'has_macros': None if office else False, 'has_ole': None if office else False,
              'external_relationships': [], 'metadata': {}, 'missing_checks': []}
    result['is_office' if office else 'is_archive'] = True
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            result.update(num_files=len(entries), total_size=sum(e.file_size for e in entries),
                          has_path_traversal=False, contains_executable=False, contains_script=False, contains_office=False)
            if len(entries) > MAX_ENTRIES:
                result['missing_checks'].append('Container entry limit reached; only the first 1000 members inspected')
            if result['total_size'] > MAX_TOTAL:
                result['suspicious'].append('Large declared uncompressed content; members were not expanded')
            if office:
                result.update(has_macros=False, has_ole=False)
            if not office:
                from services.archive_payload import payload_observations
                payload = payload_observations(content)
                result['payload_inspection'] = payload
                result['missing_checks'].extend(payload.get('missing_checks', []))
                result['missing_checks'].append('No member execution, sandbox or antivirus scan was performed')
                result['scope'] = 'Directory and bounded static ZIP payload observations; no member paths extracted or code executed.'
            budget = MAX_XML * 2
            for member in entries[:MAX_ENTRIES]:
                name = member.filename
                lower = name.lower()
                result['files'].append({'name': name[:500], 'size': member.file_size, 'compressed': member.compress_size})
                if unsafe_name(name):
                    result['has_path_traversal'] = True
                    result['suspicious'].append('Unsafe member path: ' + name[:200])
                if member.flag_bits & 1:
                    result['encrypted_members'].append(name[:500])
                if member.file_size > 1024 * 1024 and member.file_size / max(1, member.compress_size) > 100:
                    result['suspicious'].append('High compression ratio: ' + name[:200])
                if lower.endswith(('.exe', '.dll', '.scr', '.msi')):
                    result['contains_executable'] = True
                    result['suspicious'].append('Executable member: ' + name[:200])
                if lower.endswith(('.py', '.js', '.ps1', '.vbs', '.sh', '.bat')):
                    result['contains_script'] = True
                if lower.endswith(('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf')):
                    result['contains_office'] = True
                if office and lower.endswith('vbaproject.bin'):
                    result['has_macros'] = True
                    result['suspicious'].append('VBA macro project: ' + name[:200])
                if office and '/embeddings/' in lower:
                    result['has_ole'] = True
                    result['suspicious'].append('Embedded object: ' + name[:200])
                if office and (lower == 'docprops/core.xml' or lower.endswith('.rels')):
                    if member.flag_bits & 1 or member.file_size > MAX_XML or member.file_size > budget or member.file_size / max(1, member.compress_size) > 100:
                        result['missing_checks'].append('Office XML member skipped by encryption or size limits')
                        continue
                    raw = archive.read(member)
                    budget -= len(raw)
                    # Reject DTD/entity declarations before using the standard XML parser.
                    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                        result['missing_checks'].append('Office XML declarations not inspected')
                        continue
                    try:
                        tree = ET.fromstring(raw)
                    except ET.ParseError:
                        result['missing_checks'].append('Malformed Office XML')
                        continue
                    if lower == 'docprops/core.xml':
                        for elem in tree:
                            if elem.text:
                                result['metadata'][elem.tag.split('}')[-1]] = elem.text[:200]
                    else:
                        for elem in tree.iter():
                            if elem.tag.split('}')[-1] == 'Relationship' and elem.get('TargetMode') == 'External':
                                relationship = {'target': elem.get('Target', '')[:1000], 'type': elem.get('Type', '').split('/')[-1][:100]}
                                result['external_relationships'].append(relationship)
                                if relationship['type'].lower() != 'hyperlink':
                                    result['suspicious'].append('External Office relationship: ' + relationship['type'])
            result['files'] = result['files'][:100]
            result['external_relationships'] = result['external_relationships'][:100]
            result['suspicious'] = list(dict.fromkeys(result['suspicious']))[:100]
            if result['encrypted_members']:
                result['missing_checks'].append('Encrypted members were not inspected')
            result['missing_checks'] = list(dict.fromkeys(result['missing_checks']))
            if len(entries) > MAX_ENTRIES:
                for key in ('has_path_traversal','contains_executable','contains_script','contains_office','has_macros','has_ole'):
                    if result[key] is False:
                        result[key] = None
            if result['missing_checks']:
                result['coverage_status'] = 'partial'
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError, NotImplementedError):
        result.update(error='Container structure unavailable or malformed', coverage_status='partial')
    return result
