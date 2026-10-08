"""Local Docker backups and isolated restore rehearsals; never targets hosting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '--env-file', str(ROOT/'.env.docker.local'), '-f', str(ROOT/'compose.local.yml')]


def invoke(arguments, input_text=None):
    result = subprocess.run(COMPOSE + arguments, input=input_text, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=600)
    if result.returncode:
        for line in result.stdout.splitlines():
            if line.startswith(('CHECK ERROR TYPE:', 'CHECK SQLSTATE:', 'CHECK FRAME:', 'CHECK SCHEMA:')):
                print(line)
        raise RuntimeError('Local Docker operation failed; database contents and credentials were not printed.')
    return result.stdout


def checksum(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def backup_directory():
    base = os.environ.get('LOCALAPPDATA')
    return Path(base)/'MyScanner'/'backups' if base else Path.home()/'.local'/'share'/'MyScanner'/'backups'


def sql(statement):
    return invoke(['exec','-T','postgres','psql','-X','-v','ON_ERROR_STOP=1','-U','myscanner_local','-d','myscanner_local','-t','-A','-c',statement])


def verify_archive(path):
    path=Path(path).resolve()
    manifest=json.loads(path.with_suffix('.dump.json').read_text(encoding='utf-8'))
    if (manifest.get('format') != 'postgresql-custom-local-v1' or manifest.get('filename') != path.name
            or manifest.get('bytes') != path.stat().st_size or manifest.get('sha256') != checksum(path)):
        raise RuntimeError('Backup integrity verification failed.')
    return path


def create_backup():
    directory=backup_directory();directory.mkdir(parents=True,exist_ok=True)
    name='myscanner-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)+'.dump'
    path=directory/name;partial=directory/(name+'.partial');remote='/tmp/'+name
    try:
        invoke(['exec','-T','postgres','pg_dump','-U','myscanner_local','-d','myscanner_local','-Fc','-f',remote])
        invoke(['exec','-T','postgres','pg_restore','--list',remote])
        invoke(['cp','postgres:'+remote,str(partial)])
        if partial.stat().st_size == 0:
            raise RuntimeError('Backup is empty.')
        os.chmod(partial,0o600)
        partial.rename(path)
        manifest={'format':'postgresql-custom-local-v1','filename':name,'bytes':path.stat().st_size,
                  'sha256':checksum(path),'created_utc':datetime.now(timezone.utc).isoformat()}
        target=path.with_suffix('.dump.json')
        with target.open('x',encoding='utf-8') as output:
            json.dump(manifest,output,indent=2)
        os.chmod(target,0o600)
        verify_archive(path)
        print('PASS: backup archive and SHA-256 manifest saved.')
        print('Backup:',path)
        print('Bytes:',manifest['bytes'])
        return path
    finally:
        partial.unlink(missing_ok=True)
        invoke(['exec','-T','postgres','rm','-f',remote])


RESTORE_CHECK = '''
import os, sys, re, hashlib, json
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from scripts.local_runtime import require_local_stack
from services.schema_migrations import upgrade_database, application_metadata
require_local_stack(administrator=True)
name=sys.argv[1]
if not re.fullmatch(r"myscanner_rehearsal_[0-9a-f]{24}",name):
    raise SystemExit("Invalid rehearsal name")
engine=sa.create_engine(sa.engine.make_url(os.environ["DATABASE_URL"]).set(database=name),hide_parameters=True)
def snapshot():
    result={}
    with engine.connect() as connection:
        inspector=sa.inspect(connection)
        for name in inspector.get_table_names(schema="public"):
            if name=="alembic_version": continue
            quoted=connection.dialect.identifier_preparer.quote(name)
            rows=connection.exec_driver_sql("SELECT * FROM public."+quoted).mappings()
            hashes=sorted(hashlib.sha256(json.dumps(dict(row),sort_keys=True,default=str,ensure_ascii=False).encode()).hexdigest() for row in rows)
            result[name]=(len(hashes),hashlib.sha256("".join(hashes).encode()).hexdigest())
    return result
try:
    before=snapshot()
    if not {"user","scan"}.issubset(before): raise RuntimeError("Required tables missing")
    upgrade_database(engine)
    after=snapshot()
    if any(after.get(name)!=value for name,value in before.items()): raise RuntimeError("Restored data changed")
    with engine.connect() as connection:
        differences=compare_metadata(MigrationContext.configure(connection),application_metadata())
    if differences:
        for group in differences:
            for item in (group if isinstance(group,list) else [group]):
                operation=item[0]
                table=item[2] if len(item)>2 and isinstance(item[2],str) else "-"
                column=getattr(item[3],"name",item[3] if isinstance(item[3],str) else "-") if len(item)>3 else "-"
                print("CHECK SCHEMA:",operation,"table",table,"column",column)
        raise RuntimeError("Restored schema does not match models")
    print("PASS: archive restored and migrated; all restored table data unchanged.")
    print("Users:",after["user"][0],"Scans:",after["scan"][0])
except Exception as error:
    import traceback
    print("CHECK ERROR TYPE:", type(error).__name__)
    print("CHECK SQLSTATE:", getattr(getattr(error,"orig",None),"pgcode",None))
    for frame in traceback.extract_tb(error.__traceback__):
        print("CHECK FRAME:",frame.filename,"line",frame.lineno,"in",frame.name)
    raise SystemExit(1)
finally:
    engine.dispose()
''' 


def restore_check(path):
    path=verify_archive(path)
    name='myscanner_rehearsal_'+secrets.token_hex(12)
    remote='/tmp/'+name+'.dump'
    created=False
    try:
        invoke(['cp',str(path),'postgres:'+remote])
        sql('CREATE DATABASE '+name+' TEMPLATE template0');created=True
        invoke(['exec','-T','postgres','pg_restore','-U','myscanner_local','-d',name,
                '--single-transaction','--exit-on-error','--no-owner','--no-privileges',remote])
        output=invoke(['run','--rm','--no-deps','-T','--entrypoint','python','bootstrap-roles','-',name],RESTORE_CHECK)
        # Forward only our success/count lines, never arbitrary application output.
        for line in output.splitlines():
            if line.startswith(('PASS:','Users:')):print(line)
        if 'PASS: archive restored and migrated;' not in output:
            raise RuntimeError('Restore verification did not complete.')
    finally:
        if created:sql('DROP DATABASE '+name+' WITH (FORCE)')
        invoke(['exec','-T','postgres','rm','-f',remote])
    print('PASS: separate rehearsal database removed; running database was not restored over.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['backup','restore-check'])
    parser.add_argument('--backup',type=Path)
    args=parser.parse_args()
    try:
        if not (ROOT/'.env.docker.local').is_file():raise RuntimeError('Local configuration is missing.')
        if args.command=='backup':
            if args.backup:raise RuntimeError('Backup output is managed automatically.')
            create_backup()
        else:
            if not args.backup:raise RuntimeError('An explicit backup archive is required.')
            restore_check(args.backup)
    except Exception:
        print('Local backup operation failed. No credentials or database contents printed.',file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
