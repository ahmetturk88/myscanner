"""Prepare an isolated production-mode rehearsal; never modifies local/Render secrets."""
from pathlib import Path
import os
import secrets
import re
ROOT=Path(__file__).resolve().parents[1]


def initialize(root=ROOT):
    directory=Path(root)/'.deploy'/'rehearsal';directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(directory,0o700)
    for name in ['db_admin_password','db_app_password','db_migration_password','redis_password','session_key','urlvet_cache_password','urlvet_jwt_secret']:
        path=directory/name
        if path.exists():
            if not re.fullmatch('[0-9a-f]{64}',path.read_text().strip()):raise RuntimeError('Invalid existing secret; not replaced.')
        else:
            with path.open('x') as output:output.write(secrets.token_hex(32)+'\n')
        # Compose file secrets bind-mount host files without UID remapping.
        # World-readable inode within a private host directory permits non-root containers.
        os.chmod(path,0o444)
    for name in ('urlhaus_auth_key', 'abuseipdb_api_key'):
        optional=directory/name
        if optional.is_symlink():raise RuntimeError('Optional secret path must not be a symbolic link.')
        if not optional.exists():
            with optional.open('x',encoding='utf-8') as output:output.write('')
        os.chmod(optional,0o444)
    config=directory/'redis_config'
    expected='appendonly yes\nappendfsync everysec\nmaxmemory 256mb\nmaxmemory-policy noeviction\nrequirepass '+(directory/'redis_password').read_text().strip()+'\n'
    if config.exists() and config.read_text()!=expected:raise RuntimeError('Existing Redis configuration does not match secrets.')
    if not config.exists():
        with config.open('x') as output:output.write('appendonly yes\nappendfsync everysec\nmaxmemory 256mb\nmaxmemory-policy noeviction\nrequirepass '+(directory/'redis_password').read_text().strip()+'\n')
        os.chmod(config,0o444)
    provider_config=directory/'urlvet_cache_config'
    provider_expected='appendonly yes\nmaxmemory 256mb\nmaxmemory-policy allkeys-lru\nrequirepass '+(directory/'urlvet_cache_password').read_text().strip()+'\n'
    if provider_config.exists() and provider_config.read_text()!=provider_expected:raise RuntimeError('Provider cache configuration does not match secrets.')
    if not provider_config.exists():
        with provider_config.open('x') as output:output.write(provider_expected)
        os.chmod(provider_config,0o444)
    env=Path(root)/'.env.vps.rehearsal' 
    if not env.exists():
        with env.open('x') as output:output.write('COMPOSE_PROJECT_NAME=myscanner-vps-rehearsal\nVPS_IMAGE=myscanner-vps:rehearsal\nSITE_DOMAIN=localhost\nHTTP_BIND=127.0.0.1:8088\nHTTPS_BIND=127.0.0.1:8443\nSECRET_DIRECTORY=./.deploy/rehearsal\n')
        os.chmod(env,0o600)
    print('VPS rehearsal configuration prepared; existing secrets preserved.')

if __name__=='__main__':
    try:initialize()
    except Exception:raise SystemExit('VPS rehearsal preparation failed; no secrets printed.')

