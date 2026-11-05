"""Save the Telegram bot token for MyScanner İşletme alerts through a hidden prompt.

Run on the server, in an interactive terminal:  python3 scripts/configure_telegram.py
The token is never printed. The script asks Telegram for the bot's public name and
prints that, so it can be set as TELEGRAM_BOT_USERNAME in .env.vps.rehearsal.
Replacing an existing token needs --replace (for example after revoking it in @BotFather).
"""
from pathlib import Path
import getpass
import json
import os
import re
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r'^\d{5,12}:[A-Za-z0-9_-]{30,64}$')


def save_token(token, root=ROOT, replace=False):
    directory = Path(root) / '.deploy' / 'rehearsal'
    path = directory / 'telegram_bot_token'
    if not (Path(root) / '.env.vps.rehearsal').is_file() or not directory.is_dir():
        raise RuntimeError('Prepare the VPS rehearsal configuration first.')
    if any(p.is_symlink() for p in (directory, directory.parent, path)):
        raise RuntimeError('Secret path must not be a symbolic link.')
    if path.exists() and path.read_text(encoding='utf-8').strip() and not replace:
        raise RuntimeError('An existing token was preserved; use --replace to change it.')
    token = token.strip()
    if not TOKEN.match(token):
        raise RuntimeError('Invalid token format; nothing saved.')
    os.chmod(directory, 0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory, delete=False) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            output.write(token + '\n')
        os.chmod(temporary, 0o444)  # read by the container user, inside a private directory
        if path.exists():
            os.chmod(path, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o444)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def bot_name(token):
    """The bot's public @name from Telegram, or None. The request URL (with the token) is never printed."""
    try:
        with urllib.request.urlopen(f'https://api.telegram.org/bot{token}/getMe', timeout=15) as response:
            data = json.loads(response.read(65536).decode('utf-8'))
    except Exception:
        return None
    result = data.get('result') if isinstance(data, dict) and data.get('ok') else None
    name = result.get('username') if isinstance(result, dict) else None
    return name if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_]{5,32}', name) else None


def main():
    if not sys.stdin.isatty():
        raise RuntimeError('Use an interactive terminal for the hidden prompt.')
    token = getpass.getpass('Paste the Telegram bot token from @BotFather (hidden): ').strip()
    if not TOKEN.match(token):
        raise RuntimeError('Invalid token format.')
    name = bot_name(token)
    if name is None:
        raise RuntimeError('Telegram did not accept this token.')
    save_token(token, replace='--replace' in sys.argv[1:])
    print('Telegram token saved privately. No token printed.')
    print(f'Bot name: @{name}')
    print(f'Next: add TELEGRAM_BOT_USERNAME={name} to .env.vps.rehearsal, then: dc up -d web bulk-worker')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        message = str(error) if isinstance(error, RuntimeError) else 'cancelled'
        raise SystemExit(f'Telegram setup stopped: {message} No token printed; an existing token was kept.')
