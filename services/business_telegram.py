"""MyScanner Business: instant alerts on Telegram.

How a person links their chat (no phone number is ever asked or stored):
1. In the workspace they press "Link Telegram"; we create a one-time code (15 minutes).
2. The button opens t.me/<bot>?start=<code>; they press Start in Telegram.
3. A beat task asks Telegram for new messages every minute (polling: nothing on our
   site listens to the internet) and links the chat that sent the valid code.
"/stop" in the bot, or "Unlink" in the workspace, removes the link.

The bot token is a deployment secret read from TELEGRAM_BOT_TOKEN_FILE (bulk worker
only). It is never logged: request URLs contain it, so errors are reported without them.
Only instant alerts go to Telegram; digests and the monthly report stay in email.
"""
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from extensions import db

API = 'https://api.telegram.org'
CODE_LIFETIME = timedelta(minutes=15)
TOKEN = re.compile(r'^\d{5,12}:[A-Za-z0-9_-]{30,64}$')
USERNAME = re.compile(r'^[A-Za-z][A-Za-z0-9_]{3,31}bot$', re.I)
CODE = re.compile(r'^[A-Za-z0-9_-]{16,40}$')
OFFSET_KEY = 'telegram_offset'
MAX_TEXT = 3500

WORDS = {
    'tr': {'linked': '✅ MyScanner İşletme bağlandı. Önemli değişiklikler buraya da gelecek. Durdurmak için /stop yazın.',
           'stopped': 'Bildirimler durduruldu. Yeniden bağlamak için panelinizdeki “Telegram’a bağla” düğmesini kullanın.',
           'unknown': 'Bağlamak için MyScanner İşletme panelinizdeki “Telegram’a bağla” düğmesini kullanın. Bağlantı kodları 15 dakika geçerlidir.',
           'title': '⚠️ MyScanner İşletme · {domain}', 'panel': 'Panel'},
    'en': {'linked': '✅ MyScanner Business is linked. Important changes will come here too. Send /stop to end.',
           'stopped': 'Alerts stopped. To link again, use “Link Telegram” in your workspace.',
           'unknown': 'To link, use “Link Telegram” in your MyScanner Business workspace. Link codes are valid for 15 minutes.',
           'title': '⚠️ MyScanner Business · {domain}', 'panel': 'Workspace'},
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def bot_username():
    value = (os.environ.get('TELEGRAM_BOT_USERNAME') or '').strip().lstrip('@')
    return value if USERNAME.match(value) else None


def bot_token():
    path = os.environ.get('TELEGRAM_BOT_TOKEN_FILE', '')
    try:
        with open(path, encoding='utf-8') as secret:
            value = secret.read(256).strip()
    except (OSError, UnicodeError, TypeError, ValueError):
        return None
    return value if TOKEN.match(value) else None


def api(method, payload, token=None):
    """One Bot API call; the parsed result or None. The URL (with the token) is never logged or raised."""
    import requests
    token = token or bot_token()
    if not token:
        return None
    try:
        response = requests.post(f'{API}/bot{token}/{method}', json=payload, timeout=(5, 15), allow_redirects=False)
        data = response.json() if response.status_code == 200 else None
    except Exception:
        return None
    return data.get('result') if isinstance(data, dict) and data.get('ok') else None


# ------------------------------------------------------------------ linking

def chat_for(user_id):
    from models import BusinessChat
    return BusinessChat.query.filter_by(user_id=user_id).first()


def start_link(user, now=None):
    """A fresh one-time code for this person; returns the t.me deep link (None when the bot is not configured)."""
    from models import BusinessChat
    name = bot_username()
    if not name:
        return None
    now = now or _now()
    row = chat_for(user.id)
    if row is None:
        row = BusinessChat(user_id=user.id)
        db.session.add(row)
    row.code, row.code_expires = secrets.token_urlsafe(18), now + CODE_LIFETIME
    db.session.commit()
    return f'https://t.me/{name}?start={row.code}'


def unlink(user_id):
    row = chat_for(user_id)
    if row is not None:
        db.session.delete(row)
        db.session.commit()


def _offset():
    from models import BusinessSetting
    row = db.session.get(BusinessSetting, OFFSET_KEY)
    try:
        return int(row.value) if row else 0
    except ValueError:
        return 0


def _save_offset(value):
    from models import BusinessSetting
    row = db.session.get(BusinessSetting, OFFSET_KEY)
    if row is None:
        db.session.add(BusinessSetting(key=OFFSET_KEY, value=str(value)))
    else:
        row.value = str(value)


def poll(call=None, now=None):
    """Read new bot messages once: link valid codes, handle /stop. Returns how many messages were handled."""
    from models import BusinessChat
    call = call or api
    now = now or _now()
    offset = _offset()
    updates = call('getUpdates', {'offset': offset, 'timeout': 0, 'allowed_updates': ['message'], 'limit': 100})
    if not isinstance(updates, list):
        return 0
    handled, replies = 0, []
    for update in updates:
        if not isinstance(update, dict) or not isinstance(update.get('update_id'), int):
            continue
        offset = max(offset, update['update_id'] + 1)
        message = update.get('message') if isinstance(update.get('message'), dict) else {}
        chat = message.get('chat') if isinstance(message.get('chat'), dict) else {}
        text = message.get('text') if isinstance(message.get('text'), str) else ''
        if chat.get('type') != 'private' or not isinstance(chat.get('id'), int):
            continue  # groups and channels are never linked
        handled += 1
        lang = 'tr' if (message.get('from') or {}).get('language_code', 'tr') == 'tr' else 'en'
        parts = text.strip().split()
        if parts[:1] == ['/start'] and len(parts) == 2 and CODE.match(parts[1]):
            row = BusinessChat.query.filter_by(code=parts[1]).first()
            if row is not None and row.code_expires and row.code_expires >= now:
                row.chat_id, row.linked_at, row.code, row.code_expires = chat['id'], now, None, None
                replies.append((chat['id'], WORDS[lang]['linked']))
                continue
            replies.append((chat['id'], WORDS[lang]['unknown']))
        elif parts[:1] == ['/stop']:
            BusinessChat.query.filter_by(chat_id=chat['id']).delete(synchronize_session=False)
            replies.append((chat['id'], WORDS[lang]['stopped']))
        else:
            replies.append((chat['id'], WORDS[lang]['unknown']))
    _save_offset(offset)
    db.session.commit()
    for chat_id, text in replies:
        call('sendMessage', {'chat_id': chat_id, 'text': text, 'link_preview_options': {'is_disabled': True}})
    return handled


# ------------------------------------------------------------------ alerts

def recipients(workspace):
    """Linked chats of the owner and of accepted members who want alerts (verified accounts only)."""
    from models import BusinessChat, BusinessMember, User
    people = [workspace.owner_id] + [m.user_id for m in BusinessMember.query.filter(
        BusinessMember.workspace_id == workspace.id, BusinessMember.alerts.is_(True),
        BusinessMember.accepted_at.isnot(None), BusinessMember.user_id.isnot(None)).all()]
    chats = []
    for user_id in dict.fromkeys(people):
        user = db.session.get(User, user_id)
        row = BusinessChat.query.filter_by(user_id=user_id).first()
        if user is not None and getattr(user, 'is_verified', False) is True and row and row.chat_id and row.chat_id not in chats:
            chats.append(row.chat_id)
    return chats


def alert_text(text, groups, panel_url):
    lang = 'tr' if text.get('lang') == 'tr' else 'en'
    blocks = []
    for domain, _, items in groups:
        lines = [WORDS[lang]['title'].format(domain=domain), '']
        lines += [f'• {line}' for _, line, _ in items]
        blocks.append('\n'.join(lines))
    body = '\n\n'.join(blocks)
    if len(body) > MAX_TEXT:
        body = body[:MAX_TEXT].rsplit('\n', 1)[0] + '\n…'
    return f"{body}\n\n{WORDS[lang]['panel']}: {panel_url}"


def send_alert(workspace, text, groups, panel_url, call=None):
    """Send one alert message to every linked chat. Returns how many chats got it."""
    call = call or api
    message = alert_text(text, groups, panel_url)
    sent = 0
    for chat_id in recipients(workspace):
        if call('sendMessage', {'chat_id': chat_id, 'text': message, 'link_preview_options': {'is_disabled': True}}) is not None:
            sent += 1
    return sent
