"""MyScanner İşletme Telegram alerts: linking with one-time codes, /stop, recipients, alert text, secrets. No network."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import (BusinessChat, BusinessDomain, BusinessEvent, BusinessMember, BusinessSetting, BusinessWorkspace,
                    User)
from services import business_telegram as tg

T0 = datetime(2026, 11, 5, 9, 0)
ROOT = Path(__file__).resolve().parents[1]


class FakeBot:
    def __init__(self, updates=()):
        self.updates, self.calls = list(updates), []

    def __call__(self, method, payload):
        self.calls.append((method, payload))
        if method == 'getUpdates':
            return [u for u in self.updates if u['update_id'] >= payload['offset']]
        return {'message_id': 1}

    def sent(self):
        return [(p['chat_id'], p['text']) for m, p in self.calls if m == 'sendMessage']


def message(update_id, chat_id, text, kind='private', lang='tr'):
    return {'update_id': update_id, 'message': {'chat': {'id': chat_id, 'type': kind}, 'text': text,
                                                'from': {'language_code': lang}}}


class SecretTests(unittest.TestCase):
    def test_token_file_and_bot_name_are_validated(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, 'token')
            path.write_text('123456789:' + 'A' * 35 + '\n')
            with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN_FILE': str(path)}):
                self.assertEqual(tg.bot_token(), '123456789:' + 'A' * 35)
            path.write_text('not a token')
            with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN_FILE': str(path)}):
                self.assertIsNone(tg.bot_token())
        with patch.dict(os.environ, {'TELEGRAM_BOT_USERNAME': '@MyScannerAlertsBot'}):
            self.assertEqual(tg.bot_username(), 'MyScannerAlertsBot')
        with patch.dict(os.environ, {'TELEGRAM_BOT_USERNAME': 'evil.com/x'}):
            self.assertIsNone(tg.bot_username())

    def test_configure_script_never_overwrites_without_asking(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('configure_telegram', ROOT / 'scripts' / 'configure_telegram.py')
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        token = '123456789:' + 'B' * 35
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(RuntimeError):
                script.save_token(token, root)  # no prepared configuration
            Path(root, '.env.vps.rehearsal').write_text('X=1\n')
            Path(root, '.deploy', 'rehearsal').mkdir(parents=True)
            with self.assertRaises(RuntimeError):
                script.save_token('bad token', root)
            script.save_token(token, root)
            path = Path(root, '.deploy', 'rehearsal', 'telegram_bot_token')
            self.assertEqual(path.read_text().strip(), token)
            with self.assertRaises(RuntimeError):
                script.save_token('123456789:' + 'C' * 35, root)
            script.save_token('123456789:' + 'C' * 35, root, replace=True)
            self.assertTrue(path.read_text().startswith('123456789:CCC'))

    def test_the_token_lives_only_in_the_bulk_worker(self):
        import yaml
        compose = yaml.safe_load((ROOT / 'compose.vps.yml').read_text())
        self.assertIn('telegram_bot_token', compose['services']['bulk-worker']['secrets'])
        for name in ('web', 'worker', 'tip-worker', 'beat'):
            self.assertNotIn('telegram_bot_token', compose['services'][name].get('secrets', []))
        self.assertIn('TELEGRAM_BOT_USERNAME', compose['services']['web']['environment'])


class TelegramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def _clean(self):
        for model in (BusinessEvent, BusinessChat, BusinessSetting, BusinessMember, BusinessDomain, BusinessWorkspace):
            model.query.delete()
        User.query.filter(User.email.like('%@tg.invalid')).delete(synchronize_session=False)
        db.session.commit()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        self._clean()
        self.owner = self.person('owner', admin=True)
        self.workspace = BusinessWorkspace(owner_id=self.owner.id, name='owner')
        db.session.add(self.workspace)
        db.session.commit()
        self.env = patch.dict(os.environ, {'TELEGRAM_BOT_USERNAME': 'MyScannerAlertsBot'})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self._clean()
        db.session.remove()
        self.context.pop()

    def person(self, name, admin=False, verified=True):
        user = User(username=f'tg{name}', email=f'{name}@tg.invalid', password_hash='unused', is_verified=verified, is_admin=admin)
        db.session.add(user)
        db.session.commit()
        return user

    def link(self, user, chat_id, now=T0):
        url = tg.start_link(user, now=now)
        code = url.rsplit('=', 1)[1]
        bot = FakeBot([message(10 + chat_id, chat_id, f'/start {code}')])
        tg.poll(bot, now=now + timedelta(minutes=1))
        return bot

    def test_a_valid_code_links_the_chat_once(self):
        url = tg.start_link(self.owner, now=T0)
        self.assertTrue(url.startswith('https://t.me/MyScannerAlertsBot?start='))
        code = url.rsplit('=', 1)[1]
        bot = FakeBot([message(1, 555, f'/start {code}'), message(2, 777, f'/start {code}'),
                       message(3, -100, f'/start {code}', kind='group')])
        self.assertEqual(tg.poll(bot, now=T0 + timedelta(minutes=2)), 2)  # the group is ignored
        row = tg.chat_for(self.owner.id)
        self.assertEqual((row.chat_id, row.code), (555, None))
        self.assertIn('bağlandı', bot.sent()[0][1])
        self.assertEqual(bot.sent()[1][0], 777)  # the code was used up: the second chat gets the help text
        self.assertEqual(db.session.get(BusinessSetting, tg.OFFSET_KEY).value, '4')
        again = FakeBot([message(1, 555, '/start x' * 3), message(2, 777, '/start')])
        self.assertEqual(tg.poll(again, now=T0), 0)  # already handled updates are not read again

    def test_expired_codes_and_stop(self):
        url = tg.start_link(self.owner, now=T0)
        code = url.rsplit('=', 1)[1]
        bot = FakeBot([message(1, 555, f'/start {code}')])
        tg.poll(bot, now=T0 + timedelta(minutes=16))
        self.assertIsNone(tg.chat_for(self.owner.id).chat_id)
        self.link(self.owner, 555, now=T0 + timedelta(hours=1))
        self.assertEqual(tg.chat_for(self.owner.id).chat_id, 555)
        stop = FakeBot([message(5000, 555, '/stop')])
        tg.poll(stop, now=T0 + timedelta(hours=2))
        self.assertIsNone(tg.chat_for(self.owner.id))
        self.assertIn('durduruldu', stop.sent()[0][1])

    def test_recipients_follow_the_team_and_alerts_go_out_defanged(self):
        member = self.person('member')
        stranger = self.person('stranger')
        db.session.add(BusinessMember(workspace_id=self.workspace.id, email='member@tg.invalid', token='m' * 43,
                                      user_id=member.id, accepted_at=T0))
        db.session.commit()
        self.link(self.owner, 1)
        self.link(member, 2)
        self.link(stranger, 3)
        self.assertEqual(tg.recipients(self.workspace), [1, 2])
        domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com', token='cd' * 16, verified_at=T0)
        db.session.add(domain)
        db.session.commit()
        db.session.add(BusinessEvent(domain_id=domain.id, created_at=T0, code='lookalike_found', severity='bad',
                                     params=json.dumps({'name': 'magazam-giris.com', 'risk': 'high'})))
        db.session.commit()
        from services import business_alerts
        bot = FakeBot()
        business_alerts.send_instant(domain, sender=lambda *a: True, now=T0, telegram=bot)
        sent = bot.sent()
        self.assertEqual([chat for chat, _ in sent], [1, 2])
        self.assertIn('magazam-giris[.]com', sent[0][1])
        self.assertNotIn('magazam-giris.com', sent[0][1])
        self.assertTrue(all(p['link_preview_options'] == {'is_disabled': True} for m, p in bot.calls))

    def test_workspace_links_and_unlinks(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.owner.id)
            session['_fresh'] = True
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Telegram bildirimleri', page)
        token = BeautifulSoup(page, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        response = client.post('/isletme/panel/telegram/link', data={'csrf_token': token})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('https://t.me/MyScannerAlertsBot?start='))
        code = response.headers['Location'].rsplit('=', 1)[1]
        tg.poll(FakeBot([message(1, 42, f'/start {code}')]), now=datetime.utcnow())
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Bağlandı', page)
        client.post('/isletme/panel/telegram/unlink', data={'csrf_token': token})
        self.assertIsNone(tg.chat_for(self.owner.id))
        with patch.dict(os.environ, {'TELEGRAM_BOT_USERNAME': ''}):
            self.assertEqual(client.post('/isletme/panel/telegram/link', data={'csrf_token': token}).status_code, 404)
            self.assertNotIn('Telegram bildirimleri', client.get('/isletme/panel?lang=tr').get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
