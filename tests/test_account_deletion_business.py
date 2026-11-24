"""Deleting an account removes its business workspace, memberships, Telegram link and pilot sign-up."""
import unittest
from datetime import datetime

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import (BusinessChat, BusinessDomain, BusinessEvent, BusinessLead, BusinessMember, BusinessSnapshot,
                    BusinessWorkspace, User)
from services.account_deletion import delete_account

T0 = datetime(2026, 11, 24, 9, 0)


class AccountDeletionBusinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        for model in (BusinessEvent, BusinessSnapshot, BusinessDomain, BusinessMember, BusinessChat, BusinessWorkspace):
            model.query.delete()
        BusinessLead.query.filter(BusinessLead.email.like('%@del.invalid')).delete(synchronize_session=False)
        User.query.filter(User.email.like('%@del.invalid')).delete(synchronize_session=False)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def user(self, name):
        row = User(username=name, email=f'{name}@del.invalid', password_hash='unused', is_verified=True)
        db.session.add(row)
        db.session.commit()
        return row

    def test_owner_and_member_data_is_removed(self):
        owner, member, other = self.user('delowner'), self.user('delmember'), self.user('delother')
        workspace = BusinessWorkspace(owner_id=owner.id, name='owner')
        kept = BusinessWorkspace(owner_id=other.id, name='other')
        db.session.add_all([workspace, kept])
        db.session.commit()
        domain = BusinessDomain(workspace_id=workspace.id, domain='magazam.com', token='ab' * 16, verified_at=T0)
        db.session.add(domain)
        db.session.commit()
        snapshot = BusinessSnapshot(domain_id=domain.id, kind='weekly', created_at=T0, results='{}')
        db.session.add(snapshot)
        db.session.flush()
        db.session.add_all([
            BusinessEvent(domain_id=domain.id, snapshot_id=snapshot.id, created_at=T0, code='x', severity='bad', params='{}'),
            BusinessMember(workspace_id=kept.id, user_id=member.id, email=member.email, token='m' * 32, accepted_at=T0),
            BusinessMember(workspace_id=kept.id, email='delowner@del.invalid', token='p' * 32),  # a pending invitation
            BusinessChat(user_id=owner.id, chat_id=12345, linked_at=T0),
            BusinessLead(email='delowner@del.invalid', website='magazam.com'),
        ])
        db.session.commit()

        self.assertTrue(delete_account(owner.id))
        self.assertEqual(BusinessWorkspace.query.filter_by(owner_id=owner.id).count(), 0)
        self.assertEqual(BusinessDomain.query.count(), 0)
        self.assertEqual(BusinessSnapshot.query.count(), 0)
        self.assertEqual(BusinessEvent.query.count(), 0)
        self.assertEqual(BusinessChat.query.count(), 0)
        self.assertEqual(BusinessLead.query.filter_by(email='delowner@del.invalid').count(), 0)
        self.assertEqual([m.email for m in BusinessMember.query.all()], ['delmember@del.invalid'])

        self.assertTrue(delete_account(member.id))
        self.assertEqual(BusinessMember.query.count(), 0)
        self.assertEqual(BusinessWorkspace.query.filter_by(id=kept.id).count(), 1)  # someone else's workspace stays


if __name__ == '__main__':
    unittest.main()
