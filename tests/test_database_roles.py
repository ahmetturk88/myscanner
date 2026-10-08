import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from scripts.init_local_stack import initialize
from services.database_roles import provision_roles, validate_passwords, transfer_object_ownership
from services.database_role_check import expect_denied

class DatabaseRoleTests(unittest.TestCase):
    def test_table_ownership_moves_before_dependent_sequences(self):
        connection=Mock()
        connection.dialect.identifier_preparer.quote.side_effect=lambda value: '"'+value+'"'
        connection.execute.return_value.scalar.return_value='myscanner_schema_owner'
        transfer_object_ownership(connection, [('user_id_seq','S','myscanner_local'),('user','r','myscanner_local')])
        statements=[call.args[0] for call in connection.exec_driver_sql.call_args_list]
        self.assertEqual(statements,['ALTER TABLE public."user" OWNER TO myscanner_schema_owner'])
    def test_standalone_sequence_is_transferred(self):
        connection=Mock()
        connection.dialect.identifier_preparer.quote.return_value='"standalone"'
        connection.execute.return_value.scalar.return_value=None
        transfer_object_ownership(connection,[('standalone','S','myscanner_local')])
        connection.exec_driver_sql.assert_called_once_with('ALTER SEQUENCE public."standalone" OWNER TO myscanner_schema_owner')
    def test_dependency_on_untransferred_parent_is_rejected(self):
        connection=Mock();connection.execute.return_value.scalar.return_value='other_owner'
        with self.assertRaises(RuntimeError):transfer_object_ownership(connection,[('sequence','S','myscanner_local')])
        connection.exec_driver_sql.assert_not_called()
    def test_existing_credentials_survive_configuration_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory,'.env.docker.local')
            original='LOCAL_SECRET_KEY='+'a'*96+'\nLOCAL_DB_PASSWORD='+'b'*64+'\n'
            path.write_text(original)
            self.assertTrue(initialize(directory))
            updated=path.read_text()
            self.assertTrue(updated.startswith(original))
            values=dict(line.split('=',1) for line in updated.splitlines() if '=' in line)
            self.assertEqual(len(set(values.values())),4)
            self.assertFalse(initialize(directory))
            self.assertEqual(updated,path.read_text())
    def test_malformed_existing_configuration_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory,'.env.docker.local');path.write_text('LOCAL_DB_PASSWORD=invalid\n')
            with self.assertRaises(RuntimeError):initialize(directory)
            self.assertEqual(path.read_text(),'LOCAL_DB_PASSWORD=invalid\n')
    def test_remote_database_is_rejected_before_connecting(self):
        engine=Mock();engine.url=sa.engine.make_url('postgresql+psycopg2://myscanner_local:private@remote/myscanner_local')
        with self.assertRaises(RuntimeError):provision_roles(engine,'a'*64,'b'*64)
        engine.begin.assert_not_called()
    def test_shared_or_invalid_credentials_are_rejected(self):
        for first,second in [('a'*64,'a'*64),('short','b'*64),(None,'b'*64)]:
            with self.assertRaises(RuntimeError):validate_passwords(first,second)
    def test_denial_requires_actual_insufficient_privilege_sqlstate(self):
        connection=Mock();original=Exception();original.pgcode='42501'
        connection.exec_driver_sql.side_effect=DBAPIError('statement',{},original)
        expect_denied(connection,'CREATE TABLE probe(id integer)')
        connection.begin_nested.return_value.rollback.assert_called_once()
        original.pgcode='42P01'
        with self.assertRaises(RuntimeError):expect_denied(connection,'DROP TABLE probe')
    def test_unexpected_permission_is_rolled_back_and_rejected(self):
        connection=Mock()
        with self.assertRaises(RuntimeError):expect_denied(connection,'CREATE TABLE probe(id integer)')
        connection.begin_nested.return_value.rollback.assert_called_once()

if __name__=='__main__':unittest.main()
