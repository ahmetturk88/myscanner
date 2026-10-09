import unittest
from unittest.mock import MagicMock,patch
from services.email_checker import AdvancedEmailChecker

class SMTPBoundaryTests(unittest.TestCase):
    def setUp(self):self.checker=AdvancedEmailChecker();self.addCleanup(self.checker.executor.shutdown,wait=False)
    def test_timeout_and_temporary_reply_remain_unknown_and_close_session(self):
        mx=MagicMock();mx.preference=1;mx.exchange='mx.example.org.'
        for code in (None,450):
            smtp=MagicMock()
            if code is None:smtp.connect.side_effect=OSError('SECRET')
            else:smtp.rcpt.return_value=(code,b'Temporary failure')
            with patch('services.email_checker.dns.resolver.resolve',return_value=[mx]),patch('services.email_checker.PublicSMTP',return_value=smtp):
                result=self.checker.check_smtp('user@example.org')
            self.assertIsNone(result['valid']);self.assertEqual(result['coverage_status'],'unavailable')
            self.assertNotIn('SECRET',str(result));smtp.close.assert_called_once()
    def test_explicit_acceptance_and_rejection_are_checked(self):
        mx=MagicMock();mx.preference=1;mx.exchange='mx.example.org.'
        for code,valid in ((250,True),(550,False)):
            smtp=MagicMock();smtp.rcpt.return_value=(code,b'Reply')
            with patch('services.email_checker.dns.resolver.resolve',return_value=[mx]),patch('services.email_checker.PublicSMTP',return_value=smtp):
                result=self.checker.check_smtp('user@example.org')
            self.assertEqual((result['valid'],result['coverage_status']),(valid,'checked'))
    def test_unavailable_smtp_does_not_claim_undeliverable_or_safe(self):
        with patch.object(self.checker,'validate_format',return_value=(True,'user@example.org',{})),patch.object(self.checker,'check_smtp',return_value={'valid':None,'coverage_status':'unavailable'}),patch.object(self.checker,'check_dns_records',return_value={'spf':{'exists':True},'dmarc':{'exists':True}}),patch.object(self.checker,'check_blacklists',return_value={}),patch.object(self.checker,'check_domain_info',return_value={}):
            result=self.checker.check_all('user@example.org')
        self.assertEqual((result['verdict'],result['deliverability']),('unknown','UNKNOWN'))
        self.assertEqual(result['quality_score'],100)

if __name__=='__main__':unittest.main()
