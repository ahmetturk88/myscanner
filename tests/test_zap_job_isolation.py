"""Fresh job lifecycle is simulated; no ZAP process or target traffic starts."""
from contextlib import ExitStack
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from services.vulnerability_scanner.zap_job import isolated_zap_job, ZAPJobError, _stop_process
from services.active_scan_policy import TargetAuthorizationRequired
from services.vulnerability_scanner.scan_orchestrator import ScanOrchestrator

class JobTests(unittest.TestCase):
    def environment(self, stack):
        stack.enter_context(patch('services.vulnerability_scanner.zap_job.platform.system',return_value='Linux'))
        stack.enter_context(patch('services.vulnerability_scanner.zap_job.signal.SIGKILL',9,create=True))
        process=Mock(pid=12345)
        process.poll.return_value=None
        popen=stack.enter_context(patch('services.vulnerability_scanner.zap_job.subprocess.Popen',return_value=process))
        kill=stack.enter_context(patch('services.vulnerability_scanner.zap_job.os.killpg',create=True))
        health=Mock()
        health.get.return_value=Mock(status_code=200,json=lambda:{'version':'test'})
        session=stack.enter_context(patch('services.vulnerability_scanner.zap_job.requests.Session'))
        session.return_value.__enter__.return_value=health
        client=Mock()
        factory=stack.enter_context(patch('services.vulnerability_scanner.zap_job.ZAPClient',return_value=client))
        return process,popen,kill,health,client,factory

    def test_each_job_has_fresh_directory_session_key_and_no_shared_daemon(self):
        with ExitStack() as stack:
            process,popen,kill,health,client,factory=self.environment(stack)
            homes=[];keys=[]
            for _ in range(2):
                with isolated_zap_job(sys.executable) as returned:
                    self.assertIs(returned,client)
                    args=popen.call_args.args[0]
                    home=Path(args[args.index('-dir')+1]);homes.append(home)
                    config=Path(args[args.index('-configfile')+1])
                    key=factory.call_args.kwargs['api_key'];keys.append(key)
                    content=config.read_text(encoding='utf-8')
                    self.assertIn('api.key='+key,content)
                    self.assertIn('api.disablekey=false',content)
                    self.assertNotIn(key,' '.join(args))
                    self.assertEqual(Path(args[args.index('-newsession')+1]).parent,home/'sessions')
                    self.assertEqual(args[args.index('-host')+1],'127.0.0.1')
                    self.assertTrue(popen.call_args.kwargs['start_new_session'])
                    self.assertFalse(popen.call_args.kwargs['shell'])
                    self.assertFalse(factory.call_args.kwargs['use_https'])
                self.assertFalse(home.exists())
            self.assertNotEqual(homes[0],homes[1]);self.assertNotEqual(keys[0],keys[1])
            self.assertEqual(client._session.close.call_count,2)
            self.assertGreaterEqual(kill.call_count,4)
            self.assertFalse(health.trust_env)

    def test_job_body_error_stops_process_and_removes_directory(self):
        with ExitStack() as stack:
            process,popen,kill,health,client,factory=self.environment(stack)
            with self.assertRaisesRegex(RuntimeError,'body failure'):
                with isolated_zap_job(sys.executable):
                    args=popen.call_args.args[0];home=Path(args[args.index('-dir')+1])
                    raise RuntimeError('body failure')
            self.assertFalse(home.exists())
            kill.assert_any_call(process.pid,signal.SIGTERM)
            client._session.close.assert_called_once()

    def test_startup_exit_has_no_client_or_shared_fallback(self):
        with ExitStack() as stack:
            process,popen,kill,health,client,factory=self.environment(stack)
            process.poll.return_value=1
            with self.assertRaises(ZAPJobError):
                with isolated_zap_job(sys.executable):
                    self.fail('must not yield')
            factory.assert_not_called();health.get.assert_not_called()
            kill.assert_called()

    def test_startup_timeout_stops_process(self):
        with ExitStack() as stack:
            process,popen,kill,health,client,factory=self.environment(stack)
            stack.enter_context(patch('services.vulnerability_scanner.zap_job.time.monotonic',side_effect=[0,31]))
            with self.assertRaises(ZAPJobError):
                with isolated_zap_job(sys.executable):
                    self.fail('must not yield')
            factory.assert_not_called();kill.assert_called()

    def test_readiness_rejects_redirect_and_api_error_until_deadline(self):
        for response in [Mock(status_code=302),Mock(status_code=200,json=lambda:{'code':'bad_key'})]:
            with self.subTest(response=response), ExitStack() as stack:
                process,popen,kill,health,client,factory=self.environment(stack)
                health.get.return_value=response
                stack.enter_context(patch('services.vulnerability_scanner.zap_job.time.monotonic',side_effect=[0,1,31]))
                stack.enter_context(patch('services.vulnerability_scanner.zap_job.time.sleep'))
                with self.assertRaises(ZAPJobError):
                    with isolated_zap_job(sys.executable):
                        self.fail('must not yield')
                factory.assert_not_called();kill.assert_called()
                self.assertFalse(health.get.call_args.kwargs['allow_redirects'])

    def test_invalid_platform_executable_and_deadline_fail_before_launch(self):
        with patch('services.vulnerability_scanner.zap_job.platform.system',return_value='Windows'), patch('services.vulnerability_scanner.zap_job.subprocess.Popen') as popen:
            with self.assertRaises(ZAPJobError):
                with isolated_zap_job(sys.executable): pass
            popen.assert_not_called()
        with patch('services.vulnerability_scanner.zap_job.platform.system',return_value='Linux'), patch('services.vulnerability_scanner.zap_job.subprocess.Popen') as popen:
            for executable,deadline in [('relative-zap',30),(sys.executable,0),(sys.executable,61)]:
                with self.assertRaises(ZAPJobError):
                    with isolated_zap_job(executable,deadline): pass
            popen.assert_not_called()

    def test_stop_escalates_to_kill_when_graceful_exit_times_out(self):
        process=Mock(pid=12345)
        process.wait.side_effect=[subprocess.TimeoutExpired('zap',5),0]
        with patch('services.vulnerability_scanner.zap_job.os.killpg',create=True) as kill, patch('services.vulnerability_scanner.zap_job.signal.SIGKILL',9,create=True):
            _stop_process(process)
            kill.assert_any_call(process.pid,signal.SIGKILL)
        self.assertEqual(process.wait.call_count,2)

    def test_cleanup_failure_propagates(self):
        process=Mock(pid=12345)
        with patch('services.vulnerability_scanner.zap_job.os.killpg',side_effect=PermissionError('denied'),create=True):
            with self.assertRaises(PermissionError):
                _stop_process(process)

    def test_closed_activation_never_launches_process(self):
        orchestrator=object.__new__(ScanOrchestrator)
        with patch('services.vulnerability_scanner.zap_job.subprocess.Popen') as popen:
            with self.assertRaises(TargetAuthorizationRequired):
                orchestrator._run_zap_scan('https://example.com',Mock())
            popen.assert_not_called()

    def test_client_readiness_error_closes_session_without_logging_key(self):
        from services.vulnerability_scanner.zap_client import ZAPClient
        from requests import ConnectionError as RequestConnectionError
        session=Mock()
        session.get.side_effect=RequestConnectionError('secret-key-in-query')
        with patch('services.vulnerability_scanner.zap_client.requests.Session',return_value=session), patch('services.vulnerability_scanner.zap_client.logger') as logger:
            with self.assertRaises(ConnectionError) as failure:
                ZAPClient(api_key='secret-key-in-query',host='127.0.0.1',port=8080,use_https=False)
            self.assertNotIn('secret-key-in-query',str(failure.exception))
            self.assertNotIn('secret-key-in-query',str(logger.mock_calls))
        session.close.assert_called_once()

    def test_client_rejects_200_api_error_payload(self):
        from services.vulnerability_scanner.zap_client import ZAPClient
        session=Mock()
        session.get.return_value=Mock(status_code=200,json=lambda:{'code':'bad_key'})
        with patch('services.vulnerability_scanner.zap_client.requests.Session',return_value=session):
            with self.assertRaises(ConnectionError):
                ZAPClient(api_key='test-only',host='127.0.0.1',port=8080,use_https=False)
        session.close.assert_called_once()
