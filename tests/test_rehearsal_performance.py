import unittest
from scripts.rehearsal_performance import memory_bytes,percentile,valid_base,compose
class MeasurementTests(unittest.TestCase):
    def test_docker_memory_units(self):
        self.assertEqual(memory_bytes('1.5GiB'),1610612736);self.assertEqual(memory_bytes('512MiB'),536870912);self.assertEqual(memory_bytes('1GB'),1000000000)
        with self.assertRaises(ValueError):memory_bytes('unknown')
    def test_percentiles_and_no_success_do_not_fabricate_latency(self):
        self.assertEqual(percentile(list(range(1,101)),95),95);self.assertIsNone(percentile([],95))
    def test_measurement_refuses_remote_or_authenticated_urls(self):
        for url in ('https://example.com:8443','http://localhost:8443','https://user:secret@localhost:8443','https://localhost:8443/path','https://localhost:8443?key=x'):
            with self.assertRaises(ValueError):valid_base(url)
        self.assertEqual(valid_base('https://localhost:8443/'),'https://localhost:8443')
        self.assertIn('compose.app-egress.yml',compose())
if __name__=='__main__':unittest.main()
