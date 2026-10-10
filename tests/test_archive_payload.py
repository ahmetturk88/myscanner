import hashlib
import io
import os
import unittest
import zipfile
from unittest.mock import patch
from services.archive_payload import inspect_zip, payload_observations
from services.file_structure import zip_observations
from services.file_assessment import assess_file


def zipped(items, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as archive:
        for name, data in items:
            archive.writestr(name, data)
    return out.getvalue()


class PayloadTests(unittest.TestCase):
    def test_nested_hashes_and_literal_indicators(self):
        script=b'exec(user_input)'
        data=zipped([('nested.zip', zipped([('../never-written.py', script)]))])
        r=inspect_zip(data)
        self.assertEqual(r['inspected_members'],2)
        self.assertEqual(r['members'][1]['sha256'],hashlib.sha256(script).hexdigest())
        self.assertEqual(r['members'][1]['static_indicators'],['exec('])
        self.assertNotIn('malicious',r)

    def test_expanded_size_and_ratio_limits(self):
        r=inspect_zip(zipped([('bomb', b'A'*2_000_000)],zipfile.ZIP_DEFLATED))
        self.assertEqual(r['expanded_bytes'],0)
        self.assertEqual(r['status'],'partial')

    def test_shared_count_and_depth_budget(self):
        data=zipped([('leaf',b'x')])
        for _ in range(4):data=zipped([('nested.zip',data)])
        r=inspect_zip(data)
        self.assertEqual(r['inspected_members'],3)
        self.assertTrue(any('depth' in x for x in r['missing_checks']))
        r=inspect_zip(zipped([(str(n),b'x') for n in range(101)]))
        self.assertEqual(r['inspected_members'],100)
        self.assertEqual(r['status'],'partial')

    def test_crc_failure_never_assessed(self):
        data=bytearray(zipped([('test',b'unique-payload')]))
        offset=data.index(b'unique-payload');data[offset]^=1
        r=inspect_zip(bytes(data))
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['inspected_members'],0)

    def test_encrypted_and_symlink_skipped(self):
        data=bytearray(zipped([('secret',b'x')]))
        data[6]|=1
        central=data.index(b'PK\x01\x02');data[central+8]|=1
        self.assertEqual(inspect_zip(bytes(data))['inspected_members'],0)
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as a:
            info=zipfile.ZipInfo('link');info.external_attr=(0o120777<<16)
            a.writestr(info,'/etc/passwd')
        self.assertEqual(inspect_zip(out.getvalue())['inspected_members'],0)

    @unittest.skipUnless(os.name == 'posix', 'Linux resource isolation required')
    def test_process_limits_timeout_and_cleanup(self):
        import subprocess
        from pathlib import Path
        with patch('services.archive_payload.subprocess.run',side_effect=subprocess.TimeoutExpired('test',6)) as run:
            self.assertEqual(payload_observations(zipped([]))['status'],'unavailable')
            source=Path(run.call_args.args[0][-1])
            self.assertFalse(source.exists())

    @unittest.skipUnless(os.name == 'posix', 'Linux resource isolation required')
    def test_real_subprocess_and_score_coverage(self):
        r=zip_observations(zipped([('main.py',b'print(1)')]))
        self.assertEqual(r['payload_inspection']['inspected_members'],1)
        self.assertEqual(r['coverage_status'],'partial')
        score=assess_file({'security_score':100,'metadata':r,'coverage_status':'partial',
            'missing_checks':r['missing_checks'],'malwarebazaar':{'status':'not_found'}})
        self.assertEqual(score['score'],90)
        limited=zip_observations(zipped([('large',b'x'*1_100_000)]))
        score=assess_file({'security_score':100,'metadata':limited,'coverage_status':'partial',
            'missing_checks':limited['missing_checks'],'malwarebazaar':{'status':'not_found'}})
        self.assertEqual(score['score'],60)


if __name__=='__main__':unittest.main()
