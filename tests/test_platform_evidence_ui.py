from pathlib import Path
import shutil
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ProviderStateRenderingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'),'Node.js is required for actual renderer tests')
    def test_unavailable_and_negative_matches_remain_distinct_in_all_four_tools(self):
        result=subprocess.run(['node','tests/test_platform_evidence_ui.cjs'],cwd=ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
