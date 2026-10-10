import json
import shutil
import subprocess
import unittest
from services.file_report_summary import file_report_summary

class SummaryTests(unittest.TestCase):
    def test_partial_archive_is_not_clean(self):
        d={'file_type':{'actual_type':'zip'},'metadata':{'is_archive':True,'num_files':5,'contains_script':True},'malwarebazaar':{'status':'not_found'},'assessment':{'score':60,'coverage_penalty':40}}
        result=file_report_summary(d)
        self.assertEqual(len(result),5)
        self.assertIn('not inspected',' '.join(result));self.assertIn('not a clean-file verdict',' '.join(result))
        self.assertIn('60/100',' '.join(result))
        if shutil.which('node'):
            js=subprocess.check_output(['node','-e',"console.log(JSON.stringify(require('./static/report_summary.js').lines('file',JSON.parse(process.argv[1]))))",json.dumps(d)],text=True)
            self.assertEqual(result,json.loads(js))
    def test_confirmed_threat_preserved_with_unknown_metadata(self):
        result=file_report_summary({'malwarebazaar':{'status':'matched','is_malicious':True}})
        self.assertIn('Keep the file unexecuted',' '.join(result))
        self.assertNotIn('safe to open',' '.join(result))
    def test_unknown_is_not_completed_evidence(self):
        text=' '.join(file_report_summary({}))
        self.assertIn('not established',text);self.assertIn('unavailable',text)
