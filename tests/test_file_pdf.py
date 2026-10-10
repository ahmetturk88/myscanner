import io
from pathlib import Path
import unittest
from unittest.mock import patch
from flask import Flask
from flask_login import LoginManager, UserMixin
from itsdangerous import BadData
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader=None
from routes.file_pdf import file_pdf_bp
from services.file_pdf_receipts import issue_file_pdf_receipt, load_file_pdf_receipt
from services.file_pdf_report import generate_file_report

SECRET='test-session-secret'
REPORT={'filename':'sample.py','file_size':24,'verdict':'unknown','coverage_status':'partial','security_score':100,'scanned_at':'2026-10-10T06:00:00+00:00','malwarebazaar':{'status':'unavailable','reason':'authentication_rejected'},'missing_checks':['Hash reputation unavailable'],'hashes':{'sha256':'a'*64},'file_type':{'extension':'py','actual_type':'txt','mime_type':'text/plain'},'metadata':{'language':'Python','lines':1,'suspicious':[]},'yara':{'matched_rules':[]},'iocs':{'urls':[]},'recommendations':['Review the source status.']}

class FilePDFTests(unittest.TestCase):
    def test_receipt_binds_owner_and_detects_edits(self):
        token=issue_file_pdf_receipt(REPORT,'1',SECRET)
        self.assertEqual(load_file_pdf_receipt(token,'1',SECRET)['filename'],'sample.py')
        for value,user in [(token,'2'),(token+'x','1'),('', '1')]:
            with self.assertRaises(BadData):load_file_pdf_receipt(value,user,SECRET)
    def test_receipt_expires_and_bounds_payload(self):
        with patch('itsdangerous.timed.time.time',return_value=1000):token=issue_file_pdf_receipt(REPORT,'1',SECRET)
        with patch('itsdangerous.timed.time.time',return_value=5000):
            with self.assertRaises(BadData):load_file_pdf_receipt(token,'1',SECRET)
        token=issue_file_pdf_receipt({**REPORT,'metadata':{'items':['x'*5000]*1000}},'1',SECRET)
        data=load_file_pdf_receipt(token,'1',SECRET)
        self.assertLessEqual(len(data['metadata']['items']),40)
        self.assertLess(len(token),200000)
    @unittest.skipUnless(PdfReader, "pypdf is required for PDF text checks")
    def test_partial_score_not_presented_as_100(self):
        reader=PdfReader(generate_file_report(REPORT));text='\n'.join(page.extract_text() for page in reader.pages)
        self.assertIn('Evidence needs verification',text);self.assertIn('Not assigned',text);self.assertNotIn('100 / 100',text)
        self.assertIn('a'*64,text.replace('\n',''))
        self.assertGreaterEqual(len(reader.pages),2)
    @unittest.skipUnless(PdfReader, "pypdf is required for PDF text checks")
    def test_confirmed_threat_overrides_partial_title_and_has_no_active_links(self):
        report={**REPORT,'filename':'<script>file</script>','malwarebazaar':{'status':'matched','is_malicious':True,'signature':'Fixture threat'},'iocs':{'urls':['http://127.0.0.1/']}}
        reader=PdfReader(generate_file_report(report));text='\n'.join(p.extract_text() for p in reader.pages)
        self.assertIn('Known threat reported',text);self.assertIn('<script>file</script>',text)
        self.assertFalse(any(page.get('/Annots') for page in reader.pages))
    @unittest.skipUnless(PdfReader, "pypdf is required for PDF text checks")
    def test_long_nested_data_paginates(self):
        report={**REPORT,'metadata':{'member'+str(i):'x'*1000 for i in range(24)},'warnings':['<img onerror=alert(1)>']}
        reader=PdfReader(generate_file_report(report))
        self.assertLessEqual(len(reader.pages),15)
        self.assertIn('Scope and limitations','\n'.join(p.extract_text() for p in reader.pages))

class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__);self.app.config.update(SECRET_KEY=SECRET,TESTING=True)
        login=LoginManager(self.app)
        class User(UserMixin):id='1'
        @login.user_loader
        def user(uid):return User() if uid=='1' else None
        self.app.register_blueprint(file_pdf_bp);self.client=self.app.test_client()
    def signin(self):
        with self.client.session_transaction() as session:session['_user_id']='1';session['_fresh']=True
    def test_anonymous_and_foreign_receipts_are_rejected(self):
        token=issue_file_pdf_receipt(REPORT,'2',SECRET)
        self.assertEqual(self.client.post('/api/file-report/pdf',json={'receipt':token}).status_code,401)
        self.signin();self.assertEqual(self.client.post('/api/file-report/pdf',json={'receipt':token}).status_code,400)
    def test_owner_download_is_private_pdf(self):
        self.signin();token=issue_file_pdf_receipt(REPORT,'1',SECRET)
        response=self.client.post('/api/file-report/pdf',json={'receipt':token})
        self.assertEqual(response.status_code,200);self.assertEqual(response.mimetype,'application/pdf')
        self.assertTrue(response.data.startswith(b'%PDF'));self.assertIn('no-store',response.headers['Cache-Control'])
    def test_client_report_without_receipt_is_rejected(self):
        self.signin();self.assertEqual(self.client.post('/api/file-report/pdf',json=REPORT).status_code,400)

    def test_global_csrf_protects_the_pdf_post(self):
        from flask_wtf.csrf import CSRFProtect, generate_csrf
        CSRFProtect(self.app)
        @self.app.get('/csrf-fixture')
        def token():return generate_csrf()
        self.signin();receipt=issue_file_pdf_receipt(REPORT,'1',SECRET)
        self.assertEqual(self.client.post('/api/file-report/pdf',json={'receipt':receipt}).status_code,400)
        token=self.client.get('/csrf-fixture').get_data(as_text=True)
        self.assertEqual(self.client.post('/api/file-report/pdf',json={'receipt':receipt},headers={'X-CSRFToken':token}).status_code,200)

if __name__=='__main__':unittest.main()
