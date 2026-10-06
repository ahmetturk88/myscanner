"""Exercise stored account/history data in actual templates and exported HTML."""
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace as NS
from collections import defaultdict
import json
import shutil
import subprocess
import unittest
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape
from services.vulnerability_scanner.report_generator import ReportGenerator, REPORTLAB_AVAILABLE
ROOT=Path(__file__).resolve().parents[1]
PAYLOAD='\'"\\\n</script><img src=x onerror="alert(1)"><svg onload="alert(1)">&'
class StoredDisplayTests(unittest.TestCase):
    def setUp(self):
        self.env=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=select_autoescape(['html']))
        self.user=NS(id=1,username=PAYLOAD,email=PAYLOAD,is_authenticated=True,is_admin=True,is_verified=True,date_joined=datetime(2026,1,1),scans=[])
        self.scan=NS(id=2,url='javascript:alert(1)',owner=self.user,verdict='unknown',date_posted=datetime(2026,1,1))
        self.env.globals.update(url_for=lambda endpoint,**kw:'/static/'+kw['filename'] if 'filename' in kw else '/route/'+endpoint,csrf_token=lambda:'test',get_flashed_messages=lambda **kw:[(PAYLOAD,PAYLOAD)],current_user=self.user,request=NS(path='/admin',query_string=b'',args={}))
    def test_admin_actions_keep_labels_as_literal_data(self):
        other=NS(**{**vars(self.user),'id':7,'is_admin':False})
        html=self.env.get_template('admin.html').render(users=[other],scans=[self.scan]);soup=BeautifulSoup(html,'html.parser')
        button=soup.select_one('[data-delete-kind="user"]')
        self.assertEqual(button['data-delete-label'],PAYLOAD)
        self.assertNotIn('onclick',button.attrs)
        link=soup.select_one('[data-web-url]');self.assertEqual(link['data-web-url'],self.scan.url);self.assertNotIn('href',link.attrs)
        self.assertFalse(soup.find_all('svg'))
        self.assertEqual(json.loads(soup.select_one('#flash-data').get_text()),[{'cat':PAYLOAD,'msg':PAYLOAD}])
        for element in soup.select('[onclick]'):self.assertNotIn(PAYLOAD,element['onclick'])
    def test_profile_does_not_render_executable_saved_link(self):
        html=self.env.get_template('profile.html').render(scans=[self.scan]);soup=BeautifulSoup(html,'html.parser');link=soup.select_one('[data-web-url]')
        self.assertEqual(link.get_text(strip=True),self.scan.url);self.assertNotIn('href',link.attrs)
        self.assertFalse(soup.find_all('svg'))
    def test_admin_log_flash_json_round_trip(self):
        logs=NS(items=[],total=0,pages=1,page=1,has_prev=False,has_next=False,iter_pages=lambda **kw:[])
        html=self.env.get_template('admin_logs.html').render(logs=logs,stats=defaultdict(int));soup=BeautifulSoup(html,'html.parser')
        self.assertEqual(json.loads(soup.select_one('#flash-data').get_text()),[{'cat':PAYLOAD,'msg':PAYLOAD}])
        self.assertFalse(soup.find_all('svg'))
    def test_vulnerability_status_button_does_not_embed_uuid_in_code(self):
        scan=NS(target=PAYLOAD,scan_type='quick',status='running',critical_count=0,high_count=0,medium_count=0,total_vulnerabilities=0,risk_score=0,created_at=datetime(2026,1,1),scan_uuid=PAYLOAD)
        html=self.env.get_template('vuln_scan.html').render(scans=[scan],recent_scans=[scan],stats=defaultdict(int),scanners_status={'zap':{'status':'offline'},'openvas':{'status':'offline'}});soup=BeautifulSoup(html,'html.parser')
        button=soup.select_one('[data-check-scan]');self.assertIsNotNone(button);self.assertEqual(button['data-check-scan'],PAYLOAD);self.assertNotIn('onclick',button.attrs)
    @unittest.skipUnless(shutil.which('node'),'Node.js is needed for saved link/action execution tests')
    def test_native_actions_and_safe_saved_links(self):
        r=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_saved_display_xss.cjs')],capture_output=True,text=True,encoding='utf-8',check=True);self.assertIn('checks passed',r.stdout)
class ReportTests(unittest.TestCase):
    def setUp(self):
        self.generator=ReportGenerator.__new__(ReportGenerator)
        vuln={'title':PAYLOAD,'description':PAYLOAD,'solution':PAYLOAD,'affected_component':PAYLOAD,'cvss_score':5,'severity':'high'}
        self.data={'scan_info':{'target':PAYLOAD,'scan_type':PAYLOAD,'scan_uuid':PAYLOAD,'duration_minutes':PAYLOAD,'created_at':PAYLOAD},'generated_at':PAYLOAD,'statistics':{'total':1,'critical':0,'high':1,'medium':0,'low':0,'info':0,'risk_score':5,'sources':PAYLOAD},'vulnerabilities_by_severity':{'high':[vuln]},'all_vulnerabilities':[vuln],'remediation':{'critical':[{'title':PAYLOAD,'action':PAYLOAD}],'immediate_actions':[PAYLOAD],'long_term_actions':[PAYLOAD]}}
    def test_exported_html_preserves_text_without_injected_elements(self):
        html=self.generator._generate_html(self.data,False,True).decode('utf-8');soup=BeautifulSoup(html,'html.parser')
        self.assertFalse(soup.find_all(['img','svg','iframe','object']))
        self.assertEqual(len(soup.find_all('script')),1)
        self.assertIn(PAYLOAD,soup.title.get_text());self.assertIn(PAYLOAD,soup.get_text())
        for e in soup.select('[onclick]'):self.assertEqual(e['onclick'],'toggleVuln(this)')
        self.assertEqual(self.data['scan_info']['target'],PAYLOAD)
    @unittest.skipUnless(REPORTLAB_AVAILABLE,'ReportLab is needed for PDF export checks')
    def test_pdf_handles_literal_markup_in_metadata(self):
        pdf=self.generator._generate_pdf(self.data,False);self.assertTrue(pdf.startswith(b'%PDF'))
