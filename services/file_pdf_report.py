"""MyScanner A4 file evidence report. No remote resources or active PDF links."""
from io import BytesIO
from datetime import datetime, timezone
import json
import math
import unicodedata
import reportlab
from pathlib import Path
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, CondPageBreak

NAVY=colors.HexColor('#08111f')
CARD=colors.HexColor('#102135')
LINE=colors.HexColor('#294058')
CYAN=colors.HexColor('#84dfec')
WHITE=colors.HexColor('#edf5ff')
MUTED=colors.HexColor('#b0c1d6')
AMBER=colors.HexColor('#f4c77c')
RED=colors.HexColor('#ff929e')
WIDTH=A4[0]-84
# Embed the fonts bundled with ReportLab so layout is consistent on Windows/VPS.
FONT_DIR=Path(reportlab.__file__).parent/'fonts'
for name,file in [('MSFile','Vera.ttf'),('MSFileBold','VeraBd.ttf')]:
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(name,str(FONT_DIR/file)))


def safe(value,limit=800):
    text='Not reported' if value is None or value=='' else str(value)
    # Built-in PDF fonts cannot render arbitrary Unicode. Preserve code points
    # as readable escapes rather than silently dropping them or drawing boxes.
    text=''.join(c for c in text if unicodedata.category(c)!='So' and c not in ('\ufe0f','\u200d'))
    text=text[:limit].encode('ascii','backslashreplace').decode('ascii')
    return escape(text[:limit])


def generate_file_report(report):
    styles={name:ParagraphStyle(name,fontName='MSFile',fontSize=size,leading=leading,textColor=color,spaceAfter=gap,splitLongWords=True)
            for name,size,leading,color,gap in [('body',9,14,MUTED,7),('small',8,12,MUTED,5),('label',8,12,CYAN,7),('title',29,34,WHITE,15),('heading',16,21,WHITE,12),('subhead',11,15,WHITE,7)]}
    for key in ('title','heading','subhead'):
        styles[key].fontName='MSFileBold'
    def p(value,style='body',limit=800):return Paragraph(safe(value,limit),styles[style])
    def heading(number,title):return [CondPageBreak(110),Spacer(1,18),p(number+' / '+title.upper(),'label'),p(title,'heading')]
    def table(rows,widths=None):
        t=Table([[p(k,'small',120),p(v,'body',1000)] for k,v in rows],colWidths=widths or [130,WIDTH-130],hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),CARD),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),8),('LINEBELOW',(0,0),(-1,-1),.4,LINE)]))
        return t
    def items(values,default='No entries reported.'):
        if not isinstance(values,list) or not values:return [p(default)]
        return [p('- '+str(v),limit=600) for v in values[:20]]
    mb=report.get('malwarebazaar')
    if not isinstance(mb,dict):mb={}
    malicious=report.get('verdict')=='malicious' or (mb.get('status')=='matched' and mb.get('is_malicious') is True)
    partial=report.get('coverage_status')!='completed' or bool(report.get('missing_checks')) or mb.get('status') not in ('matched','not_found')
    risk=report.get('verdict') in ('suspicious','high_risk')
    title='Known threat reported' if malicious else 'Indicators need review' if risk else 'Evidence needs verification' if partial else 'No indicators reported'
    score=report.get('security_score')
    available=type(score) in (int,float) and math.isfinite(score) and 0<=score<=100 and not partial and report.get('verdict') in ('malicious','high_risk','suspicious','safe','not_found')
    status='Matched malicious hash' if mb.get('status')=='matched' and mb.get('is_malicious') is True else 'No dataset match' if mb.get('status')=='not_found' else 'Not verified'
    story=[p('MYSCANNER / FILE INTELLIGENCE','label'),p('File evidence\nreport'.replace('\n',' '),'title'),p('Static inspection. Source-aware findings. A clear record of what was actually reported.'),Spacer(1,20)]
    verdict=Paragraph(safe(title),ParagraphStyle('verdict',parent=styles['heading'],textColor=RED if malicious else AMBER if partial or risk else CYAN))
    story.append(verdict)
    story.append(p('Keep the file unexecuted and review the confirmed evidence.' if malicious else 'Review this report in context. Neither a high index nor a dataset negative establishes that a file is safe to open.'))
    story.append(table([('File',report.get('filename')),('Reported at',report.get('scanned_at') or report.get('analyzed_at')),('Size (bytes)',report.get('file_size_bytes',report.get('file_size'))),('Verdict',report.get('verdict')),('Coverage','Limited evidence' if partial else 'Configured checks returned'),('Local heuristic index',str(score)+' / 100' if available else 'Not assigned - evidence is incomplete or unavailable')]))
    story+=heading('01','Source evidence')
    meta=report.get('metadata') if isinstance(report.get('metadata'),dict) else {}
    patterns=report.get('yara') if isinstance(report.get('yara'),dict) else {}
    story.append(table([('MalwareBazaar',status),('Provider reason',{'credential_missing':'Credential not configured','credential_unreadable':'Credential file unavailable','authentication_rejected':'Authentication rejected','rate_limited':'Provider rate limit reached','timeout':'Provider request timed out'}.get(mb.get('reason'),mb.get('reason'))),('Local metadata','Unavailable' if meta.get('error') or meta.get('metadata_error') else 'Returned' if meta else 'Not reported'),('Byte patterns','Not verified' if not isinstance(patterns.get('matched_rules'),list) else str(len(patterns['matched_rules']))+' local patterns reported')]))
    story.append(p('A MalwareBazaar negative applies only to the queried hash and dataset. Byte patterns are local heuristics, not a YARA engine or sandbox verdict.','small'))
    story+=heading('02','Coverage and next steps')
    story+=items(report.get('missing_checks'),'No missing checks were reported by the configured sources.')
    story+=items(report.get('recommendations'),'Review the source status before deciding how to handle this file.')
    story+=[PageBreak()]+heading('03','File identity and fingerprints')
    ft=report.get('file_type') if isinstance(report.get('file_type'),dict) else {}
    story.append(table([('Extension',ft.get('extension')),('Observed format',ft.get('actual_type')),('MIME observation',ft.get('mime_type')),('Format mismatch',ft.get('is_spoofed')),('Detection scope',ft.get('detection_scope'))]))
    hashes=report.get('hashes') if isinstance(report.get('hashes'),dict) else {}
    for key in ['sha256','sha512','sha1','md5','blake2b']:
        story.append(KeepTogether([Spacer(1,12),p(key.upper(),'label'),p(hashes.get(key),'body',160)]))
    story.append(p('Fingerprints identify the analyzed bytes. They do not assign a safety rating.','small'))
    story+=heading('04','Metadata and structure')
    rows=[]
    for key,value in list(meta.items())[:24]:
        if isinstance(value,(dict,list)):
            value=json.dumps(value,ensure_ascii=True,default=str)
        rows.append((key.replace('_',' ').title(),value))
    story.append(table(rows) if rows else p('No metadata fields reported.'))
    story+=heading('05','Reported findings')
    story+=items(patterns.get('matched_rules'),'No byte patterns reported; this does not establish safety.')
    story+=items(meta.get('suspicious'),'No metadata findings reported.')
    if malicious:story.append(table([('Provider signature',mb.get('signature')),('Provider first seen',mb.get('first_seen')),('Provider tags',', '.join(map(str,mb.get('tags',[]))) if isinstance(mb.get('tags'),list) else None)]))
    iocs=report.get('iocs') if isinstance(report.get('iocs'),dict) else {}
    story+=heading('06','Embedded indicators')
    for key in ['urls','domains','ipv4','ipv6','emails','onion_addresses','bitcoin_addresses']:
        values=iocs.get(key)
        if isinstance(values,list) and values:
            story.append(p(key.replace('_',' ').title(),'subhead'));story+=items(values)
    if not any(isinstance(v,list) and v for v in iocs.values()):story.append(p('No indicator entries reported. This is not a negative reputation finding.'))
    story+=heading('07','Scope and limitations')
    story+=items(report.get('warnings'),'No additional warnings reported.')
    story.append(p(report.get('scope') or 'Static evidence only. No execution, sandbox or multi-engine antivirus scan.'))
    story.append(p('This PDF contains selected, bounded evidence. Export JSON for the full response. Non-ASCII characters are shown as Unicode escapes to preserve their identity.','small'))
    buffer=BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=64,bottomMargin=52,title='MyScanner File Evidence Report',author='MyScanner')
    def page(canvas,document):
        canvas.saveState();canvas.setFillColor(NAVY);canvas.rect(0,0,A4[0],A4[1],fill=1,stroke=0)
        canvas.setStrokeColor(LINE);canvas.line(42,A4[1]-43,A4[0]-42,A4[1]-43);canvas.line(42,38,A4[0]-42,38)
        canvas.setFont('MSFileBold',8);canvas.setFillColor(CYAN);canvas.drawString(42,A4[1]-30,'MYSCANNER')
        canvas.setFont('MSFile',8);canvas.setFillColor(MUTED);canvas.drawRightString(A4[0]-42,A4[1]-30,'FILE EVIDENCE / STATIC INSPECTION')
        canvas.drawString(42,24,'Generated '+datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))
        canvas.drawRightString(A4[0]-42,24,'PAGE '+str(document.page));canvas.restoreState()
    doc.build(story,onFirstPage=page,onLaterPages=page)
    buffer.seek(0);return buffer
