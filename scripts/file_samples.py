"""Check the file scanner on harmless copies of common scam files.

Builds each sample in memory (a fake e-Devlet app, a cargo app that reads SMS, PDFs
with links, a web page) and prints the verdict the file scanner gives it. Nothing
harmful is made: the apps hold no code and the links are never opened. The listed
link is Google's own test page, which Web Risk reports as phishing on purpose.
Run it in the worker, which holds the Web Risk key:
    dc exec -T worker python scripts/file_samples.py
"""
import io
import logging
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GOOGLE_TEST_PHISHING = 'http://testsafebrowsing.appspot.com/s/phishing.html'


def axml(package, permissions):
    """A minimal binary AndroidManifest.xml (UTF-16 string pool)."""
    strings = ['manifest', 'package', package, 'uses-permission', 'name'] + permissions
    index = {s: i for i, s in enumerate(strings)}
    body = b''.join(struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\0\0' for s in strings)
    offsets, at = [], 0
    for s in strings:
        offsets.append(at)
        at += 2 + len(s) * 2 + 2
    body += b'\0' * (-len(body) % 4)
    pool_header = 28 + 4 * len(strings)
    pool = struct.pack('<HHIIIIII', 0x0001, 28, pool_header + len(body), len(strings), 0, 0, pool_header, 0)
    pool += b''.join(struct.pack('<I', o) for o in offsets) + body

    def element(tag, attributes):
        attrs = b''.join(struct.pack('<IIIHBBI', 0xFFFFFFFF, index[n], index[v], 8, 0, 3, index[v]) for n, v in attributes)
        return struct.pack('<HHIIIIIHHHHHH', 0x0102, 16, 36 + len(attrs), 1, 0xFFFFFFFF, 0xFFFFFFFF, index[tag], 20, 20, len(attributes), 0, 0, 0) + attrs

    document = pool + element('manifest', [('package', package)]) + b''.join(element('uses-permission', [('name', p)]) for p in permissions)
    return struct.pack('<HHI', 0x0003, 8, 8 + len(document)) + document


def apk(package, permissions):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('AndroidManifest.xml', axml(package, permissions))
        archive.writestr('classes.dex', b'dex\n035\0')
    return stream.getvalue()


def pdf_with_link(url):
    from pypdf import PdfWriter
    from pypdf.annotations import Link
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_annotation(page_number=0, annotation=Link(rect=(10, 10, 100, 50), url=url))
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def samples():
    """(file name, bytes, expected verdicts)"""
    accessibility = 'android.permission.BIND_ACCESSIBILITY_SERVICE'
    return [
        ('e-Devlet.apk', apk('com.edevlet.giris', [accessibility, 'android.permission.INTERNET']), {'suspicious'}),
        ('Kargo Takip.apk', apk('com.ptt.kargotakip', ['android.permission.RECEIVE_SMS']), {'suspicious'}),
        ('notes.apk', apk('org.example.notes', ['android.permission.INTERNET']), {'not_found', 'unknown'}),
        ('Fatura.pdf', pdf_with_link('https://garanti-bbva-giris.xyz/login'), {'suspicious', 'malicious'}),
        ('Odeme.pdf', pdf_with_link(GOOGLE_TEST_PHISHING), {'malicious'}),
        ('Brosur.pdf', pdf_with_link('https://www.garantibbva.com.tr/'), {'not_found', 'unknown'}),
        ('odeme.html', f'<html><body><a href="{GOOGLE_TEST_PHISHING}">Öde</a></body></html>'.encode(), {'malicious'}),
    ]


def main():
    logging.disable(logging.ERROR)
    from services.file_deep_analyzer import FileDeepAnalyzer
    analyzer, passed = FileDeepAnalyzer(), 0
    cases = samples()
    for name, content, expected in cases:
        report = analyzer.comprehensive_analysis(content, name)
        links = report.get('link_check') or {}
        ok = report['verdict'] in expected
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<16} {report['verdict']:<11} links={links.get('status', '-')}"
              f" listed={[x['host'] for x in links.get('listed', [])]} look-alike={[x['brand'] for x in links.get('lookalikes', [])]}")
    print(f'\n{passed} of {len(cases)} as expected')
    return 0 if passed == len(cases) else 1


if __name__ == '__main__':
    sys.exit(main())
