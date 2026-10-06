"""QR URL analysis backed by the shared evidence-based web assessment."""
from services.web_assessment import WebAssessment

class QRAnalyzer:
    def scan_url(self, url, api_key=None, include_provider=False):
        return WebAssessment().analyze(url, include_provider=include_provider)

    def scan_urls_batch(self, urls):
        if not isinstance(urls, list) or len(urls) > 20:
            raise ValueError('A batch must contain at most 20 URLs')
        return [self.scan_url(url) for url in urls]
