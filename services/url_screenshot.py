"""Page previews: captured by the worker, served only to the scan owner.

The worker asks the url.vet browser (already behind the provider egress
gateway) for a PNG, re-encodes it as a bounded JPEG and stores it next to
the reports. The viewer's browser only ever loads it from MyScanner, so no
third party learns which URL was scanned or who looked at it.
"""
import io
import logging
import os
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MAX_SOURCE_PIXELS = 1920 * 4320
PREVIEW_WIDTH = 1366
PREVIEW_MAX_HEIGHT = 2048
CAPTURE_TIMEOUT = (5, 45)
RETENTION_DAYS = 30


def screenshot_dir():
    configured = os.environ.get('SCREENSHOT_DIR')
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / 'reports' / 'screenshots'


def screenshot_path(scan_id):
    return screenshot_dir() / f'{int(scan_id)}.jpg'


def _download(url, base_url):
    with requests.get(f'{base_url.rstrip("/")}/api/v1/screenshot', params={'url': url},
                      timeout=CAPTURE_TIMEOUT, stream=True, allow_redirects=False) as response:
        if response.status_code != 200:
            return None
        content = bytearray()
        for chunk in response.iter_content(64 * 1024):
            content.extend(chunk)
            if len(content) > MAX_DOWNLOAD_BYTES:
                return None
    return bytes(content)


def _to_jpeg(png):
    from PIL import Image
    if not png.startswith(PNG_SIGNATURE):
        return None
    with Image.open(io.BytesIO(png)) as image:
        if image.format != 'PNG' or image.width * image.height > MAX_SOURCE_PIXELS:
            return None
        image = image.convert('RGB')
        image.thumbnail((PREVIEW_WIDTH, PREVIEW_MAX_HEIGHT))
        output = io.BytesIO()
        image.save(output, 'JPEG', quality=80, optimize=True)
    return output.getvalue()


def capture_screenshot(url, scan_id, base_url=None):
    """Store a preview for scan_id. Never raises: a missing preview is not a finding."""
    base_url = base_url or os.environ.get('URLVET_URL')
    if not base_url:
        return False
    try:
        png = _download(url, base_url)
        jpeg = _to_jpeg(png) if png else None
        if not jpeg:
            return False
        target = screenshot_path(scan_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_suffix('.partial')
        partial.write_bytes(jpeg)
        os.replace(partial, target)
        return True
    except Exception as error:
        logger.warning('Screenshot unavailable; scan_id=%s; error=%s', scan_id, type(error).__name__)
        return False


def prune_screenshots(days=RETENTION_DAYS):
    directory = screenshot_dir()
    if not directory.is_dir():
        return 0
    cutoff, removed = time.time() - days * 86400, 0
    for path in directory.glob('*.jpg'):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def remove_screenshot(scan_id):
    screenshot_path(scan_id).unlink(missing_ok=True)
