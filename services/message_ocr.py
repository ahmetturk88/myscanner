"""Read the text of a message screenshot on our own server (Tesseract), for the message check.

The image is checked (PNG, JPEG or WebP, at most 8 MB and 40 million pixels), turned grey,
inverted when it is a dark-mode screenshot and enlarged when small, then read by Tesseract
in Turkish, English and Arabic. It is handled in a temporary folder that is deleted at once;
it is never kept, logged or sent anywhere else.
"""
import io
import shutil
import subprocess
import tempfile
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 40_000_000
FORMATS = {'PNG', 'JPEG', 'WEBP'}
LANGUAGES = 'tur+eng+ara'
TIMEOUT = 25


class OCRError(Exception):
    """A readable reason: bad_image, too_large, unavailable or no_text."""


def available():
    return shutil.which('tesseract') is not None


def _prepare(data):
    from PIL import Image, ImageOps, ImageStat
    if len(data) > MAX_BYTES:
        raise OCRError('too_large')
    try:
        with Image.open(io.BytesIO(data)) as probe:
            if probe.format not in FORMATS or probe.width * probe.height > MAX_PIXELS:
                raise OCRError('bad_image' if probe.format not in FORMATS else 'too_large')
            probe.verify()
        image = Image.open(io.BytesIO(data))
        image = ImageOps.exif_transpose(image).convert('L')
    except OCRError:
        raise
    except Exception:
        raise OCRError('bad_image') from None
    if ImageStat.Stat(image).mean[0] < 110:  # dark mode: light text on a dark background
        image = ImageOps.invert(image)
    if image.width < 1100:  # small screenshots read much better enlarged
        scale = min(3, 1100 / max(image.width, 1))
        image = image.resize((int(image.width * scale), int(image.height * scale)))
    return ImageOps.autocontrast(image)


def read_text(data, run=None):
    """The text in a screenshot. `run` replaces the Tesseract call in tests."""
    image = _prepare(data)
    if run is None and not available():
        raise OCRError('unavailable')
    with tempfile.TemporaryDirectory(prefix='msg-ocr-') as folder:
        path = Path(folder) / 'message.png'
        image.save(path)
        if run is not None:
            text = run(path)
        else:
            try:
                done = subprocess.run(['tesseract', str(path), 'stdout', '-l', LANGUAGES, '--psm', '6'],
                                      capture_output=True, timeout=TIMEOUT, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise OCRError('unavailable') from None
            if done.returncode != 0:
                raise OCRError('unavailable')
            text = done.stdout.decode('utf-8', 'replace')
    lines = [' '.join(line.split()) for line in text.splitlines()]
    text = '\n'.join(line for line in lines if line).strip()
    if len(text) < 4:
        raise OCRError('no_text')
    return text[:6000]
