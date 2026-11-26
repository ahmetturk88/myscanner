"""Read the text of a message screenshot on our own server (Tesseract), for the message check.

The image is checked (a single PNG, JPEG or WebP frame, at most 8 MB and 20 million pixels), turned grey,
inverted when it is a dark-mode screenshot and enlarged when small, then read by Tesseract
in Turkish, English and Arabic. It is handled in a temporary folder that is deleted at once;
it is never kept, logged or sent anywhere else.

Tesseract runs with hard limits (memory, CPU time, one thread) and at most two readings at
once per server process; a third is told to try again instead of queueing up.
"""
import io
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 20_000_000
FORMATS = {'PNG', 'JPEG', 'WEBP'}
LANGUAGES = 'tur+eng+ara'
TIMEOUT = 25
MEMORY = 768 * 1024 * 1024  # bytes of address space Tesseract may use
CPU_SECONDS = 30
_SLOTS = threading.BoundedSemaphore(2)
WAIT = 5  # seconds to wait for a free slot


class OCRError(Exception):
    """A readable reason: bad_image, too_large, busy, unavailable or no_text."""


def available():
    return shutil.which('tesseract') is not None


def _prepare(data):
    from PIL import Image, ImageOps, ImageStat
    if len(data) > MAX_BYTES:
        raise OCRError('too_large')
    try:
        with Image.open(io.BytesIO(data)) as probe:
            if probe.format not in FORMATS or getattr(probe, 'n_frames', 1) != 1:
                raise OCRError('bad_image')  # animated images are not screenshots
            if probe.width * probe.height > MAX_PIXELS:
                raise OCRError('too_large')
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
        scale = min(3, 1100 / max(image.width, 1), (MAX_PIXELS / max(image.width * image.height, 1)) ** 0.5)
        image = image.resize((int(image.width * scale), int(image.height * scale)))
    return ImageOps.autocontrast(image)


def _command(path):
    """Tesseract under hard limits. prlimit (util-linux) sets them in the child, which is safe in a threaded
    server, unlike a Python preexec_fn."""
    command = ['tesseract', str(path), 'stdout', '-l', LANGUAGES, '--psm', '6']
    limiter = shutil.which('prlimit')
    if limiter:
        command = [limiter, f'--as={MEMORY}', f'--cpu={CPU_SECONDS}', '--core=0', '--'] + command
    return command


def _tesseract(path):
    import os
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'OMP_THREAD_LIMIT': '1', 'LANG': 'C.UTF-8'}
    try:
        done = subprocess.run(_command(path), capture_output=True, timeout=TIMEOUT, check=False, env=env,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise OCRError('unavailable') from None
    if done.returncode != 0:
        raise OCRError('unavailable')
    return done.stdout.decode('utf-8', 'replace')


def read_text(data, run=None):
    """The text in a screenshot. `run` replaces the Tesseract call in tests."""
    image = _prepare(data)
    if run is None and not available():
        raise OCRError('unavailable')
    if not _SLOTS.acquire(timeout=WAIT):
        raise OCRError('busy')
    try:
        with tempfile.TemporaryDirectory(prefix='msg-ocr-') as folder:
            path = Path(folder) / 'message.png'
            image.save(path)
            text = (run or _tesseract)(path)
    finally:
        _SLOTS.release()
    lines = [' '.join(line.split()) for line in text.splitlines()]
    text = '\n'.join(line for line in lines if line).strip()
    if len(text) < 4:
        raise OCRError('no_text')
    return text[:6000]
