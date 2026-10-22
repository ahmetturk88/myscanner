import os
import re
import tempfile

from werkzeug.utils import secure_filename

# The file scanner accepts any type: the analyzer identifies files by their
# bytes, not their names. The sandbox keeps its own allow-list.
FILE_MAX_SIZE = 50 * 1024 * 1024
CHUNK = 1024 * 1024
_EXTENSION = re.compile(r'^[a-z0-9]{1,10}$')


class UploadValidationError(ValueError):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def _too_large(max_size):
    return UploadValidationError(f'File too large. Max: {max_size // (1024 * 1024)} MB', 413)


def _safe_name(file, allowed_extensions):
    """A storage-safe display name; the extension comes from the original name.

    secure_filename drops non-ASCII letters, so "فاتورة.pdf" would lose its stem
    and its dot; the extension is read before that and the stem falls back to "file".
    """
    if file is None:
        raise UploadValidationError('No file provided')
    if not file.filename:
        raise UploadValidationError('No file selected')
    original = os.path.basename(file.filename.replace('\\', '/'))
    stem, dot, extension = original.rpartition('.')
    if not dot:
        stem, extension = original, ''
    extension = extension.lower()
    if not _EXTENSION.match(extension):
        extension = ''
    if allowed_extensions is not None and extension not in allowed_extensions:
        raise UploadValidationError('File type not allowed')
    stem = secure_filename(stem).strip('.')[:180] or 'file'
    return f'{stem}.{extension}' if extension else stem


def read_validated_upload(file, allowed_extensions, max_size):
    """Name and bytes of an upload; allowed_extensions=None accepts any type."""
    filename = _safe_name(file, allowed_extensions)
    content = file.stream.read(max_size + 1)
    if len(content) > max_size:
        raise _too_large(max_size)
    if not content:
        raise UploadValidationError('File is empty')
    return filename, content


def store_validated_upload(file, max_size, folder, allowed_extensions=None):
    """Copy an upload to a private temporary file in chunks; returns (name, path).

    The whole file is never held in memory, and nothing is kept on any failure.
    """
    filename = _safe_name(file, allowed_extensions)
    path = _temporary_path(filename, folder)
    try:
        size = 0
        with open(path, 'wb') as output:
            while True:
                chunk = file.stream.read(min(CHUNK, max_size + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    raise _too_large(max_size)
                output.write(chunk)
        if size == 0:
            raise UploadValidationError('File is empty')
        return filename, path
    except BaseException:
        remove_temporary_upload(path)
        raise


def _temporary_path(filename, folder):
    os.makedirs(folder, exist_ok=True)
    # Only the validated extension enters the path; the basename is random.
    extension = filename.rpartition('.')[2] if '.' in filename else 'bin'
    descriptor, path = tempfile.mkstemp(prefix='scan-', suffix='.' + extension, dir=os.path.abspath(folder))
    os.close(descriptor)
    return path


def save_temporary_upload(content, filename, folder):
    path = _temporary_path(filename, folder)
    try:
        with open(path, 'wb') as output:
            output.write(content)
        return path
    except Exception:
        remove_temporary_upload(path)
        raise


def remove_temporary_upload(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
