import os
import tempfile

from werkzeug.utils import secure_filename

FILE_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z', 'js', 'py', 'ps1', 'sh', 'bat', 'vbs', 'scr', 'msi'}
FILE_MAX_SIZE = 10 * 1024 * 1024


class UploadValidationError(ValueError):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def read_validated_upload(file, allowed_extensions, max_size):
    if file is None:
        raise UploadValidationError('No file provided')
    if not file.filename:
        raise UploadValidationError('No file selected')
    filename = secure_filename(file.filename)
    if '.' not in filename:
        raise UploadValidationError('File type not allowed')
    stem, extension = filename.rsplit('.', 1)
    if not stem or extension.lower() not in allowed_extensions:
        raise UploadValidationError('File type not allowed')
    filename = stem[:180] + '.' + extension.lower()
    content = file.stream.read(max_size + 1)
    if len(content) > max_size:
        raise UploadValidationError(f'File too large. Max: {max_size // (1024 * 1024)} MB', 413)
    if not content:
        raise UploadValidationError('File is empty')
    return filename, content


def save_temporary_upload(content, filename, folder):
    os.makedirs(folder, exist_ok=True)
    # Only the validated extension enters the path; the basename is random.
    path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb', prefix='scan-', suffix='.' + filename.rsplit('.', 1)[1],
            dir=os.path.abspath(folder), delete=False,
        ) as output:
            path = output.name
            output.write(content)
        return path
    except Exception:
        if path:
            remove_temporary_upload(path)
        raise


def remove_temporary_upload(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
