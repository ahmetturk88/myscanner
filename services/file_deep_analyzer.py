# =================================================================
# file_deep_analyzer.py - التحليل العميق الشامل للملفات (النسخة الكاملة المعدلة)
# =================================================================

import os
import hashlib
import re
import json
import tempfile
import subprocess
import zipfile
from services.file_structure import container_type, zip_observations
from services.archive_directory import archive_observations
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import logging
logger = logging.getLogger(__name__)
# محاولة استيراد المكتبات الاختيارية
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import filetype
    FILETYPE_AVAILABLE = True
except ImportError:
    FILETYPE_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False


class FileDeepAnalyzer:
    """التحليل العميق الشامل للملفات - نسخة كاملة بجميع الميزات"""
    
    def __init__(self, cache_dir: str = 'file_cache', use_exiftool: bool = False):
        """
        تهيئة المحلل
        
        Args:
            cache_dir: مجلد التخزين المؤقت
            use_exiftool: استخدام exiftool إن وجد (للميتاداتا الإضافية)
        """
        self.cache_dir = cache_dir
        self.use_exiftool = use_exiftool
        self.max_file_size = 50 * 1024 * 1024  # 50 MB
        self.max_file_size_stream = 500 * 1024 * 1024  # 500 MB للـ streaming
        os.makedirs(cache_dir, exist_ok=True)
        logger.info("✅ FileDeepAnalyzer initialized successfully")
        # قواعد IoC patterns (موسعة)
        self.IOC_PATTERNS = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'windows_path': r'[A-Za-z]:\\[^*|"<>?\n]*',
            'registry_key': r'HKEY_[A-Z_]+\\[^*|"<>?\n]*',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'onion': r'\b[a-z2-7]{16,56}\.onion\b',
            'telegram': r't\.me/[a-zA-Z0-9_]+',
            'discord': r'discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'
        }
        
        # القائمة البيضاء للمواقع الآمنة (لتقليل النتائج الخاطئة)
        self.SAFE_DOMAINS = [
            'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
            'linkedin.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'youtube.com', 'wikipedia.org', 'adobe.com', 'office.com',
            'onedrive.com', 'sharepoint.com', 'researchgate.net', 'academia.edu',
            'scholar.google.com', 'doi.org', 'springer.com', 'elsevier.com'
        ]
        
        # الكلمات الآمنة (لتفادي الكشف الخاطئ)
        self.SAFE_CONTEXT_WORDS = [
            'dde protocol', 'dynamic data exchange', 'microsoft dde',
            'example.com', 'test.com', 'localhost', '127.0.0.1'
        ]
        
        # قواعد YARA المتقدمة (معدلة لتقليل النتائج الخاطئة)
        self.YARA_RULES = {
            # PDF Rules (معدلة)
            "PDF_JavaScript": {
                "patterns": [b'/JS', b'/JavaScript', b'app.alert', b'app.launchURL', b'this.print', b'this.submitForm'],
                "risk": 30,
                "description": "PDF contains JavaScript",
                "requires_context": True
            },
            "PDF_Launch_Action": {
                "patterns": [b'/Launch', b'/OpenAction'],
                "risk": 40,
                "description": "PDF has auto-launch actions",
                "requires_context": True
            },
            "PDF_Embedded_File": {
                "patterns": [b'/EmbeddedFile', b'/Filespec', b'/EF'],
                "risk": 35,
                "description": "PDF contains embedded files",
                "requires_context": True
            },
            "PDF_URI_Action": {
                "patterns": [b'/URI'],
                "risk": 5,  # خفضنا من 15 إلى 5
                "description": "PDF contains external links",
                "requires_context": False
            },
            
            # PE Rules
            "PE_Packed_UPX": {
                "patterns": [b'UPX0', b'UPX1', b'UPX2'],
                "risk": 25,
                "description": "UPX packer detected",
                "requires_context": False
            },
            "PE_Packed_Other": {
                "patterns": [b'.aspack', b'.MPRESS', b'.PEC2', b'.PEC3', b'.RLPack'],
                "risk": 30,
                "description": "Packer/Protector detected",
                "requires_context": False
            },
            "PE_AntiDebug": {
                "patterns": [b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtGlobalFlag', b'OutputDebugString'],
                "risk": 20,
                "description": "Anti-debugging techniques detected",
                "requires_context": False
            },
            "PE_Virtualization": {
                "patterns": [b'vbox', b'vmware', b'virtualbox', b'VBoxGuest'],
                "risk": 15,
                "description": "Virtualization detection",
                "requires_context": False
            },
            
            # Malicious Patterns (معدلة)
            "Dynamic_Code_Execution": {
                "patterns": [b'eval(', b'exec(', b'system(', b'popen(', b'subprocess.Popen'],
                "risk": 35,
                "description": "Dynamic code execution",
                "requires_context": True
            },
            "Network_Download": {
                "patterns": [b'URLDownloadToFile', b'DownloadFile', b'webclient.Download', b'requests.get', b'urllib.request.urlretrieve'],
                "risk": 30,
                "description": "Network download capability",
                "requires_context": True
            },
            "Persistence_Mechanism": {
                "patterns": [b'Run', b'RunOnce', b'Startup', b'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', b'CreateService'],
                "risk": 35,
                "description": "Persistence mechanism detected",
                "requires_context": True
            },
            "Data_Exfiltration": {
                "patterns": [b'post(', b'send(', b'upload', b'exfiltrate', b'steal'],
                "risk": 40,
                "description": "Possible data exfiltration",
                "requires_context": True
            },
            "Encoded_Commands": {
                "patterns": [b'base64', b'FromBase64String', b'-EncodedCommand', b'hex_decode'],
                "risk": 25,
                "description": "Encoded/obfuscated commands",
                "requires_context": True
            },
            "Suspicious_Processes": {
                "patterns": [b'cmd.exe /c', b'powershell.exe -', b'wscript.exe', b'cscript.exe', b'rundll32.exe'],
                "risk": 20,
                "description": "Suspicious process execution",
                "requires_context": True
            },
            
            # Office Rules (معدلة - DDE أصبحت أقل خطورة)
            "Office_Macros": {
                "patterns": [b'VBA', b'Macro', b'ThisDocument', b'Module', b'AutoOpen', b'Document_Open', b'Workbook_Open'],
                "risk": 45,
                "description": "Office macros detected",
                "requires_context": True
            },
            "Office_DDE": {
                "patterns": [b'DDEAUTO'],
                "risk": 25,  # خفضنا من 50 إلى 25
                "description": "DDE auto-execution pattern detected",
                "requires_context": True
            },
            
            # Suspicious Content (معدلة)
            "Suspicious_URLs": {
                "patterns": [b'.onion', b'bitcoin', b'cryptocurrency', b'wallet'],
                "risk": 10,  # خفضنا من 20 إلى 10
                "description": "Suspicious URL patterns",
                "requires_context": True
            },
            "Ransomware_Indicators": {
                "patterns": [b'.encrypted', b'.locked', b'.crypted', b'recover', b'decrypt'],
                "risk": 50,
                "description": "Ransomware-like indicators",
                "requires_context": True
            },
            "C2_Communication": {
                "patterns": [b'beacon', b'heartbeat', b'command and control', b'c&c', b'callback'],
                "risk": 45,
                "description": "Possible C2 communication patterns",
                "requires_context": True
            },
            
            # Image Rules (Steganography)
            "Steganography_Indicator": {
                "patterns": [b'steg', b'LSB', b'zsteg', b'steghide', b'outguess'],
                "risk": 30,
                "description": "Possible steganography tool references",
                "requires_context": True
            }
        }
    
    # ================================================================
    # دالة لتحديد إذا كان الملف عادياً (لتقليل النتائج الخاطئة)
    # ================================================================
    
    def _is_likely_benign(self, file_content: bytes, filename: str) -> Tuple[bool, List[str]]:
        # Names, extensions and familiar domains do not establish benign intent.
        return False, []

    def _is_false_positive(self, rule_name: str, matched_pattern: bytes, file_content: bytes, filename: str) -> bool:
        # Preserve observations; context elsewhere must not suppress a byte match.
        return False

    # ================================================================
    # 1. حساب التجزئات (Hashes) - متقدم
    # ================================================================
    
    def calculate_hashes(self, file_content: bytes) -> Dict[str, str]:
        logger.debug(f"Calculating hashes for file of size: {len(file_content)} bytes")
        """حساب جميع تجزئات الملف"""
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest(),
            "sha512": hashlib.sha512(file_content).hexdigest(),
            "blake2b": hashlib.blake2b(file_content).hexdigest()
        }
    
    def calculate_hashes_streaming(self, file_path: str, chunk_size: int = 8192) -> Dict[str, str]:
        """حساب التجزئات للملفات الكبيرة (تدريجياً)"""
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        hash_sha512 = hashlib.sha512()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha512.update(chunk)
        
        return {
            "md5": hash_md5.hexdigest(),
            "sha1": hash_sha1.hexdigest(),
            "sha256": hash_sha256.hexdigest(),
            "sha512": hash_sha512.hexdigest()
        }
    
    # ================================================================
    # 2. كشف نوع الملف (باستخدام filetype + فحص يدوي موسع)
    # ================================================================
    
    def detect_file_type(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        logger.debug(f"Detecting file type for: {filename}")
        """كشف نوع الملف الحقيقي باستخدام filetype مع دعم موسع"""
        result = {
            "extension": filename.split('.')[-1].lower() if '.' in filename else '',
            "is_spoofed": False,
            "mime_type": "unknown",
            "actual_type": "unknown",
            "description": "Unknown",
            "is_executable": False,
            "is_archive": False,
            "is_document": False,
            "is_script": False,
            "is_image": False,
            "is_pdf": False,
            "is_office": False
        }
        
        if FILETYPE_AVAILABLE:
            try:
                kind = filetype.guess(file_content)
                if kind:
                    result["mime_type"] = kind.mime
                    result["actual_type"] = kind.extension
                    result["description"] = f"{kind.extension.upper()} file - {kind.mime}"
            except Exception as e:
                logger.error(f"Error in [function_name]: {str(e)}")
                result["description"] = f"Error: {str(e)}"
        
        # كشف يدوي إذا فشل filetype (موسع)
        if result["actual_type"] == "unknown":
            # PDF
            if file_content[:4] == b'%PDF':
                result["actual_type"] = "pdf"
                logger.info(f"Detected file type: {result['actual_type']} for {filename}")
                result["mime_type"] = "application/pdf"
                result["description"] = "PDF file"
            # Office Open XML (docx, xlsx, pptx)
            elif file_content[:4] == b'PK\x03\x04':
                # قراءة أول 1000 بايت لتحديد النوع
                header = file_content[:1000].decode('latin-1', errors='ignore')
                if 'word/' in header:
                    result["actual_type"] = "docx"
                    result["mime_type"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    result["description"] = "Word document"
                elif 'xl/' in header:
                    result["actual_type"] = "xlsx"
                    result["mime_type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    result["description"] = "Excel spreadsheet"
                elif 'ppt/' in header or 'slide' in header:
                    result["actual_type"] = "pptx"
                    result["mime_type"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    result["description"] = "PowerPoint presentation"
                else:
                    result["actual_type"] = "zip"
                    result["mime_type"] = "application/zip"
                    result["description"] = "ZIP archive"
            # OLE (doc, xls, ppt old format)
            elif file_content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                header = file_content[:200].decode('latin-1', errors='ignore')
                if 'Word' in header or 'Microsoft Word' in header:
                    result["actual_type"] = "doc"
                    result["mime_type"] = "application/msword"
                    result["description"] = "Old Word document"
                elif 'Excel' in header or 'Workbook' in header:
                    result["actual_type"] = "xls"
                    result["mime_type"] = "application/vnd.ms-excel"
                    result["description"] = "Old Excel spreadsheet"
                elif 'PowerPoint' in header or 'PPT' in header:
                    result["actual_type"] = "ppt"
                    result["mime_type"] = "application/vnd.ms-powerpoint"
                    result["description"] = "Old PowerPoint presentation"
                else:
                    result["actual_type"] = "ole"
                    result["mime_type"] = "application/x-ole-storage"
                    result["description"] = "OLE storage file"
            # RAR
            elif file_content[:7] == b'Rar!\x1a\x07\x00':
                result["actual_type"] = "rar"
                result["mime_type"] = "application/x-rar-compressed"
                result["description"] = "RAR archive"
            # 7Z
            elif file_content[:6] == b"7z\xbc\xaf\x27\x1c":
                result["actual_type"] = "7z"
                result["mime_type"] = "application/x-7z-compressed"
                result["description"] = "7-Zip archive"
            # PE (EXE/DLL)
            elif file_content[:2] == b'MZ':
                result["actual_type"] = "exe"
                result["mime_type"] = "application/x-msdownload"
                result["description"] = "Windows PE executable"
            # PNG
            elif file_content[:8] == b'\x89PNG\r\n\x1a\n':
                result["actual_type"] = "png"
                result["mime_type"] = "image/png"
                result["description"] = "PNG image"
            # JPEG
            elif file_content[:2] == b'\xff\xd8':
                result["actual_type"] = "jpg"
                result["mime_type"] = "image/jpeg"
                result["description"] = "JPEG image"
            # GIF
            elif file_content[:3] == b'GIF':
                result["actual_type"] = "gif"
                result["mime_type"] = "image/gif"
                result["description"] = "GIF image"
            # ELF (Linux)
            elif file_content[:4] == b'\x7fELF':
                result["actual_type"] = "elf"
                result["mime_type"] = "application/x-elf"
                result["description"] = "Linux ELF executable"
        
        # Inspect the central directory, not just the first ZIP bytes.
        container = container_type(file_content)
        if container:
            result['actual_type'] = container
            result['mime_type'] = {'zip':'application/zip', 'docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation'}[container]
            result['description'] = 'Container directory observation: ' + container
        elif result['actual_type'] == 'unknown' and file_content and b'\x00' not in file_content:
            try:
                file_content.decode('utf-8-sig')
                result.update(actual_type='txt', mime_type='text/plain', description='UTF-8 text; language is inferred separately from the filename')
            except UnicodeDecodeError:
                pass
        result['detection_scope'] = 'Magic bytes, container directory or UTF-8 text; not execution or authenticity verification.'

        # تحديد أنواع الملفات
        result["is_executable"] = result["actual_type"] in ['exe', 'dll', 'scr', 'msi', 'bin', 'elf']
        result["is_archive"] = result["actual_type"] in ['zip', 'rar', '7z', 'gz', 'tar']
        result["is_document"] = result["actual_type"] in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        result["is_office"] = result["actual_type"] in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'ole']
        result["is_script"] = result["extension"] in ['py', 'js', 'ps1', 'sh', 'bat', 'vbs', 'rb', 'pl']
        result["is_image"] = result["actual_type"] in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']
        result["is_pdf"] = result["actual_type"] == "pdf"
        
        # كشف تزوير الامتداد (موسع)
        ext_to_type = {
            'pdf': ['pdf'], 'exe': ['exe', 'dll', 'scr', 'msi'], 'doc': ['doc', 'docx'],
            'docx': ['docx', 'doc'], 'xls': ['xls', 'xlsx'], 'xlsx': ['xlsx', 'xls'],
            'ppt': ['ppt', 'pptx'], 'pptx': ['pptx', 'ppt'], 'zip': ['zip', 'jar', 'apk'],
            'rar': ['rar'], 'jpg': ['jpg', 'jpeg'], 'jpeg': ['jpg', 'jpeg'],
            'png': ['png'], 'txt': ['txt','py','js','ps1','sh','bat','vbs','rb','pl'], 'html': ['html', 'htm'], 'js': ['js'],
            'py': ['py'], 'ps1': ['ps1'], 'sh': ['sh'], 'bat': ['bat']
        }
        for ext_type, extensions in ext_to_type.items():
            if result["actual_type"] == ext_type and result["extension"] not in extensions:
                result["is_spoofed"] = True
                break
        
        return result
    
    # ================================================================
    # 3. استخراج البيانات الوصفية (Metadata) لجميع أنواع الملفات
    # ================================================================
    
    def extract_metadata_pe(self, file_content: bytes) -> Dict[str, Any]:
        """تحليل ملفات Windows PE (exe, dll, sys)"""
        if not PEFILE_AVAILABLE:
            return {"is_pe": False, "error": "pefile not installed. Run: pip install pefile"}
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            pe = pefile.PE(tmp_path)
            
            result = {
                "is_pe": True,
                "machine": hex(pe.FILE_HEADER.Machine),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
                "is_driver": bool(pe.FILE_HEADER.Characteristics & 0x80),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "compile_time": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else None,
                "sections": [],
                "imports": [],
                "exports": [],
                "resources": [],
                "suspicious": []
            }
            
            # تحليل الأقسام
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                section_data = {
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "virtual_address": hex(section.VirtualAddress),
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy() if hasattr(section, 'get_entropy') else 0,
                    "characteristics": hex(section.Characteristics)
                }
                result["sections"].append(section_data)
                
                # كشف الأقسام المضغوطة
                packed = ['UPX', 'UPX0', 'UPX1', '.aspack', '.MPRESS', 'PEC2', 'PEC3', '.RLPack']
                for sig in packed:
                    if sig in section_name:
                        result["suspicious"].append(f"Packer detected: {sig}")
                        break
                
                # كشف الانتروبي العالي (ضغط/تشفير)
                if section_data["entropy"] > 7.0:
                    result["suspicious"].append(f"High entropy section: {section_name} ({section_data['entropy']:.2f})")
            
            # تحليل الاستيرادات الخطرة
            dangerous_apis = [
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
                "ShellExecute", "WinExec", "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
                "DeleteFile", "MoveFile", "CopyFile", "RegSetValue", "RegCreateKey", "RegDeleteKey",
                "CreateService", "StartService", "DeleteService", "CryptEncrypt", "CryptDecrypt",
                "SetWindowsHookEx", "SetWinEventHook", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow",
                "OpenProcess", "TerminateProcess", "DebugActiveProcess", "WriteProcessMemory", "ReadProcessMemory"
            ]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode()
                            result["imports"].append({"dll": dll_name, "function": func_name})
                            if func_name in dangerous_apis:
                                result["suspicious"].append(f"Dangerous API: {dll_name}!{func_name}")
            
            # تحليل التصديرات
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result["exports"].append(exp.name.decode())
            
            # تحليل الموارد
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name:
                        result["resources"].append(f"Type: {resource_type.name}")
                    else:
                        result["resources"].append(f"Type ID: {resource_type.id}")
            
            # التحقق من التوقيع الرقمي
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                result["has_digital_signature"] = True
            
            os.unlink(tmp_path)
            return result
            
        except Exception as e:
            return {"is_pe": False, "error": str(e)}
    
    def extract_metadata_pdf(self, file_content: bytes) -> Dict[str, Any]:
        from services.pdf_structure import pdf_observations
        return pdf_observations(file_content)

    def extract_metadata_office(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        if container_type(file_content) in ('docx', 'xlsx', 'pptx'):
            return zip_observations(file_content, office=True)
        # Legacy OLE bytes cannot prove absence of compressed VBA streams.
        return {'is_office': True, 'type': 'ole', 'has_macros': None,
                'suspicious': [], 'coverage_status': 'partial',
                'error': 'Legacy OLE macro and object inspection is not implemented',
                'scope': 'Legacy container signature only; macro absence was not established.'}

    def extract_metadata_script(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تحليل الملفات النصية"""
        content_str = file_content.decode('utf-8', errors='ignore')
        
        result = {
            "is_script": True,
            "language": "unknown",
            "lines": len(content_str.splitlines()),
            "size_chars": len(content_str),
            "has_network": False,
            "has_file_operations": False,
            "has_obfuscation": False,
            "imports": [],
            "suspicious": []
        }
        
        # تحديد لغة البرمجة
        if filename.endswith('.py'):
            result["language"] = "python"
            # استخراج الـ imports
            imports = re.findall(r'^import\s+(\w+)|^from\s+(\w+)\s+import', content_str, re.MULTILINE)
            result["imports"] = [imp[0] or imp[1] for imp in imports if imp[0] or imp[1]]
            # كشف الأنشطة المشبوهة
            if re.search(r'requests|urllib|socket|http', content_str, re.I):
                result["has_network"] = True
            if re.search(r'open\(|file\(|shutil|os\.remove|os\.system', content_str):
                result["has_file_operations"] = True
            if re.search(r'eval\(|exec\(|__import__|compile\(', content_str):
                result["has_obfuscation"] = True
                result["suspicious"].append("Dynamic code execution")
            if 'base64' in content_str.lower():
                result["suspicious"].append("Base64 encoding detected")
                
        elif filename.endswith('.js'):
            result["language"] = "javascript"
            if re.search(r'XMLHttpRequest|fetch\(|axios|\.get\(|\.post\(', content_str):
                result["has_network"] = True
            if re.search(r'eval\(|Function\(|setTimeout\(|setInterval\(', content_str):
                result["has_obfuscation"] = True
                result["suspicious"].append("Dynamic code execution")
            if re.search(r'document\.write|innerHTML|createElement', content_str):
                result["suspicious"].append("DOM manipulation")
                
        elif filename.endswith(('.ps1', '.psm1')):
            result["language"] = "powershell"
            if re.search(r'Invoke-WebRequest|DownloadFile|Net\.WebClient', content_str, re.I):
                result["has_network"] = True
                result["suspicious"].append("Network download capability")
            if re.search(r'-EncodedCommand|FromBase64String', content_str, re.I):
                result["has_obfuscation"] = True
                result["suspicious"].append("Encoded command detected")
            if re.search(r'Start-Process|Invoke-Expression', content_str, re.I):
                result["suspicious"].append("Process execution")
                
        elif filename.endswith(('.sh', '.bash')):
            result["language"] = "bash"
            if re.search(r'curl|wget|nc|telnet', content_str):
                result["has_network"] = True
            if re.search(r'rm -rf|dd if=|mkfs|:(){', content_str):
                result["suspicious"].append("Potentially destructive commands")
        
        return result
    
    def extract_metadata_archive(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        if container_type(file_content) == 'zip':
            return zip_observations(file_content)
        if file_content.startswith(b'Rar!\x1a\x07'):
            return archive_observations(file_content, 'rar')
        if file_content.startswith(b'7z\xbc\xaf\x27\x1c'):
            return archive_observations(file_content, '7z')
        return {'is_archive': True, 'type': 'unknown', 'suspicious': [],
                'coverage_status': 'partial', 'error': 'This archive format has no configured structural parser'}

    def extract_metadata_image(self, file_content: bytes) -> Dict[str, Any]:
        """تحليل الصور واستخراج EXIF و GPS"""
        if not PIL_AVAILABLE:
            return {"is_image": False, "error": "PIL not installed. Run: pip install pillow"}
        
        result = {
            "is_image": True,
            "format": None,
            "mode": None,
            "width": 0,
            "height": 0,
            "has_exif": False,
            "exif_data": {},
            "gps_data": {},
            "has_thumbnail": False,
            "suspicious": []
        }
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            img = Image.open(tmp_path)
            result["format"] = img.format
            result["mode"] = img.mode
            result["width"] = img.width
            result["height"] = img.height
            
            # استخراج EXIF
            if hasattr(img, '_getexif') and img._getexif():
                result["has_exif"] = True
                exif = img._getexif()
                for tag_id, value in exif.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == 'GPSInfo':
                        for gps_tag in value:
                            gps_name = GPSTAGS.get(gps_tag, gps_tag)
                            result["gps_data"][gps_name] = value[gps_tag]
                    else:
                        # تقييد طول القيمة
                        result["exif_data"][tag_name] = str(value)[:200]
            
            # كشف الصور المصغرة المشبوهة
            if hasattr(img, 'thumbnail') and img.thumbnail:
                result["has_thumbnail"] = True
            
            # كشف الأبعاد غير الطبيعية (قد تكون تمويه)
            if img.width > 5000 or img.height > 5000:
                result["suspicious"].append("Unusually large dimensions - possible steganography")
            
            os.unlink(tmp_path)
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def extract_metadata_via_exiftool(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """استخراج البيانات الوصفية باستخدام exiftool"""
        if not self.use_exiftool:
            return {"enabled": False, "message": "exiftool not enabled"}
        
        result = {"available": False, "data": {}}
        
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            proc = subprocess.run(
                ['exiftool', '-json', tmp_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                if data:
                    result["available"] = True
                    result["data"] = data[0]
            
            if not result["available"]:
                result["error"] = "ExifTool metadata unavailable or malformed"
        except FileNotFoundError:
            result["error"] = "exiftool not installed"
        except Exception as e:
            result["error"] = "ExifTool metadata failed or timed out"
        
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return result
    
    # ================================================================
    # 4. استخراج المؤشرات (IoCs) المتقدم
    # ================================================================
    
    def extract_iocs(self, file_content: bytes) -> Dict[str, List[str]]:
        logger.debug("Extracting IoCs from file content")
        """استخراج جميع المؤشرات من الملف"""
        content_str = file_content.decode('latin-1', errors='ignore')
        
        iocs = {
            "ipv4": [],
            "ipv6": [],
            "urls": [],
            "emails": [],
            "domains": [],
            "md5_hashes": [],
            "sha1_hashes": [],
            "sha256_hashes": [],
            "windows_paths": [],
            "registry_keys": [],
            "bitcoin_addresses": [],
            "onion_addresses": [],
            "telegram_links": [],
            "discord_webhooks": []
        }
        
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            matches = re.findall(pattern, content_str, re.IGNORECASE)
            unique_matches = list(set(matches))
            
            if ioc_type == 'ipv4':
                # فلترة العناوين الصالحة فقط
                valid_ips = []
                for ip in unique_matches:
                    parts = ip.split('.')
                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                        # استبعاد العناوين الخاصة
                        if not (ip.startswith('127.') or ip.startswith('10.') or 
                                ip.startswith('192.168.') or ip.startswith('172.16.') or
                                ip.startswith('0.0.0.0') or ip == '255.255.255.255'):
                            valid_ips.append(ip)
                iocs[ioc_type] = valid_ips[:50]
                
            elif ioc_type == 'domain':
                # فلترة لتجنب تكرار الـ URLs
                valid_domains = [d for d in unique_matches if not d.startswith('http') and '.' in d and len(d) > 3]
                # استبعاد النطاقات الآمنة المعروفة
                valid_domains = [d for d in valid_domains if not any(safe in d.lower() for safe in self.SAFE_DOMAINS)]
                iocs[ioc_type] = valid_domains[:50]
                
            elif ioc_type == 'url':
                # استبعاد الروابط الآمنة
                safe_urls = []
                for url in unique_matches[:50]:
                    if not any(safe in url.lower() for safe in self.SAFE_DOMAINS):
                        safe_urls.append(url)
                iocs[ioc_type] = safe_urls[:50]
                
            elif ioc_type == 'bitcoin':
                iocs["bitcoin_addresses"] = unique_matches[:20]
            elif ioc_type == 'onion':
                iocs["onion_addresses"] = [f"{addr}.onion" for addr in unique_matches[:20]]
            elif ioc_type == 'telegram':
                iocs["telegram_links"] = unique_matches[:20]
            elif ioc_type == 'discord':
                iocs["discord_webhooks"] = unique_matches[:20]
            else:
                iocs[ioc_type] = unique_matches[:50]
                
        logger.debug(f"Found IoCs - IPs: {len(iocs['ipv4'])}, URLs: {len(iocs['urls'])}, Domains: {len(iocs['domains'])}")
        return iocs
    
    # ================================================================
    # 5. فحص YARA المتقدم (مع فلtering للنتائج الخاطئة)
    # ================================================================
    
    def scan_with_yara(self, file_content: bytes, filename: str = "") -> Dict[str, Any]:
        logger.debug(f"Scanning with YARA rules for: {filename}")
        """فحص الملف باستخدام قواعد YARA المتقدمة مع فلترة النتائج الخاطئة"""
        if file_content.startswith(b'%PDF-'):
            return {'matched_rules': [], 'details': [], 'risk_score': 0, 'count': 0, 'status': 'not_checked'}
        matched_rules = []
        total_risk = 0
        details = []
        
        for rule_name, rule_data in self.YARA_RULES.items():
            for pattern in rule_data["patterns"]:
                if pattern in file_content:
                    # التحقق من النتيجة الخاطئة
                    if self._is_false_positive(rule_name, pattern, file_content, filename):
                        continue
                    
                    matched_rules.append(rule_name)
                    logger.warning(f"Local byte pattern observed: {rule_name} (Risk: {rule_data['risk']})")
                    total_risk += rule_data["risk"]
                    details.append({
                        "rule": rule_name,
                        "pattern": pattern.decode('latin-1', errors='ignore'),
                        "description": rule_data["description"],
                        "risk": rule_data["risk"]
                    })
                    break
        
        # إزالة التكرارات
        matched_rules = list(set(matched_rules))
        
        return {
            "matched_rules": matched_rules,
            "details": details[:20],
            "risk_score": min(100, total_risk),
            "count": len(matched_rules)
        }
    
    # ================================================================
    # 6. فحص السمعة ضد قواعد البيانات
    # ================================================================
    
    def check_hash_reputation(self, hash_value: str) -> Dict[str, Any]:
        """Hash-only dataset lookup; never uploads or executes the sample."""
        from services.malwarebazaar_client import get_malwarebazaar_client
        provider=get_malwarebazaar_client().check_hash(hash_value)
        matched=provider.get('status')=='matched' and provider.get('is_malicious') is True
        return {"is_malicious": True if matched else False if provider.get('status')=='not_found' else None,
                "provider":provider,"status":provider.get('status','unavailable'),"sources":["MalwareBazaar"] if matched else [],
                "risk_score":80 if matched else 0,"detections":[{"source":"MalwareBazaar","malware":provider.get('signature') or 'Unknown'}] if matched else []}

    # ================================================================
    # 7. تحليل الملفات الكبيرة (Streaming)
    # ================================================================
    
    def analyze_large_file(self, file_path: str, chunk_size: int = 8192) -> Dict[str, Any]:
        """تحليل الملفات الكبيرة بدون تحميلها كاملة في الذاكرة"""
        file_size = os.path.getsize(file_path)
        
        if file_size > self.max_file_size_stream:
            return {"error": f"File too large: {file_size} bytes", "max_size_mb": self.max_file_size_stream // 1024 // 1024}
        
        result = {
            "filename": Path(file_path).name,
            "file_size_mb": round(file_size / 1024 / 1024, 2),
            "chunks_analyzed": 0,
            "iocs": {key: [] for key in self.IOC_PATTERNS.keys()},
            "hashes": {}
        }
        
        # حساب التجزئات أثناء القراءة
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        hash_sha512 = hashlib.sha512()
        
        chunk_number = 0
        all_content = b''
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                chunk_number += 1
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
                hash_sha512.update(chunk)
                
                all_content += chunk
                
                # استخراج IoCs من كل جزء
                chunk_iocs = self.extract_iocs(chunk)
                for ioc_type, iocs in chunk_iocs.items():
                    if ioc_type in result["iocs"]:
                        result["iocs"][ioc_type].extend(iocs)
        
        result["hashes"] = {
            "md5": hash_md5.hexdigest(),
            "sha1": hash_sha1.hexdigest(),
            "sha256": hash_sha256.hexdigest(),
            "sha512": hash_sha512.hexdigest()
        }
        result["chunks_analyzed"] = chunk_number
        
        # تنظيف وتفريد الـ IoCs
        for ioc_type in result["iocs"]:
            result["iocs"][ioc_type] = list(set(result["iocs"][ioc_type]))[:50]
        
        # فحص YARA على المحتوى الكامل
        filename = Path(file_path).name
        result["yara"] = self.scan_with_yara(all_content, filename)
        
        return result
    
    # ================================================================
    # 8. التحليل الشامل الكامل (المعدل)
    # ================================================================
    
    def comprehensive_analysis(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        logger.info(f"🔍 Starting comprehensive analysis for: {filename} (Size: {len(file_content)} bytes)")
        """التحليل الشامل للملف مع جميع الميزات"""
        
        file_size = len(file_content)
        original_filename = filename
        filename = filename.lower()
        
        warnings = []
        if file_size == 0:
            warnings.append("File is empty")
        if file_size > self.max_file_size:
            warnings.append(f"File exceeds size limit ({self.max_file_size // 1024 // 1024} MB)")
        
        # التحقق إذا كان الملف غالباً عادي
        is_benign, benign_reasons = self._is_likely_benign(file_content, filename)
        if is_benign:
            warnings.append(f"ℹ️ File appears legitimate: {', '.join(benign_reasons)}")
        
        # 1. التجزئات
        hashes = self.calculate_hashes(file_content)
        
        # 2. كشف نوع الملف
        file_type = self.detect_file_type(file_content, filename)
        
        if file_type.get("is_spoofed"):
            warnings.append(f"⚠️ Extension spoofing! Actually {file_type.get('actual_type')}")
        
        # 3. البيانات الوصفية حسب نوع الملف
        metadata = {"type": file_type.get("actual_type", "unknown"), "suspicious": []}
        
        if file_type.get("is_executable"):
            metadata.update(self.extract_metadata_pe(file_content))
        elif file_type.get("is_pdf"):
            metadata.update(self.extract_metadata_pdf(file_content))
        elif file_type.get("is_office"):
            metadata.update(self.extract_metadata_office(file_content, filename))
        elif file_type.get("is_archive"):
            metadata.update(self.extract_metadata_archive(file_content, filename))
        elif file_type.get("is_script") and file_type.get('actual_type') == 'txt':
            metadata.update(self.extract_metadata_script(file_content, filename))
        elif file_type.get("is_image"):
            metadata.update(self.extract_metadata_image(file_content))
        else:
            metadata['error'] = 'No structural parser selected for the observed format'

        # 4. exiftool metadata (اختياري)
        exiftool_data = self.extract_metadata_via_exiftool(file_content, filename) if self.use_exiftool else {}
        
        # 5. المؤشرات (IoCs)
        # Compressed container bytes and member names are not decoded payload evidence.
        iocs = {key: [] for key in self.IOC_PATTERNS} if file_type.get('is_archive') or file_type.get('is_pdf') else self.extract_iocs(file_content)
        if file_type.get('is_pdf'):
            iocs = self.extract_iocs('\n'.join(metadata.get('uris', [])).encode('utf-8'))
            metadata['ioc_scope'] = 'Explicit PDF URI action values only; no raw or compressed byte matching.'
        
        # 6. فحص YARA (مع اسم الملف للفلترة)
        yara_result = ({'matched_rules': [], 'details': [], 'risk_score': 0, 'count': 0,
                        'status': 'not_checked', 'scope': 'Raw PDF byte patterns skipped; object findings are reported separately.'}
                       if file_type.get('is_pdf') else self.scan_with_yara(file_content, filename))
        
        # 7. سمعة التجزئة
        hash_reputation = self.check_hash_reputation(hashes["sha256"])
        
        # 8. حساب درجة الخطورة (معدلة)
        security_score = 100
        
        # تأثير YARA (مخفض للملفات العادية)
        if yara_result.get("risk_score", 0):
            penalty = yara_result["risk_score"]
            if is_benign:
                penalty = penalty // 2  # تخفيض العقوبة للملفات العادية
            security_score -= penalty
        
        if metadata.get('has_path_traversal'):
            security_score -= 25
        if any('External Office relationship:' in w for w in metadata.get('suspicious', [])):
            security_score -= 20
        if file_type.get('is_spoofed'):
            security_score -= 15

        # تأثير السمعة
        if hash_reputation.get("is_malicious"):
            security_score -= 40
        
        # تأثير التحذيرات من البيانات الوصفية (مخفض)
        if metadata.get("suspicious"):
            # نأخذ فقط التحذيرات الخطيرة حقاً
            critical_warnings = [w for w in metadata["suspicious"] 
                               if 'Launch' in w or 'DDE' in w or 'macro' in w.lower()]
            if critical_warnings:
                security_score -= min(40, len(critical_warnings) * 10)
            elif len(metadata["suspicious"]) > 0 and not is_benign:
                security_score -= min(20, len(metadata["suspicious"]) * 4)
        
        # تأثير الماكرو (فقط إذا كان خطيراً)
        if metadata.get("has_macros") and not is_benign:
            security_score -= 35
        
        # تأثير JavaScript (فقط إذا كان تنفيذياً)
        if metadata.get("has_javascript") and b'app.launchURL' in file_content:
            security_score -= 25
        
        # تأثير المرفقات
        if metadata.get("has_attachments") and not is_benign:
            security_score -= 20
        
        # تأثير الإجراءات التلقائية
        if metadata.get("has_actions") and not is_benign:
            security_score -= 15
        
        # IoCs تأثير (فقط للـ IoCs غير الآمنة)
        unsafe_ioc_count = len(iocs.get("urls", [])) + len(iocs.get("ipv4", [])) + len(iocs.get("onion_addresses", []))
        if unsafe_ioc_count > 0 and not is_benign:
            security_score -= min(30, unsafe_ioc_count * 2)
        
        # روابط مشبوهة إضافية
        if (iocs.get("bitcoin_addresses") or iocs.get("onion_addresses")) and not is_benign:
            security_score -= 20
        
        if warnings:
            security_score -= len(warnings) * 5
        
        # رفع درجة الأمان للملفات العادية
        if is_benign and security_score < 70:
            security_score = min(85, security_score + 25)
        
        security_score = max(0, min(100, security_score))
        
        # 9. الحكم النهائي
        if security_score >= 80:
            verdict = "safe"
            verdict_icon = "✅"
            severity = "low"
        elif security_score >= 60:
            verdict = "suspicious"
            verdict_icon = "⚠️"
            severity = "medium"
        elif security_score >= 30:
            verdict = "high_risk"
            verdict_icon = "🔴"
            severity = "high"
        else:
            verdict = "high_risk"
            verdict_icon = "🔴"
            severity = "high"
        
        # تعديل الحكم للملفات العادية
        if is_benign and verdict in ["malicious", "high_risk"]:
            verdict = "suspicious"
            verdict_icon = "⚠️"
            severity = "medium"
        
        # 10. التوصيات (معدلة)
        recommendations = []
        
        if verdict == "malicious":
            recommendations.append("🚨 CRITICAL: DO NOT EXECUTE this file!")
            recommendations.append("🗑️ Delete the file immediately")
            recommendations.append("🔒 Scan your system with updated antivirus")
        elif verdict == "high_risk":
            recommendations.append("⚠️ High risk detected - proceed with extreme caution")
            recommendations.append("📁 Run in isolated sandbox environment only")
        elif verdict == "suspicious":
            recommendations.append("🔍 Suspicious indicators found - investigate further")
            if is_benign:
                recommendations.append("ℹ️ Note: Some indicators may be false positives (file appears legitimate)")
        
        # إضافة تحذيرات خطيرة فقط
        if metadata.get("suspicious"):
            for sus in metadata["suspicious"][:3]:
                if any(keyword in sus.lower() for keyword in ['launch', 'macro', 'dde', 'execut']):
                    recommendations.append(f"🔸 {sus}")
        
        if metadata.get("has_macros") and not is_benign:
            recommendations.append("📌 File contains macros - DISABLE macros before opening")
        
        if metadata.get("has_javascript") and b'app.launchURL' in file_content:
            recommendations.append("📌 PDF contains JavaScript that can launch external URLs")
        
        if yara_result.get("matched_rules") and not is_benign:
            recommendations.append(f"📋 Local byte patterns reported ({len(yara_result['matched_rules'])}): {', '.join(yara_result['matched_rules'][:4])}")
        
        if hash_reputation.get("is_malicious"):
            recommendations.append(f"💀 File hash found in malware database ({', '.join(hash_reputation['sources'])})")
        
        if file_type.get("is_spoofed"):
            recommendations.append(f"🎭 Extension spoofing detected! Real type: {file_type.get('actual_type')}")
        
        if not recommendations:
            recommendations.append("No indicators detected by the available local checks; this does not establish safety.")
        missing_checks=[]
        if hash_reputation.get('status') not in ('matched','not_found'):missing_checks.append('Hash reputation unavailable')
        if metadata.get('error') or metadata.get('metadata_error'):missing_checks.append('File metadata parser unavailable or failed')
        missing_checks.extend(metadata.get('missing_checks', []))
        if file_type.get('actual_type') == 'unknown':missing_checks.append('File format could not be identified')
        if exiftool_data.get('error'):missing_checks.append('Optional exiftool metadata unavailable')
        # Byte-pattern heuristics are not a signature engine or a sandbox.
        if hash_reputation.get('is_malicious') is True:
            verdict='malicious';verdict_icon='💀';severity='critical';security_score=min(security_score,20)
        if verdict=='safe':
            verdict='unknown' if missing_checks else 'not_found'
            verdict_icon='⚠️' if missing_checks else 'ℹ️'
        logger.info(f"✅ Analysis completed for: {filename} | Score: {security_score} | Verdict: {verdict}")
        return {
            "filename": original_filename,
            "coverage_status": "partial" if missing_checks else "completed",
            "missing_checks": missing_checks,
            "scope": "Static metadata, byte patterns and hash reputation; no execution, sandbox or antivirus guarantee.",
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / 1024 / 1024, 2),
            "file_type": file_type,
            "hashes": hashes,
            "metadata": metadata,
            "exiftool_data": exiftool_data,
            "iocs": iocs,
            "yara": yara_result,
            "hash_reputation": hash_reputation,
            "warnings": warnings,
            "security_score": security_score,
            "verdict": verdict,
            "verdict_icon": verdict_icon,
            "severity": severity,
            "recommendations": recommendations,
            "is_likely_benign": is_benign,
            "benign_reasons": benign_reasons,
            "analyzed_at": datetime.now().isoformat()
        }


# ================================================================
# دالة مساعدة سريعة للاستخدام المباشر
# ================================================================

def analyze_file(file_path: str, use_exiftool: bool = False) -> Dict[str, Any]:
    """
    دالة سريعة لتحليل ملف من المسار
    
    Args:
        file_path: مسار الملف
        use_exiftool: استخدام exiftool إن وجد
    
    Returns:
        تحليل كامل للملف
    """
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    analyzer = FileDeepAnalyzer(use_exiftool=use_exiftool)
    return analyzer.comprehensive_analysis(file_content, Path(file_path).name)


def analyze_file_streaming(file_path: str) -> Dict[str, Any]:
    """
    تحليل الملفات الكبيرة باستخدام streaming
    
    Args:
        file_path: مسار الملف
    
    Returns:
        تحليل للملف الكبير
    """
    analyzer = FileDeepAnalyzer()
    return analyzer.analyze_large_file(file_path)


# ================================================================
# مثال الاستخدام
# ================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python file_deep_analyzer.py <file_path>")
        print("\nExample: python file_deep_analyzer.py suspicious.pdf")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    # تحليل الملف
    file_size = os.path.getsize(file_path)
    
    if file_size > 50 * 1024 * 1024:
        print(f"[!] Large file detected ({file_size / 1024 / 1024:.2f} MB) - using streaming...")
        result = analyze_file_streaming(file_path)
    else:
        result = analyze_file(file_path, use_exiftool=True)
    
    # طباعة النتائج
    print("\n" + "=" * 70)
    print(f" FILE DEEP ANALYSIS REPORT ".center(70, "="))
    print("=" * 70)
    
    print(f"\n📄 File: {result.get('filename')}")
    print(f"📏 Size: {result.get('file_size_mb')} MB")
    print(f"🎯 Verdict: {result.get('verdict_icon')} {result.get('verdict', 'unknown').upper()}")
    print(f"📊 Security Score: {result.get('security_score')}/100")
    print(f"⚠️ Severity: {result.get('severity', 'unknown')}")
    
    if result.get('is_likely_benign'):
        print(f"✅ Likely legitimate: {', '.join(result.get('benign_reasons', []))}")
    
    print(f"\n🔐 Hashes:")
    for hash_type, hash_value in result.get('hashes', {}).items():
        print(f"   {hash_type.upper()}: {hash_value[:16]}...")
    
    print(f"\n📊 IoCs Found:")
    iocs = result.get('iocs', {})
    print(f"   IP Addresses: {len(iocs.get('ipv4', []))}")
    print(f"   URLs: {len(iocs.get('urls', []))}")
    print(f"   Domains: {len(iocs.get('domains', []))}")
    print(f"   Emails: {len(iocs.get('emails', []))}")
    print(f"   Bitcoin: {len(iocs.get('bitcoin_addresses', []))}")
    print(f"   Onion: {len(iocs.get('onion_addresses', []))}")
    
    print(f"\n🎯 YARA Results:")
    yara = result.get('yara', {})
    print(f"   Matched Rules: {yara.get('count', 0)}")
    for rule in yara.get('matched_rules', [])[:5]:
        print(f"   - {rule}")
    
    print(f"\n💡 Recommendations:")
    for rec in result.get('recommendations', [])[:8]:
        print(f"   {rec}")
    
    print("\n" + "=" * 70)
    
    # حفظ التقرير
    report_path = f"{Path(file_path).stem}_analysis_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📁 Full report saved to: {report_path}")
