# file_analyzer.py - تحليل متقدم للملفات (بدون libmagic)
import os
import hashlib
import struct
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import filetype

class FileAnalyzer:
    """تحليل متقدم للملفات قبل الرفع إلى VirusTotal"""
    
    def __init__(self):
        self.max_size = 10 * 1024 * 1024  # 10 MB
        
    def calculate_hashes(self, file_content: bytes) -> Dict[str, str]:
        """حساب جميع هاشات الملف"""
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest(),
            "sha512": hashlib.sha512(file_content).hexdigest()
        }
    
    def detect_file_type(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """كشف نوع الملف الحقيقي"""
        try:
            # استخدام filetype للكشف
            kind = filetype.guess(file_content)
            
            if kind is not None:
                mime_type = kind.mime
                description = f"{kind.extension.upper()} file - {kind.mime}"
                actual_type = kind.extension
            else:
                # محاولة الكشف يدوياً
                mime_type = "application/octet-stream"
                description = "Unknown file type"
                actual_type = "unknown"
            
            # كشف الامتداد الحقيقي
            extension = filename.split('.')[-1].lower() if '.' in filename else ''
            
            # التحقق من تزوير الامتداد
            is_spoofed = False
            
            # قائمة الامتدادات المتوقعة لكل نوع
            ext_map = {
                'pdf': ['pdf'],
                'exe': ['exe', 'dll', 'scr', 'msi'],
                'doc': ['doc', 'docx'],
                'xls': ['xls', 'xlsx'],
                'zip': ['zip'],
                'rar': ['rar'],
                'jpg': ['jpg', 'jpeg'],
                'png': ['png'],
                'txt': ['txt'],
                'html': ['html', 'htm'],
                'js': ['js'],
                'py': ['py'],
                'ps1': ['ps1'],
                'sh': ['sh']
            }
            
            for ext_type, extensions in ext_map.items():
                if actual_type == ext_type and extension not in extensions:
                    is_spoofed = True
                    break
            
            return {
                "mime_type": mime_type,
                "description": description,
                "extension": extension,
                "actual_type": actual_type,
                "is_spoofed": is_spoofed,
                "is_executable": actual_type in ['exe', 'dll', 'scr', 'msi', 'bin'],
                "is_archive": actual_type in ['zip', 'rar', '7z', 'gz', 'tar'],
                "is_document": actual_type in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
                "is_script": extension in ['py', 'js', 'ps1', 'sh', 'bat', 'vbs']
            }
            
        except Exception as e:
            return {
                "mime_type": "unknown",
                "description": f"Error: {str(e)}",
                "extension": filename.split('.')[-1].lower() if '.' in filename else '',
                "is_executable": False,
                "is_spoofed": False
            }
    
    def analyze_pe_file(self, file_content: bytes) -> Dict[str, Any]:
        """تحليل ملفات Windows PE (exe, dll, sys)"""
        try:
            import pefile
            import tempfile
            
            # حفظ الملف مؤقتاً للتحليل
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
                "sections": [],
                "imports": [],
                "exports": [],
                "suspicious": []
            }
            
            # تحليل الأقسام
            packed_signatures = ['UPX', 'UPX0', 'UPX1', '.aspack', '.MPRESS', 'PEC2', 'PEC3']
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                section_data = {
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "virtual_address": hex(section.VirtualAddress),
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy() if hasattr(section, 'get_entropy') else 0
                }
                result["sections"].append(section_data)
                
                # كشف الأقسام المضغوطة
                for sig in packed_signatures:
                    if sig in section_name:
                        result["suspicious"].append(f"Packer detected: {sig}")
                        break
                
                # كشف الانتروبي العالي (ضغط/تشفير)
                if section_data["entropy"] > 7.0:
                    result["suspicious"].append(f"High entropy section: {section_name} (possible encryption/packing)")
            
            # تحليل الاستيرادات
            dangerous_apis = [
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", 
                "ShellExecute", "WinExec", "URLDownloadToFile", "DeleteFile",
                "RegSetValue", "CreateService", "StartService", "CryptEncrypt"
            ]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode()
                            result["imports"].append({
                                "dll": dll_name,
                                "function": func_name
                            })
                            
                            # كشف API الخطرة
                            if func_name in dangerous_apis:
                                result["suspicious"].append(f"Dangerous API: {dll_name}!{func_name}")
            
            # تحليل التصديرات
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result["exports"].append(exp.name.decode())
            
            # تنظيف الملف المؤقت
            os.unlink(tmp_path)
            
            return result
            
        except ImportError:
            return {"is_pe": False, "error": "pefile not installed. Run: pip install pefile"}
        except Exception as e:
            return {"is_pe": False, "error": str(e)}
    
    def analyze_pdf(self, file_content: bytes) -> Dict[str, Any]:
        """تحليل ملفات PDF"""
        try:
            # فحص بسيط بدون PyPDF2
            content_str = file_content.decode('latin-1', errors='ignore')
            
            result = {
                "is_pdf": True,
                "num_pages": 0,
                "is_encrypted": '/Encrypt' in content_str,
                "has_javascript": False,
                "has_actions": False,
                "has_attachments": False,
                "has_launch": False,
                "suspicious": []
            }
            
            # البحث عن JavaScript
            js_indicators = ['/JS', '/JavaScript', 'app.alert', 'app.launchURL', 'this.print']
            for indicator in js_indicators:
                if indicator in content_str:
                    result["has_javascript"] = True
                    result["suspicious"].append(f"JavaScript found: {indicator}")
                    break
            
            # البحث عن الإجراءات التلقائية
            action_indicators = ['/AA', '/OpenAction', '/Launch']
            for indicator in action_indicators:
                if indicator in content_str:
                    result["has_actions"] = True
                    result["suspicious"].append(f"Auto-action detected: {indicator}")
                    break
            
            # البحث عن المرفقات
            if '/EmbeddedFile' in content_str or '/Filespec' in content_str:
                result["has_attachments"] = True
                result["suspicious"].append("Embedded files found")
            
            # البحث عن روابط خطرة
            if '/URI' in content_str and ('http' in content_str or 'https' in content_str):
                result["suspicious"].append("External URL links found")
            
            return result
            
        except Exception as e:
            return {"is_pdf": False, "error": str(e)}
    
    def analyze_office_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تحليل ملفات Office (doc, docx, xls, xlsx)"""
        try:
            result = {
                "is_office": True,
                "type": "old" if filename.endswith(('.doc', '.xls', '.ppt')) else "new",
                "has_macros": False,
                "has_ole": False,
                "suspicious": []
            }
            
            # للملفات الجديدة (docx, xlsx) - هي عبارة عن ZIP
            if result["type"] == "new":
                # البحث عن الماكرو
                if b'vba' in file_content.lower() or b'macro' in file_content.lower():
                    result["has_macros"] = True
                    result["suspicious"].append("Macros detected in Office file")
                
                # البحث عن علاقات خارجية
                if b'relationship' in file_content.lower() and b'http' in file_content:
                    result["suspicious"].append("External relationships found")
            
            else:
                # للملفات القديمة (doc, xls)
                # الكشف عن وجود OLE objects
                if b'\xd0\xcf\x11\xe0' in file_content[:100]:  # OLE signature
                    result["has_ole"] = True
                    if b'VBA' in file_content or b'Macro' in file_content:
                        result["has_macros"] = True
                        result["suspicious"].append("Macros detected in legacy Office file")
            
            return result
            
        except Exception as e:
            return {"is_office": False, "error": str(e)}
    
    def analyze_archive(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تحليل الملفات المضغوطة"""
        try:
            import zipfile
            import tempfile
            
            result = {
                "is_archive": True,
                "type": "zip",
                "num_files": 0,
                "total_size": 0,
                "contains_executable": False,
                "suspicious": []
            }
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=filename) as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            try:
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    result["num_files"] = len(zf.namelist())
                    
                    for file_info in zf.infolist():
                        result["total_size"] += file_info.file_size
                        
                        # كشف الملفات التنفيذية داخل الأرشيف
                        if file_info.filename.endswith(('.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs')):
                            result["contains_executable"] = True
                            result["suspicious"].append(f"Executable found: {file_info.filename}")
                        
                        # كشف المسارات الخطرة
                        if '..' in file_info.filename:
                            result["suspicious"].append(f"Path traversal: {file_info.filename}")
                            
            except:
                result["type"] = "other"
            
            os.unlink(tmp_path)
            return result
            
        except Exception as e:
            return {"is_archive": False, "error": str(e)}
    
    def analyze_script(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """تحليل الملفات النصية"""
        try:
            content_str = file_content.decode('utf-8', errors='ignore')
            result = {
                "is_script": True,
                "language": "unknown",
                "lines": len(content_str.splitlines()),
                "size_chars": len(content_str),
                "has_network": False,
                "has_file_operations": False,
                "has_obfuscation": False,
                "suspicious": []
            }
            
            # تحديد لغة البرمجة
            if filename.endswith('.py'):
                result["language"] = "python"
                if 'import requests' in content_str or 'urllib' in content_str:
                    result["has_network"] = True
                if 'open(' in content_str or 'file(' in content_str:
                    result["has_file_operations"] = True
                if 'eval(' in content_str or 'exec(' in content_str:
                    result["has_obfuscation"] = True
                    result["suspicious"].append("Dynamic code execution (eval/exec)")
                if 'base64' in content_str and ('decode' in content_str or 'encode' in content_str):
                    result["suspicious"].append("Base64 encoding detected")
                    
            elif filename.endswith('.js'):
                result["language"] = "javascript"
                if 'XMLHttpRequest' in content_str or 'fetch(' in content_str:
                    result["has_network"] = True
                if 'eval(' in content_str:
                    result["has_obfuscation"] = True
                    result["suspicious"].append("Dynamic eval() detected")
                    
            elif filename.endswith(('.ps1', '.psm1')):
                result["language"] = "powershell"
                if 'Invoke-WebRequest' in content_str or 'DownloadFile' in content_str:
                    result["has_network"] = True
                    result["suspicious"].append("Network download detected")
                if '-EncodedCommand' in content_str:
                    result["has_obfuscation"] = True
                    result["suspicious"].append("Encoded command detected")
                    
            elif filename.endswith(('.sh', '.bash')):
                result["language"] = "bash"
                if 'curl ' in content_str or 'wget ' in content_str:
                    result["has_network"] = True
                if 'rm -rf' in content_str:
                    result["suspicious"].append("Dangerous delete command (rm -rf)")
                    
            return result
            
        except Exception as e:
            return {"is_script": False, "error": str(e)}
    
    def comprehensive_analysis(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """التحليل الشامل للملف"""
        file_size = len(file_content)
        
        # التحذيرات
        warnings = []
        if file_size == 0:
            warnings.append("File is empty")
        if file_size > self.max_size:
            warnings.append(f"File exceeds size limit ({self.max_size // 1024 // 1024} MB)")
        
        # تحليل أساسي
        hashes = self.calculate_hashes(file_content)
        file_type = self.detect_file_type(file_content, filename)
        
        if file_type.get("is_spoofed"):
            warnings.append(f"Extension spoofing! Actually {file_type.get('actual_type')}")
        
        # تحذير للملفات التنفيذية
        if file_type.get("is_executable"):
            warnings.append("Executable file - scan before running")
        
        result = {
            "filename": filename,
            "size_bytes": file_size,
            "size_mb": round(file_size / 1024 / 1024, 2),
            "hashes": hashes,
            "file_type": file_type,
            "warnings": warnings,
            "detailed_analysis": {}
        }
        
        # تحليل متخصص حسب نوع الملف
        if file_type.get("is_executable") or file_type.get("extension") in ['exe', 'dll', 'scr']:
            result["detailed_analysis"]["pe"] = self.analyze_pe_file(file_content)
        
        if file_type.get("mime_type") == "application/pdf" or filename.endswith('.pdf'):
            result["detailed_analysis"]["pdf"] = self.analyze_pdf(file_content)
        
        if file_type.get("is_document"):
            result["detailed_analysis"]["office"] = self.analyze_office_file(file_content, filename)
        
        if file_type.get("is_archive"):
            result["detailed_analysis"]["archive"] = self.analyze_archive(file_content, filename)
        
        if file_type.get("is_script"):
            result["detailed_analysis"]["script"] = self.analyze_script(file_content, filename)
        
        return result