"""File narrative for PDF export; uses observations, never a guessed file purpose."""
def file_report_summary(d):
    m=d.get('metadata') or {};mb=d.get('malwarebazaar') or {};ft=d.get('file_type') or {};a=d.get('assessment') or {}
    out=[f"The observed file format is {str(ft['actual_type']).upper()}; this describes its structure, not its safety." if ft.get('actual_type') else 'The file format was not established by the reported checks.']
    if m.get('is_archive') is True:
        count=m.get('num_files')
        payload=m.get('payload_inspection') or {}
        out.append(f"Bounded static inspection read {payload.get('inspected_members', 0)} archive members; skipped members remain unverified." if payload.get('status') in ('assessed','partial') else f'The archive directory contains {count} entries; member payloads and nested archives were not inspected.' if type(count) in (int,float) else 'The archive directory could not be fully enumerated.')
        out.append('Encrypted members were reported; their contents remain unverified.' if m.get('encrypted') is True or m.get('encrypted_members') else 'Script files appear in the directory; their presence alone is not a malware finding.' if m.get('contains_script') is True else 'No member execution, sandbox or antivirus test was performed.' if payload.get('status') in ('assessed','partial') else 'Member payloads and nested archives were not inspected.')
    else:
        out.append('Local metadata could not be verified.' if m.get('error') or m.get('metadata_error') else 'The report contains static observations only; no file execution or sandbox test was performed.')
    out.append('A malicious verdict or confirmed hash match was reported. Keep the file unexecuted.' if d.get('verdict')=='malicious' or (mb.get('status')=='matched' and mb.get('is_malicious') is True) else 'The queried hash was not found in MalwareBazaar; this is not a clean-file verdict.' if mb.get('status')=='not_found' else 'A verified MalwareBazaar hash result is unavailable.')
    score=a.get('score');penalty=a.get('coverage_penalty',0)
    out.append(f'The evidence index is {score}/100, with {penalty} coverage points deducted. It is not a probability of safety.' if type(score) in (int,float) else 'No evidence index was recorded; missing checks do not establish safety.')
    return out[:5]
