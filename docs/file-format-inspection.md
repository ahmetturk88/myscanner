# File format inspection

`services/format_inspectors.py` adds checks for the file types scams use most.
Nothing is executed, rendered or fetched; findings ask for review (suspicious)
and never confirm malware on their own. Only the antivirus engine or a hash
match confirms a threat (file-evidence-v5).

| Format | How it is recognised | What is checked | Review when |
|---|---|---|---|
| Android app (APK) | ZIP with `AndroidManifest.xml` | Package name, permissions (binary XML read by a small built-in parser), SMS receivers, signing certificate | Two or more takeover capabilities (SMS, accessibility, overlay, notifications, device admin) or a debug signing key |
| HTML page | `.html`/`.htm` name or `<html>` start | Password fields and where forms send them, redirects, scrambled scripts, linked sites | A password form, a redirect, or obfuscated script |
| SVG image | `.svg` name or `<svg>` start | Scripts, event handlers, `foreignObject` | Any code inside the image |
| Saved email (EML) | `.eml` name or mail headers | Sender and Reply-To domains, SPF/DKIM/DMARC results, attachment names, linked sites | A risky or disguised attachment, or a failed sender check |
| Office | Office detection | Macros (VBA and Excel 4.0, via oletools and `xl/macrosheets/`), auto-run events, commands that run programs or download, password locks | Any macro or a password lock |
| Image | Image detection | QR codes (zxing-cpp) and the link they hold | Never; the link is reported so the user can check it |

A failed APK, web, email or Office inspection is a missing check; a failed
QR decode is not, since images are otherwise fully checked. All report text has
Turkish translations in `services/i18n_tr.py` (tested in
`tests/test_format_inspectors.py`).
