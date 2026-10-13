"""Transactional email layout. Every dynamic value is HTML-escaped here."""
from html import escape


def action_email(title, greeting, paragraphs, button_label=None, link=None, note=None, tone='#77dcff'):
    """Return (html, text) for a simple branded message with one optional button."""
    safe = lambda value: escape(str(value), quote=True)
    body = ''.join(f'<p style="margin:0 0 16px;color:#a9bbd2;font-size:15px;line-height:1.7">{safe(p)}</p>' for p in paragraphs)
    button = ''
    if button_label and link:
        button = (f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin:28px 0"><tr><td style="border-radius:12px;background:{tone}">'
                  f'<a href="{safe(link)}" style="display:inline-block;padding:14px 30px;font:700 15px Arial,sans-serif;color:#05202d;text-decoration:none;border-radius:12px">{safe(button_label)}</a></td></tr></table>'
                  f'<p style="margin:0 0 6px;color:#7f93ad;font-size:12.5px">If the button does not work, paste this link into your browser:</p>'
                  f'<p style="margin:0 0 20px;color:#77dcff;font:12px Consolas,monospace;word-break:break-all">{safe(link)}</p>')
    footer_note = f'<p style="margin:20px 0 0;padding:14px 16px;border-radius:10px;background:#0b1626;border:1px solid #1f3348;color:#9fb3cb;font-size:13px;line-height:1.6">{safe(note)}</p>' if note else ''
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#070d18">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#070d18;padding:32px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#0e1828;border:1px solid #213650;border-radius:20px;overflow:hidden;font-family:Arial,Helvetica,sans-serif">
<tr><td style="padding:26px 32px;background:linear-gradient(135deg,#123a55,#1a1240);border-bottom:1px solid #213650">
<span style="font:800 22px Arial,sans-serif;color:#eef6ff">My<span style="color:#77dcff">Scanner</span></span>
<span style="display:block;margin-top:4px;font:11px Consolas,monospace;letter-spacing:2px;color:#8ea6c0">EVIDENCE BEFORE TRUST</span></td></tr>
<tr><td style="padding:34px 32px 30px">
<h1 style="margin:0 0 18px;font:700 23px Arial,sans-serif;color:#eef6ff">{safe(title)}</h1>
<p style="margin:0 0 16px;color:#dbe8f6;font-size:15px">{safe(greeting)}</p>
{body}{button}{footer_note}
</td></tr>
<tr><td style="padding:18px 32px;border-top:1px solid #1b2d42;color:#6f86a0;font-size:12px;line-height:1.6">
MyScanner · Istanbul · <a href="mailto:info@myscanners.com" style="color:#8fd9f2">info@myscanners.com</a><br>
You received this email because of an action on your MyScanner account.</td></tr>
</table></td></tr></table></body></html>"""
    text_parts = [title, '', greeting, ''] + list(paragraphs)
    if button_label and link:
        text_parts += ['', f'{button_label}: {link}']
    if note:
        text_parts += ['', note]
    text_parts += ['', '— MyScanner', 'info@myscanners.com']
    return html, '\n'.join(str(p) for p in text_parts)
