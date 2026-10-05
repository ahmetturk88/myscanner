# Runtime security configuration

Set APP_ENV=production on the VPS web process and all Celery processes.
Render services explicitly use production mode in render.yaml.

Set the same private SECRET_KEY on the web, worker, and Beat services.
Generate it locally with:
python -c "import secrets; print(secrets.token_urlsafe(48))"

Store it in the hosting environment, never in Git. Production refuses missing,
known placeholder, or shorter-than-32-character keys. Changing the key invalidates
existing sessions, remember-me cookies, and email-verification tokens.

Production disables Flask debug mode and requires HTTPS for session and remember-me
cookies. Terminate TLS at the web reverse proxy before launch.

Local development defaults to HTTP-compatible cookies and debug off.
FLASK_DEBUG=1 explicitly enables local debugging. Use a private local SECRET_KEY
in an ignored .env file to keep sessions and verification tokens across restarts.
If no usable local key exists, each process generates its own temporary key;
this fallback is only suitable for one local process, not production.

This change does not configure TLS, reverse-proxy trust, or the complete VPS deployment.
