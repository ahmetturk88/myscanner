# Host-side administrator bootstrap

The command is explicit and never runs during app import:
python make_admin.py --email existing-verified-account@example.invalid

It grants is_admin=True, role=admin, and existing modeled admin service quotas to
one existing verified account. It creates no account and does not modify passwords
or verification status. A missing, unverified, or ambiguous account causes failure.
Repeated promotion is harmless and does not reset an existing complete admin role.
There is no HTTP promotion endpoint or hardcoded account identity.

## Render without Shell

After this command is deployed, temporarily prepend it to the existing Start Command:
python make_admin.py --email "$BOOTSTRAP_ADMIN_EMAIL" && <original Start Command>

Set BOOTSTRAP_ADMIN_EMAIL to the exact account email in Render Environment.
Keep the original command and all its options unchanged after the &&.
Use && so an unsuccessful promotion does not continue silently.

After a successful deployment, verify the account can open /admin and
/admin/proxy-info. Restore the original Start Command and remove BOOTSTRAP_ADMIN_EMAIL.
The startup command should not be left as an ongoing privilege-granting mechanism.

Promotion operates on the database configured for the hosted service, not on the
laptop. If the service uses ephemeral local SQLite, database changes can be lost on
redeployment; verify persistent storage/database setup before using this workflow.
Do not substitute a hosted database connection string into chat or commit it to Git.
