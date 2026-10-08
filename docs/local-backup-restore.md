# Local PostgreSQL backup and restore rehearsal

Run from the repository with Docker Desktop and the local PostgreSQL container
running. These commands use only compose.local.yml and the fixed local database;
they do not connect to Render or replace the running database.

```powershell
python scripts/local_backup.py backup
```

The command uses a PostgreSQL custom-format dump, validates the archive catalogue,
copies it outside the repository into `%LOCALAPPDATA%\MyScanner\backups` on Windows,
and saves its size, UTC timestamp and SHA-256 in an adjacent `.dump.json` file.
On other systems the default is `~/.local/share/MyScanner/backups`.
Keep both files together. Failed copies are not published as completed archives.
The archive contains sensitive account and report data. Do not upload it to GitHub
or chat. Protect the directory with your OS account permissions and disk encryption;
the archive itself is not encrypted. No automatic deletion or scheduled backup is
configured by this change.

Copy the printed archive path into this command:

```powershell
python scripts/local_backup.py restore-check --backup "C:\path\to\myscanner-....dump"
```

The command rejects altered/mismatched archives before database creation. It creates
a new database with a random `myscanner_rehearsal_` name, restores with
`--single-transaction --exit-on-error --no-owner --no-privileges`, and runs explicit
migrations there. Hashes compare all restored public table rows before and after
migration; the final schema must match the application models except for the explicitly
retained legacy `user.sandbox_remaining` column. Its contents are preserved and
compared too; all other schema differences fail validation. Only success and
user/scan counts are printed. The rehearsal database is dropped in cleanup even
if restoration or validation fails. Only this invocation's generated database name
is used for DROP; callers cannot provide a database destination.

The comparison verifies preservation of restored data during migrations. It does
not compare the live database to the dump; the application may keep writing while
pg_dump takes its consistent snapshot. This is a local restore rehearsal, not a
production disaster recovery or migration procedure. PostgreSQL dump files must
come from a trusted source: restoration executes SQL from the archive.

Build the current local application image before restore-check. It runs the
verification code in a one-off bootstrap service with local administrative
credentials, without publishing ports or provisioning roles in the live database.

Production follow-up: hosted backup before expiry, encrypted off-host storage,
automatic schedule and retention, monitoring, and a restore rehearsal on the target
server. Those require deployment-specific settings and are not configured here.
