# Authentication request limits

Counters use atomic SQLite/PostgreSQL upserts and are committed separately from
login transactions. All application processes must share the database and SECRET_KEY.
Counter keys are HMAC hashes; email addresses and IP addresses are not stored in this table.

Defaults:
- Login: 20 POST attempts per account per 15 minutes, and 60 per client address.
- Registration: 5 POST attempts per client address per hour.
- Verification email: 1 attempt per minute and 3 per hour per user, including registration.

Successful and unsuccessful attempts count. A throttled request returns HTTP 429,
Retry-After, and a styled waiting page. Windows expire automatically; expired records
older than a day are deleted when limits are checked. This is throttling, not permanent
account suspension. Verification limits count requests, including rejected/send-failed
requests, so repeated requests cannot hammer the email provider.

CSRF validation runs before counting requests. Authentication POSTs fail closed with
503 if their rate-limit storage is unavailable. A failure later in verification checks
also prevents email sending.

Deployment: request.remote_addr is used; arbitrary X-Forwarded-For headers are ignored.
Before launch, configure and test trusted reverse-proxy handling separately. If the
proxy address is presented instead of the client address, users share that IP quota.
Do not trust forwarded headers from direct public clients.

The migration supports the current startup create_all behavior. For a controlled
deployment, apply migrations before serving traffic. PostgreSQL SQL is supported by
the dialect-specific upsert; the automated concurrency tests run on SQLite.
