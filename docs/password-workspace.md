# Password Security workspace

Strength is estimated locally on the application server with zxcvbn 4.5.0, including dictionary, keyboard, repetition, sequence and date patterns. The 0–100 index maps estimated log10 guesses linearly to 14, with a cap at 100. It is not a safety probability, mathematical entropy or a promised cracking time. Estimator rank and explanatory scope are returned separately. Dictionary coverage is language dependent; personal context, password reuse and account protection are not verified.

Inputs are 1–128 characters, never truncated or normalized. This bound limits estimator resource consumption. A missing or failed estimator yields unavailable strength, never a fabricated score. Raw estimator output contains passwords and matched substrings and is never returned. Fixed password examples have been removed.

Strength and breach exposure are separate. A confirmed Pwned Passwords dataset match always produces an exposed verdict and replacement advice without rewriting the strength estimate. Skipped, unavailable and valid negative matches remain distinct.

The authenticated CSRF-protected endpoint processes the entered password over HTTPS, enforces request quota, closes the request session and returns Cache-Control: no-store. It does not save the input, hash or matched tokens in reports or activity logs. Opt-in breach lookup sends only the first five SHA-1 characters, with Add-Padding and no redirects, and validates bounded streamed responses. Exceptions remain generic. This does not hide the prefix from HIBP or the application server's access to the entered input.

The browser generator uses getRandomValues with rejection sampling, generates 24 characters, and never automatically submits. Input is cleared after a successful assessment; visibility is reset on tab hiding. Clear cancels the pending request and removes displayed results. No localStorage, sessionStorage or password export is used. JSON export contains assessment data only. Clearing references is not a promise of secure memory erasure.

Validation: run test_password_workspace.py and test_password_workspace.cjs, plus test_password_breach_coverage.py and test_tool_result_xss.py in the complete checkout. Rebuild Docker and verify /password-check, both breach settings, generator, clear and keyboard/mobile layouts before merge.

References: https://github.com/dwolfhub/zxcvbn-python and https://haveibeenpwned.com/API/V3#PwnedPasswords.
