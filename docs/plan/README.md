# Plan (encrypted)

`plan.tar.gpg` holds the full business plan and its progress tracker
(`ROADMAP.md`) plus the final-decisions PDF. The repository is public, so the
plan is committed only in encrypted form (GPG, AES-256, passphrase). The
passphrase is held by the owner and is never committed.

Open it (asks for the passphrase):

    cd docs/plan
    gpg -d plan.tar.gpg | tar xf -

Re-lock after editing `ROADMAP.md`:

    tar cf - ROADMAP.md MyScanner-Final-Decisions.pdf | gpg --symmetric --cipher-algo AES256 -o plan.tar.gpg --yes

The decrypted files are git-ignored so they can't be committed by mistake.
Work sessions: ask the owner for the passphrase, read `ROADMAP.md` first, and
continue from its progress section.
