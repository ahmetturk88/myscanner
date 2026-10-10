# ZIP payload inspection

ZIP uploads now have bounded static member inspection in a disposable Linux subprocess. Member names are never used as filesystem paths. Uploaded code is never executed; decoded member bytes remain in memory.

Limits: 10 MiB input, 1 MiB per decoded member, 8 MiB cumulative decoded bytes, 100 entries across the tree, two nested ZIP levels, compression ratio at most 100, six seconds wall time, three seconds CPU, 256 MiB process address space and 1 MiB output. Temporary input/result files are deleted after success, failure or timeout.

Each read member receives a SHA-256 fingerprint and observed magic/text type. Literal code-related patterns are contextual observations, not malware detections. No member fingerprints are sent to external providers. Encrypted members, symbolic links, corrupt entries, excess budgets and unsupported nested formats remain explicitly unverified. RAR/7z uploads retain directory-only inspection. OpenXML retains its separate bounded XML checks.

The existing index retains the archive coverage deduction when member inspection is skipped or limited. A fully read ZIP still has partial overall coverage because no execution, sandbox or antivirus scan was performed. A high index is not a safety probability.

Validation:

```powershell
python -m unittest discover -s tests -p test_archive_payload.py -v
```

Native subprocess execution is intended for the Linux Docker runtime. Windows host runs report unavailable rather than decompressing without resource isolation.
