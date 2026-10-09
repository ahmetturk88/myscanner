# Rehearsal performance and sizing

Run `python scripts/rehearsal_performance.py --seconds 30 --concurrency 2` after the four-file stack is healthy. The tool accepts loopback HTTPS port 8443 only, performs at most one home/health request per second per reader, and samples the stack's running containers with Docker stats. It does not start scans, change rows, or print credentials. TLS bypass is confined to the local rehearsal certificate. Parameters are bounded to 10–60 seconds and 1–4 readers.

Repeat with `--seconds 60 --concurrency 4` while you start representative authorized scans in the browser. Keep the same targets across runs, note whether results were cached, and record actual scan durations from the interface. Use harmless small text/PDF test files and targets you own. Test the services you intend to launch, not only health requests. Do not infer scanner throughput from home-page latency.

The client uses direct IPv4 loopback while retaining the original HTTP Host and TLS SNI. Each request opens a fresh connection, does not follow redirects, and measures connection, TLS and response-header wait separately. This avoids treating Windows localhost IPv6 fallback time as application latency. It does not measure browser connection reuse.

The output includes per-endpoint failures and p95 latency, peak container CPU/memory/PIDs, Docker Desktop's CPU/RAM allocation and a conservative sum of memory peaks. Container CPU 100% corresponds to roughly one logical CPU. The provisional memory floor adds 50% headroom and 1 GiB for the operating system; it is a planning envelope, not a capacity guarantee. Worker concurrency, browser page complexity, external-provider latency and cache behavior materially change requirements.

CPU sizing must use the representative scan run, not the idle baseline. Docker Desktop limits can bottleneck before the physical machine does. Re-run on the selected VPS before public launch, with longer sustained tests in a controlled deployment. Do not claim a server size or concurrent-user capacity until those measurements exist.

Optional: `--output` writes the same nonsensitive summary to a **new** path chosen by you. Existing files are not overwritten. Keep workload notes beside the measurements without passwords, cookies, email addresses or scanned URL query strings.
