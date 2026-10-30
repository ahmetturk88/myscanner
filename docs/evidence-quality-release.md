# Evidence quality and release checks

## Decision rules

- `email-evidence-v5`: brand-like domain/local-part names are review signals, not confirmation of fraud. A corporate registrar or an old registration does not establish brand ownership and must not suppress a lookalike warning. Supported Google Web Risk evidence can flag the domain's website; it does not authenticate the sender or every message.
- `email-evidence-v6`: one naming case is dangerous without a threat listing: a strong disguise (other-alphabet letters, swapped letters, a brand's domain in front of another, "https" in the name) or a bank, cargo or government brand in the name, on a domain registered less than 90 days ago. Old or undated look-alikes stay review; a registrar never suppresses the warning.
- `url-evidence-v13`: betting/casino content is a neutral content category. It carries no risk deduction and cannot by itself escalate the security verdict. Independent malicious listings, download detections and deceptive behavior still apply.
- `url-evidence-v14`: betting/casino content asks for care (suspicious, 10 points) because our users are in Turkey, where unlicensed betting is illegal and often keeps deposits. The wording says the licence was not verified. It never makes a link dangerous on its own; listings, malware and deceptive behaviour still decide that. Betting links from another site stay informational.
- Unknown/malformed source states are unavailable, never negative matches. An antivirus outage must not produce “nothing found.”
- URL analysis cache keys changed for fresh scans. Saved reports retain their recorded policy/verdict and expose the current policy separately; they are not silently rewritten.
- The mobile summary consumes the server's `plain` contract without scoring independently. Prototype-property names cannot select renderer tones or check styles. Web/mobile/PDF decision parity has an offline saved-report integration test.

## New fetch-path checks

The crawler and downloaded files use `PublicHTTPSession`: public-address validation, pinned connections, redirect validation and byte/deadline limits remain mandatory. Tests cover private/mixed DNS downloads without opening a socket, redirect/private IPv6 and DNS-rebinding cases, and a bounded crawl frontier. Link URLs are preserved for requests rather than truncated into a different request. The rendered-text provider response is streamed with a 64 KiB cap and closed immediately on overflow; redirects are disabled.

These are source-level/offline checks, not proof of the current VPS firewall or browser deployment. After deployment rerun `/app/egress-check.py` in web-egress, worker-egress, urlvet-egress and urlvet-browser-egress using the complete Compose overlay set. Do not remove the gateway to make a failed test pass. Check metadata-service addresses, IPv6 and redirect chains in a controlled fixture environment too.

## Quality evaluation

The old email benchmark accepted `review` for both controls and threat samples; it could pass a checker that warned about everything. It now fails on control false alarms, counts unknown/dead/invalid addresses as inconclusive and propagates failures from both batches. A phishing URL converted into `info@host` is explicitly a proxy, not verified malicious-mailbox ground truth.

For an independent holdout, supply private JSONL records with `id`, `email`, `label` (`clean` or `threat`), `provenance`, and ISO `observed_at` date:

```sh
python scripts/email_bench.py --dataset /private/independent-email-holdout.jsonl
```

Both labels and unique samples are required. It makes live provider requests and can consume quotas. It prints aggregate counts, precision, recall among decided samples, false-positive rate and decision coverage without printing the supplied addresses. Exit 1 means a false positive/negative; exit 2 means otherwise inconclusive. Unknowns are never removed to manufacture a perfect success rate.

Have an independent reviewer label and freeze the holdout *before* running it. Keep tuning and regression examples out of it. Stratify legitimate small businesses/free mail, new sites, Unicode, redirects, stale threat reports and unavailable sources; record date/source expiration and sample counts. No new live accuracy percentage is claimed by this patch. A real independently adjudicated corpus still needs collection and review.

## Performance

`scripts/load_test.py` accepts repeated `--target` URLs, distributes them across users and prints the distinct-target count. Targets outside the service host require `--ack-authorized-targets`. Use only owned/authorized fixtures. The runner now waits through `pending`, validates the saved analysis, fails unknown terminal states and records virtual-user exceptions.

```sh
python scripts/load_test.py --base https://YOUR-STAGING-HOST --users 4 \
  --target https://YOUR-STAGING-HOST/fixture-a \
  --target https://YOUR-STAGING-HOST/fixture-b
```

This command is a manual live workload, not run automatically by CI. Caches are NOT bypassed: record separate first-run and repeated-run results; use distinct controlled paths with distinct content when measuring cold scans. Do not infer uncached capacity from repeated scans of one URL. Compare end-to-end scans, queue wait, per-provider latency/coverage, failures and container peaks on the intended VPS. This patch does not select a production server size or claim a new live-load result.

## Release gates

CI adds mobile typecheck, lint, translation checks, report-contract execution and Android JavaScript/assets export. A bundle export does not create/sign an APK and does not test camera, deep links, document picker, OAuth, billing or installed-device rendering. Those require an installed build/device acceptance pass. No native version/build increment or store submission is implied here.

Before public launch: independent holdout evaluation; staged uncached mixed scans including bounded file uploads; all four live egress checks; installed Android acceptance; backup/restore and rollback rehearsal; source credential/quota checks; reviewed dependency-audit findings. The dependency audit remains explicitly advisory until its baseline is triaged. Merging this patch is not a claim that these live release gates passed.
