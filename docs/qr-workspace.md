# QR decoding and evidence workspace

The QR image is decoded in the browser. Decoding never submits the image or decoded URL to an API. An HTTP(S) payload offers a separate **Inspect decoded URL** action. The existing authenticated, permission-checked and CSRF-protected QR endpoint performs read-only WebAssessment checks with public-target DNS/connection and redirect controls. Optional url.vet remains unchecked by default.

## Interface and scope

The responsive workspace includes a decorative QR illustration, image preview, drag/drop and clipboard image paste, actual elapsed loading time, a five-sentence evidence brief, payload fields, warnings, copy and JSON/text-summary exports. Reduced motion and keyboard-visible focus states are supported. GIF decoding reads the browser-rendered frame; animated codes may vary. One readable QR payload is returned per image; crop images containing multiple codes.

Images are limited to 5 MB and 16 megapixels. Decoding tries normal/inverted QR pixels, with a 1,600-pixel fallback for large images that did not decode at native resolution. This does not promise support for damaged codes or other barcode formats. Payloads are capped at 8,192 characters; inspectable web links at 2,048. Credentials, control whitespace and backslashes disable inspection. Non-web application actions are never executed.

Recognized payloads: HTTP(S), text, Wi-Fi, mailto, tel, SMS/SMSTO, vCard/MECARD, geo and custom schemes. Recognition is structural, not authenticity or safety verification. No call, message, Wi-Fi join or contact import is initiated.

Wi-Fi passwords and contact-card raw payloads are hidden by default and excluded from exports even after reveal. Explicit reveal enables sensitive-payload copying. Other decoded text, including URL query parameters, may contain private data: copy/export/inspection remain user actions. No payload is placed in localStorage. Clearing an image resets provider consent and clears decoded state.

URL coverage is the fraction of selected checks completed (including a completed invalid-certificate finding); `not_requested` and `not_applicable` checks are excluded. Unavailable/partial checks reduce coverage. The ring is absent before assessment and after failure, and is **not a safety probability**. A failed inspection preserves the decoded payload, reports the attempted failure, and does not retain an old assessment. A 45-second client timeout bounds waiting; it does not cancel an already-running server assessment.

## Local decoder provenance

`static/vendor/jsQR-1.4.0.js` is the unmodified upstream browser distribution from `cozmo/jsQR` commit `8e6a036beafa7053dd44b1b76ac578d22b1b3311`, whose package version is 1.4.0. Apache-2.0 license is retained in `static/vendor/jsQR-LICENSE.txt`. It replaces the external CDN script.

## Verification

```powershell
python -m unittest discover -s tests -p test_qr_workspace.py -v
python -m unittest discover -s tests -p test_qr_subdomain_xss.py -v
python -m unittest discover -s tests -p test_web_assessment.py -k AssessmentTests -v
```

Node.js is required for executable JavaScript checks. Fixtures contain only synthetic, non-sensitive QR contents. Actual jsQR decoding is tested against generated matrices in normal, inverted and rotated orientations. Controller tests simulate DOM/image/fetch behavior for explicit opt-in, failed reads, oversized images, stale evidence removal, retries, sensitive export/copy and object-URL cleanup. Shared XSS tests exercise literal rendering and bound actions; WebAssessment tests cover private targets/redirects and provider failure/opt-in.

Local verification: 22 selected Python tests passed, including 71 JavaScript assertions for payload/decode/workflow behavior. Browser visual verification and real Docker endpoint rehearsal remain separate checks. Review desktop/mobile appearance, upload a QR encoding an authorized web target, decode it, and explicitly inspect it. Also try text, Wi-Fi and an unreadable image.
