# PDF evidence correction

PDF files are parsed with pinned pypdf 6.10.0 in a disposable Linux subprocess. The parser observes actual PDF objects, page count, metadata, action dictionaries, embedded-file indicators and explicit URI actions. Names and visible text do not automatically become active actions. Ordinary links are contextual observations rather than automatic threat findings.

Raw PDF bytes are excluded from generic regex IOC extraction and literal threat-pattern scoring, which otherwise produce false findings from compressed data and report text. PDF IOCs now come only from explicitly parsed URI action strings. Launch and JavaScript action dictionaries remain reported, including indirect references.

Limits: 10 MiB input, 1000 pages, 10,000 traversed nodes, 40 graph levels, six-second wall timeout, three-second CPU limit, 256 MiB address-space limit, 1 MiB output and no core dump. All temporary files are removed after success, timeout or failure. Malformed, encrypted, unavailable or budget-limited results disclose missing evidence rather than asserting safety. Parsing does not execute scripts, render pages, fetch links, decompress content streams for threat matching or inspect embedded payload behavior.

Docker images install the pinned parser. Host test dependencies include pypdf and reportlab. Native-isolation checks run on Linux; Windows reports parser unavailable and skips native subprocess tests. Rebuild the Docker image and rescan the same PDF to validate the actual user file; its pasted JSON alone cannot reproduce the original bytes.
