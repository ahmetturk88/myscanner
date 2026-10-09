# URL report interface

The report presents the existing overall assessment without changing its scoring policy. A browser and link illustration, responsive evidence cards and native disclosure sections organize the saved report.

Loading uses the actual queued/running/report states returned by the application; it does not invent a completion percentage. Reduced-motion preferences disable decorative animation. Refresh reads the existing scan.

Source cards distinguish observations, limited coverage, dataset matches and unavailable evidence. The link journey shows recorded redirects and destination URLs as escaped text without clickable target links. Missing hops are not inferred.

Users can search disclosure sections, expand or collapse evidence, copy a concise report, and export JSON or CSV. CSV cells guard against formula injection. Exported summaries explain that the score is not a probability or guarantee of safety.

Validation: test_url_report_ui.py executes the production JavaScript for loading states, disclosure search, copy summary, source states, redirect escaping and CSV safety. test_scan_result_xss.py verifies hostile provider data and template escaping. Review desktop and mobile appearance in the running rehearsal stack before merging.
