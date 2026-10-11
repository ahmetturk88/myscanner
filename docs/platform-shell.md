# Brand and navigation shell

The shared base template uses the supplied MyScanner mark in navigation and browser icons, and the full supplied wordmark in the footer. Original PNG files are preserved.

Explore tools opens a native modal dialog with search and category filters. Ctrl/Command+K opens search. Escape dismisses the dialog; focus returns to its opener. Native modal behavior handles focus confinement. The footer also provides links when JavaScript is unavailable.

Authenticated navigation includes profile, workspace and threat intelligence. Logout remains a POST protected by the existing CSRF token. Anonymous navigation offers sign-in and public information. Tool descriptions describe evidence scope rather than engine counts or guarantees.

Animations respect reduced-motion settings. The thin header line indicates page scrolling, not scan progress or platform health. Footer contact details retain existing site contacts.

Validation: Python template tests cover both session states, escaping, POST logout, landmarks, original PNGs and safe rendering. Node syntax check passes. Browser installation failed in the authoring environment; manually verify native dialog focus/Escape, keyboard shortcut, 360px mobile layout, desktop layout and footer before release.
