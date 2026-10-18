import type { IconName } from '@/components/icon';

/** The tools, with the same names, descriptions and page copy as the website. */
export type ToolField = { label: string; placeholder: string; secure?: boolean; keyboard?: 'default' | 'email-address' | 'url' };
export type Tool = {
  name: string; title: string; short: string; menu: string; category: 'links' | 'identity' | 'files' | 'network';
  icon: IconName; aiTool: string; route?: '/qr' | '/file' | 'url';
  kicker: string; heading: string; accent?: string; lead: string; chips: string[]; steps: [string, string][];
  field?: ToolField; body?: (value: string) => unknown; action?: string;
};

export const CATEGORIES = [
  { key: 'all', label: 'All tools' }, { key: 'links', label: 'Links & pages' }, { key: 'identity', label: 'Identity' },
  { key: 'files', label: 'Files' }, { key: 'network', label: 'Infrastructure' },
] as const;

export const TOOLS: Tool[] = [
  { name: 'url', title: 'URL Scanner', short: 'URL Scanner', menu: 'Destination, content & source evidence', category: 'links', icon: 'link', aiTool: 'url', route: 'url',
    kicker: 'URL intelligence', heading: "What's behind this link?", accent: 'this link?',
    lead: 'Bring connection security, redirects, page content and available threat sources into one evidence report.',
    chips: ['URL identity', 'Content', 'Threat intelligence'], steps: [] },
  { name: 'site', title: 'Site Scanner', short: 'Site Scanner', menu: 'Read-only page & connection observations', category: 'links', icon: 'globe', aiTool: 'site',
    kicker: 'Website intelligence / read-only', heading: 'See beyond the homepage.', accent: 'the homepage.',
    lead: 'Follow the destination. Inspect its connection. Understand the evidence behind the page.',
    chips: ['HTTP & redirects', 'TLS identity', 'Static page evidence'],
    steps: [['Connection', 'Public DNS, redirect chain and certificate observations.'], ['Page', 'Headers, static HTML and form destinations without submission.'], ['Context', 'Source evidence, missing checks and portable exports.']],
    field: { label: 'Domain or public website URL', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: 'Inspect website' },
  { name: 'qr', title: 'QR Scanner', short: 'QR Scanner', menu: 'Decode payloads before taking action', category: 'links', icon: 'qr', aiTool: 'qr', route: '/qr',
    kicker: 'Decode · understand · decide', heading: 'Look beyond the QR code.', accent: 'QR code.',
    lead: 'A small square can carry a link, a password or an action. Reveal what is inside, then inspect web evidence on your terms.',
    chips: ['Camera decoding', 'Explicit URL inspection', 'Evidence first'],
    steps: [['Reveal', 'Decode the first readable QR payload without opening it.'], ['Decide', 'Links are only inspected when you choose to.'], ['Inspect', 'Run the full URL report on the decoded link.']] },
  { name: 'email', title: 'Email Checker', short: 'Email', menu: 'Routing, authentication & reputation', category: 'identity', icon: 'mail', aiTool: 'email',
    kicker: 'Email intelligence / Evidence first', heading: 'Know more. Trust with evidence.', accent: 'Trust with evidence.',
    lead: "Explore an email address's routing, sender protections and domain signals. One clear assessment, with every finding and every limitation explained. SPF dependencies, published DMARC policy and sampled mail infrastructure are audited.",
    chips: ['MX routing', 'SPF & DMARC', 'Domain signals'],
    steps: [['Understand the domain', 'See mail routing and sender-policy records, with the original evidence available for review.'], ['Know what is missing', 'Failed lookups, skipped probes and untested checks are separated from reported risk indicators.'], ['Take the evidence with you', 'Copy a readable report for follow-up.']],
    field: { label: 'Email address to investigate', placeholder: 'name@company.com', keyboard: 'email-address' }, body: (v) => ({ email: v }), action: 'Analyze address' },
  { name: 'password', title: 'Password Security', short: 'Password', menu: 'Guess resistance & breach exposure', category: 'identity', icon: 'key', aiTool: 'password',
    kicker: 'Password security / private by design', heading: 'Strength is more than a symbol.', accent: 'than a symbol.',
    lead: 'Understand predictable patterns, modelled guess resistance and breach exposure, each with its own evidence.',
    chips: ['Pattern-aware estimate', 'Opt-in exposure check', 'No password in reports'],
    steps: [['Guess resistance', 'Words, keyboard paths, repetitions and sequences influence the estimate.'], ['Exposure', 'A confirmed dataset match requires replacement regardless of strength.'], ['Account protection', 'Use unique credentials, a password manager, and MFA or passkeys.']],
    field: { label: 'Password to assess · 1–128 characters', placeholder: 'Never stored', secure: true }, body: (v) => ({ password: v, check_breaches: true }), action: 'Assess password' },
  { name: 'file', title: 'File Scanner', short: 'File Scanner', menu: 'Static inspection & hash reputation', category: 'files', icon: 'file', aiTool: 'file', route: '/file',
    kicker: 'File intelligence', heading: 'Every file has a hidden story.', accent: 'hidden story.',
    lead: 'Look beyond the filename. Explore its structure, embedded indicators and hash reputation in one evidence-led report.',
    chips: ['Static inspection', 'Hash reputation', 'Readable evidence'],
    steps: [['File identity', 'Size, format observations and cryptographic fingerprints.'], ['Static indicators', 'Embedded content and structure, inspected without running the file.'], ['Reputation', 'Hash lookups against available threat sources.']] },
  { name: 'ip', title: 'IP Lookup', short: 'IP Lookup', menu: 'Network metadata & community reports', category: 'network', icon: 'server', aiTool: 'ip',
    kicker: 'Network intelligence / read only', heading: 'One address. A clearer picture.', accent: 'A clearer picture.',
    lead: 'Explore the network behind an IP and review the available abuse evidence. Every source has a visible state.',
    chips: ['IPv4 + IPv6', 'Network & ASN', '90-day report window'],
    steps: [['Who operates it?', 'Organization, ASN and approximate location from the metadata provider.'], ['What was reported?', 'Community report counts and provider confidence, with a defined time window.'], ['What is still unknown?', 'Unavailable sources stay visible. Missing reports never become a safety guarantee.']],
    field: { label: 'Public IP address', placeholder: '8.8.8.8', keyboard: 'url' }, body: (v) => ({ ip: v }), action: 'Look up IP' },
  { name: 'domain', title: 'Domain Lookup', short: 'Domain', menu: 'Registration & DNS observations', category: 'network', icon: 'search', aiTool: 'domain',
    kicker: 'Domain intelligence / read only', heading: 'Understand the domain. See the evidence.', accent: 'See the evidence.',
    lead: 'Explore DNS records, registration history and the coverage behind every observation.',
    chips: ['DNS · 7 record types', 'Registration · RDAP', 'Evidence export'], steps: [],
    field: { label: 'Domain name', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: 'Look up domain' },
  { name: 'subdomain', title: 'Subdomain Finder', short: 'Subdomains', menu: 'Bounded discovery & hostname evidence', category: 'network', icon: 'layers', aiTool: 'subdomain',
    kicker: 'MyScanner / asset discovery', heading: 'Map the names. Understand the evidence.', accent: 'Understand the evidence.',
    lead: 'Discover subdomains through certificate history and DNS. Explore responses, certificates and wildcard signals in one focused workspace.',
    chips: ['DNS evidence', 'Certificate history', 'Read-only web observations'],
    steps: [['Collect candidates', 'Combine common names with certificate records.'], ['Verify observations', 'Separate DNS, web and certificate evidence.'], ['Explore the footprint', 'Filter results and inspect what was found.']],
    field: { label: 'Domain name', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v, include_ct: true }), action: 'Discover subdomains' },
  { name: 'ssl', title: 'SSL Checker', short: 'SSL Checker', menu: 'Verified TLS & certificate observations', category: 'network', icon: 'lock', aiTool: 'ssl',
    kicker: 'TLS intelligence / verified connection', heading: 'Inspect the trust behind the lock.', accent: 'behind the lock.',
    lead: 'Understand the certificate, hostname and negotiated connection, with clear boundaries around what was tested.',
    chips: ['Chain verification', 'Hostname identity', 'Renewal window'],
    steps: [['Identity', 'Trust and hostname checks stay enabled throughout the connection.'], ['Lifetime', 'Short-lived certificates can be valid and automatically renewed.'], ['Scope', 'A single handshake does not enumerate all supported protocols or prove website safety.']],
    field: { label: 'Domain or website URL', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: 'Inspect certificate' },
];

export const toolByName = (name?: string) => TOOLS.find((t) => t.name === name);

/** The first http(s) link in a piece of text, if any. */
export function findLink(text: string) {
  const match = text.match(/https?:\/\/[^\s<>"']+/i);
  return match ? match[0].replace(/[).,;!?]+$/, '') : null;
}
