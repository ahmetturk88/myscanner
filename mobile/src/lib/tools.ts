import type { IconName } from '@/components/icon';
import { lang, t } from '@/lib/i18n';

export type ToolField = { label: string; placeholder: string; secure?: boolean; keyboard?: 'default' | 'email-address' | 'url' };
export type Tool = {
  name: string; title: string; short: string; menu: string; category: 'links' | 'identity' | 'files' | 'network';
  icon: IconName; aiTool: string; route?: '/qr' | '/file' | 'url';
  kicker: string; heading: string; accent?: string; lead: string; chips: string[]; steps: [string, string][];
  field?: ToolField; body?: (value: string) => unknown; action?: string;
};

export const categories = () => [
  { key: 'all', label: t('All tools') }, { key: 'links', label: t('Links & pages') }, { key: 'identity', label: t('Identity') },
  { key: 'files', label: t('Files') }, { key: 'network', label: t('Infrastructure') },
] as const;

/** The tools, with the same names, descriptions and page copy as the website, in the current language. */
function build(): Tool[] {
  return [
  { name: 'url', title: t('URL Scanner'), short: t('URL Scanner'), menu: t('Destination, content & source evidence'), category: 'links', icon: 'link', aiTool: 'url', route: 'url',
    kicker: t('URL intelligence'), heading: t("What's behind this link?"), accent: t('this link?'),
    lead: t('Bring connection security, redirects, page content and available threat sources into one evidence report.'),
    chips: [t('URL identity'), t('Content'), t('Threat intelligence')], steps: [] },
  { name: 'site', title: t('Site Scanner'), short: t('Site Scanner'), menu: t('Read-only page & connection observations'), category: 'links', icon: 'globe', aiTool: 'site',
    kicker: t('Website intelligence / read-only'), heading: t('See beyond the homepage.'), accent: t('the homepage.'),
    lead: t('Follow the destination. Inspect its connection. Understand the evidence behind the page.'),
    chips: [t('HTTP & redirects'), t('TLS identity'), t('Static page evidence')],
    steps: [[t('Connection'), t('Public DNS, redirect chain and certificate observations.')], [t('Page'), t('Headers, static HTML and form destinations without submission.')], [t('Context'), t('Source evidence, missing checks and portable exports.')]],
    field: { label: t('Domain or public website URL'), placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: t('Inspect website') },
  { name: 'qr', title: t('QR Scanner'), short: t('QR Scanner'), menu: t('Decode payloads before taking action'), category: 'links', icon: 'qr', aiTool: 'qr', route: '/qr',
    kicker: t('Decode · understand · decide'), heading: t('Look beyond the QR code.'), accent: t('QR code.'),
    lead: t('A small square can carry a link, a password or an action. Reveal what is inside, then inspect web evidence on your terms.'),
    chips: [t('Camera decoding'), t('Explicit URL inspection'), t('Evidence first')],
    steps: [[t('Reveal'), t('Decode the first readable QR payload without opening it.')], [t('Decide'), t('Links are only inspected when you choose to.')], [t('Inspect'), t('Run the full URL report on the decoded link.')]] },
  { name: 'email', title: t('Email Checker'), short: t('Email'), menu: t('Routing, authentication & reputation'), category: 'identity', icon: 'mail', aiTool: 'email',
    kicker: t('Email intelligence / Evidence first'), heading: t('Know more. Trust with evidence.'), accent: t('Trust with evidence.'),
    lead: t("Explore an email address's routing, sender protections and domain signals. One clear assessment, with every finding and every limitation explained. SPF dependencies, published DMARC policy and sampled mail infrastructure are audited."),
    chips: [t('MX routing'), t('SPF & DMARC'), t('Domain signals')],
    steps: [[t('Understand the domain'), t('See mail routing and sender-policy records, with the original evidence available for review.')], [t('Know what is missing'), t('Failed lookups, skipped probes and untested checks are separated from reported risk indicators.')], [t('Take the evidence with you'), t('Copy a readable report for follow-up.')]],
    field: { label: t('Email address to investigate'), placeholder: t('name@company.com'), keyboard: 'email-address' }, body: (v) => ({ email: v }), action: t('Analyze address') },
  { name: 'password', title: t('Password Security'), short: t('Password'), menu: t('Guess resistance & breach exposure'), category: 'identity', icon: 'key', aiTool: 'password',
    kicker: t('Password security / private by design'), heading: t('Strength is more than a symbol.'), accent: t('than a symbol.'),
    lead: t('Understand predictable patterns, modelled guess resistance and breach exposure, each with its own evidence.'),
    chips: [t('Pattern-aware estimate'), t('Opt-in exposure check'), t('No password in reports')],
    steps: [[t('Guess resistance'), t('Words, keyboard paths, repetitions and sequences influence the estimate.')], [t('Exposure'), t('A confirmed dataset match requires replacement regardless of strength.')], [t('Account protection'), t('Use unique credentials, a password manager, and MFA or passkeys.')]],
    field: { label: t('Password to assess · 1–128 characters'), placeholder: t('Never stored'), secure: true }, body: (v) => ({ password: v, check_breaches: true }), action: t('Assess password') },
  { name: 'file', title: t('File Scanner'), short: t('File Scanner'), menu: t('Static inspection & hash reputation'), category: 'files', icon: 'file', aiTool: 'file', route: '/file',
    kicker: t('File intelligence'), heading: t('Every file has a hidden story.'), accent: t('hidden story.'),
    lead: t('Look beyond the filename. Explore its structure, embedded indicators and hash reputation in one evidence-led report.'),
    chips: [t('Static inspection'), t('Hash reputation'), t('Readable evidence')],
    steps: [[t('File identity'), t('Size, format observations and cryptographic fingerprints.')], [t('Static indicators'), t('Embedded content and structure, inspected without running the file.')], [t('Reputation'), t('Hash lookups against available threat sources.')]] },
  { name: 'ip', title: t('IP Lookup'), short: t('IP Lookup'), menu: t('Network metadata & community reports'), category: 'network', icon: 'server', aiTool: 'ip',
    kicker: t('Network intelligence / read only'), heading: t('One address. A clearer picture.'), accent: t('A clearer picture.'),
    lead: t('Explore the network behind an IP and review the available abuse evidence. Every source has a visible state.'),
    chips: ['IPv4 + IPv6', t('Network & ASN'), t('90-day report window')],
    steps: [[t('Who operates it?'), t('Organization, ASN and approximate location from the metadata provider.')], [t('What was reported?'), t('Community report counts and provider confidence, with a defined time window.')], [t('What is still unknown?'), t('Unavailable sources stay visible. Missing reports never become a safety guarantee.')]],
    field: { label: t('Public IP address'), placeholder: '8.8.8.8', keyboard: 'url' }, body: (v) => ({ ip: v }), action: t('Look up IP') },
  { name: 'domain', title: t('Domain Lookup'), short: t('Domain'), menu: t('Registration & DNS observations'), category: 'network', icon: 'search', aiTool: 'domain',
    kicker: t('Domain intelligence / read only'), heading: t('Understand the domain. See the evidence.'), accent: t('See the evidence.'),
    lead: t('Explore DNS records, registration history and the coverage behind every observation.'),
    chips: [t('DNS · 7 record types'), t('Registration · RDAP'), t('Evidence export')], steps: [],
    field: { label: t('Domain name'), placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: t('Look up domain') },
  { name: 'subdomain', title: t('Subdomain Finder'), short: t('Subdomains'), menu: t('Bounded discovery & hostname evidence'), category: 'network', icon: 'layers', aiTool: 'subdomain',
    kicker: t('MyScanner / asset discovery'), heading: t('Map the names. Understand the evidence.'), accent: t('Understand the evidence.'),
    lead: t('Discover subdomains through certificate history and DNS. Explore responses, certificates and wildcard signals in one focused workspace.'),
    chips: [t('DNS evidence'), t('Certificate history'), t('Read-only web observations')],
    steps: [[t('Collect candidates'), t('Combine common names with certificate records.')], [t('Verify observations'), t('Separate DNS, web and certificate evidence.')], [t('Explore the footprint'), t('Filter results and inspect what was found.')]],
    field: { label: t('Domain name'), placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v, include_ct: true }), action: t('Discover subdomains') },
  { name: 'ssl', title: t('SSL Checker'), short: t('SSL Checker'), menu: t('Verified TLS & certificate observations'), category: 'network', icon: 'lock', aiTool: 'ssl',
    kicker: t('TLS intelligence / verified connection'), heading: t('Inspect the trust behind the lock.'), accent: t('behind the lock.'),
    lead: t('Understand the certificate, hostname and negotiated connection, with clear boundaries around what was tested.'),
    chips: [t('Chain verification'), t('Hostname identity'), t('Renewal window')],
    steps: [[t('Identity'), t('Trust and hostname checks stay enabled throughout the connection.')], [t('Lifetime'), t('Short-lived certificates can be valid and automatically renewed.')], [t('Scope'), t('A single handshake does not enumerate all supported protocols or prove website safety.')]],
    field: { label: t('Domain or website URL'), placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }), action: t('Inspect certificate') },
  ];
}

let cache: { lang: string; tools: Tool[] } | null = null;
export function tools(): Tool[] {
  if (cache?.lang !== lang()) cache = { lang: lang(), tools: build() };
  return cache.tools;
}

export const toolByName = (name?: string) => tools().find((tool) => tool.name === name);

/** The first http(s) link in a piece of text, if any. */
export function findLink(text: string) {
  const match = text.match(/https?:\/\/[^\s<>"']+/i);
  return match ? match[0].replace(/[).,;!?]+$/, '') : null;
}
