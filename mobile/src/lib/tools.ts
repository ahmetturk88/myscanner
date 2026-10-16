import type { IconName } from '@/components/icon';

/** The tools the app offers, and how each one's form maps to the API. */
export type ToolField = { label: string; placeholder: string; secure?: boolean; keyboard?: 'default' | 'email-address' | 'url' };
export type Tool = {
  name: string; title: string; short: string; hint: string; icon: IconName; color: string; aiTool: string;
  field?: ToolField; body?: (value: string) => unknown; route?: '/qr' | '/file' | 'url';
};

export const TOOLS: Tool[] = [
  { name: 'url', title: 'URL Scanner', short: 'URL Scanner', hint: 'Destination, content and threat sources', icon: 'link', color: '#22d3ee', aiTool: 'url', route: 'url' },
  { name: 'site', title: 'Site Scanner', short: 'Site Scanner', hint: 'Website headers and connection', icon: 'globe', color: '#38bdf8', aiTool: 'site',
    field: { label: 'Website', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
  { name: 'qr', title: 'QR Scanner', short: 'QR Scanner', hint: 'Read a code before you open it', icon: 'qr', color: '#818cf8', aiTool: 'qr', route: '/qr' },
  { name: 'email', title: 'Email Checker', short: 'Email', hint: 'Routing, authentication and reputation', icon: 'mail', color: '#a78bfa', aiTool: 'email',
    field: { label: 'Email address', placeholder: 'name@example.com', keyboard: 'email-address' }, body: (v) => ({ email: v }) },
  { name: 'password', title: 'Password Security', short: 'Password', hint: 'Strength and breach exposure', icon: 'key', color: '#f472b6', aiTool: 'password',
    field: { label: 'Password to check', placeholder: 'Never stored', secure: true }, body: (v) => ({ password: v, check_breaches: true }) },
  { name: 'file', title: 'File Scanner', short: 'File Scanner', hint: 'Static inspection and hash reputation', icon: 'file', color: '#fb923c', aiTool: 'file', route: '/file' },
  { name: 'ip', title: 'IP Lookup', short: 'IP Lookup', hint: 'Network and community reports', icon: 'server', color: '#34d399', aiTool: 'ip',
    field: { label: 'IP address', placeholder: '1.1.1.1', keyboard: 'url' }, body: (v) => ({ ip: v }) },
  { name: 'domain', title: 'Domain Lookup', short: 'Domain', hint: 'Registration and DNS', icon: 'search', color: '#2dd4bf', aiTool: 'domain',
    field: { label: 'Domain', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
  { name: 'subdomain', title: 'Subdomain Finder', short: 'Subdomains', hint: 'Publicly reported hostnames', icon: 'layers', color: '#60a5fa', aiTool: 'subdomain',
    field: { label: 'Domain', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v, include_ct: true }) },
  { name: 'ssl', title: 'SSL Checker', short: 'SSL Checker', hint: 'Certificate and TLS', icon: 'lock', color: '#facc15', aiTool: 'ssl',
    field: { label: 'Domain or HTTPS URL', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
];

export const toolByName = (name?: string) => TOOLS.find((t) => t.name === name);

/** The first http(s) link in a piece of text, if any. */
export function findLink(text: string) {
  const match = text.match(/https?:\/\/[^\s<>"']+/i);
  return match ? match[0].replace(/[).,;!?]+$/, '') : null;
}
