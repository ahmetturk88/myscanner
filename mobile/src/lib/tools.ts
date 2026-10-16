/** The tools the app offers, and how each one's form maps to the API. */
export type ToolField = { key: string; label: string; placeholder: string; secure?: boolean; keyboard?: 'default' | 'email-address' | 'url' };
export type Tool = { name: string; title: string; hint: string; icon: string; field: ToolField; body: (value: string) => unknown; aiTool: string };

export const TOOLS: Tool[] = [
  { name: 'email', title: 'Email Checker', hint: 'Routing, authentication and reputation', icon: '@', aiTool: 'email',
    field: { key: 'email', label: 'Email address', placeholder: 'name@example.com', keyboard: 'email-address' }, body: (v) => ({ email: v }) },
  { name: 'domain', title: 'Domain Lookup', hint: 'Registration and DNS', icon: '◎', aiTool: 'domain',
    field: { key: 'domain', label: 'Domain', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
  { name: 'ssl', title: 'SSL Checker', hint: 'Certificate and TLS', icon: '🔒', aiTool: 'ssl',
    field: { key: 'domain', label: 'Domain or HTTPS URL', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
  { name: 'ip', title: 'IP Lookup', hint: 'Network and reputation', icon: '⌁', aiTool: 'ip',
    field: { key: 'ip', label: 'IP address', placeholder: '1.1.1.1', keyboard: 'url' }, body: (v) => ({ ip: v }) },
  { name: 'site', title: 'Site Scanner', hint: 'Website headers and observations', icon: '◍', aiTool: 'site',
    field: { key: 'domain', label: 'Website', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v }) },
  { name: 'subdomain', title: 'Subdomain Finder', hint: 'Publicly reported hostnames', icon: '☷', aiTool: 'subdomain',
    field: { key: 'domain', label: 'Domain', placeholder: 'example.com', keyboard: 'url' }, body: (v) => ({ domain: v, include_ct: true }) },
  { name: 'password', title: 'Password Security', hint: 'Strength and breach exposure', icon: '✱', aiTool: 'password',
    field: { key: 'password', label: 'Password to check', placeholder: 'Never stored', secure: true }, body: (v) => ({ password: v, check_breaches: true }) },
];

export const toolByName = (name?: string) => TOOLS.find((t) => t.name === name);
