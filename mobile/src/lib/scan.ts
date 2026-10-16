import { router } from 'expo-router';

import { api } from '@/lib/api';

/** Queue a URL scan and open its live report. Throws ApiError with a readable message. */
export async function startUrlScan(url: string, replace = false) {
  const queued: any = await api.tool('url', { url: url.trim() });
  const target = { pathname: '/scan/[id]' as const, params: { id: String(queued.scan_id) } };
  if (replace) router.replace(target);
  else router.push(target);
}
