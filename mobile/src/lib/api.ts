/**
 * Client for MyScanner's mobile API (/api/mobile/v1).
 * The sign-in token lives in the device's secure storage and is sent as a bearer token.
 */
import Constants from 'expo-constants';
import { fetch as streamingFetch } from 'expo/fetch';
import * as SecureStore from 'expo-secure-store';
import { Linking, Platform } from 'react-native';

import { t } from '@/lib/i18n';
import { getSettings } from '@/lib/settings';

const TOKEN_KEY = 'myscanner.token';
export const SITE = String(Constants.expoConfig?.extra?.apiBaseUrl || 'https://myscanners.com').replace(/\/$/, '');
const BASE = `${SITE}/api/mobile/v1`;

let token: string | null = null;
let onSignedOut: (() => void) | null = null;

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

// Secure storage on the phone; the browser preview falls back to localStorage.
const store = Platform.OS === 'web'
  ? {
      get: async () => globalThis.localStorage?.getItem(TOKEN_KEY) ?? null,
      set: async (v: string) => globalThis.localStorage?.setItem(TOKEN_KEY, v),
      remove: async () => globalThis.localStorage?.removeItem(TOKEN_KEY),
    }
  : {
      get: () => SecureStore.getItemAsync(TOKEN_KEY),
      set: (v: string) => SecureStore.setItemAsync(TOKEN_KEY, v),
      remove: () => SecureStore.deleteItemAsync(TOKEN_KEY),
    };

export async function loadToken() {
  token = await store.get();
  return token;
}

export async function saveToken(value: string | null) {
  token = value;
  if (value) await store.set(value);
  else await store.remove();
}

/** Called when the server says the token is no longer valid. */
export function setSignedOutHandler(handler: () => void) {
  onSignedOut = handler;
}

function headers(json = true): Record<string, string> {
  // The server writes report summaries in this language.
  const h: Record<string, string> = { Accept: 'application/json', 'Accept-Language': getSettings().language };
  if (json) h['Content-Type'] = 'application/json';
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function failure(response: { status: number; json(): Promise<any> }) {
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && token) {
    await saveToken(null);
    onSignedOut?.();
  }
  const fallback = response.status === 413 ? t('This file is larger than 50 MB.')
    : response.status === 429 ? t("Today's allowance is used up. It resets at 00:00 UTC.")
    : response.status >= 500 ? t('MyScanner is unavailable right now. Please try again in a minute.')
    : t('Something went wrong. Please try again.');
  return new ApiError(typeof data.error === 'string' ? data.error : fallback, response.status);
}

export async function request<T = any>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(BASE + path, {
      method: options.method || (options.body === undefined ? 'GET' : 'POST'),
      headers: headers(),
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new ApiError(t('No connection. Check your internet and try again.'), 0);
  }
  if (!response.ok) throw await failure(response);
  return response.json();
}

/** No byte from the server for this long means the answer stalled (network change, slow provider). */
const STREAM_IDLE_MS = 30_000;
/** A whole answer never takes longer than this; the user gets a retry instead of endless dots. */
const STREAM_TOTAL_MS = 120_000;
/** Redraw the growing answer at most this often; per-word redraws of a long chat jam slow phones. */
const STREAM_PAINT_MS = 90;

/**
 * POST and read a streamed AI answer (server-sent events).
 * onText receives the whole answer so far; resolves with the final event.
 */
export async function stream(path: string, body: unknown, onText: (text: string) => void): Promise<any> {
  const controller = new AbortController();
  let timedOut = false;
  const abort = () => { timedOut = true; controller.abort(); };
  let idle = setTimeout(abort, STREAM_IDLE_MS);
  const total = setTimeout(abort, STREAM_TOTAL_MS);
  const slow = () => new ApiError(t('The answer is taking too long. Please try again.'), 0);
  let painted = 0;
  let pending: ReturnType<typeof setTimeout> | null = null;
  let text = '';
  const paint = (force = false) => {
    if (pending) { clearTimeout(pending); pending = null; }
    const wait = STREAM_PAINT_MS - (Date.now() - painted);
    if (force || wait <= 0) { painted = Date.now(); onText(text); }
    else pending = setTimeout(() => paint(true), wait);
  };
  let reader: any = null;
  try {
    let response;
    try {
      response = await streamingFetch(BASE + path, { method: 'POST', headers: headers(), body: JSON.stringify(body), signal: controller.signal });
    } catch {
      throw timedOut ? slow() : new ApiError(t('No connection. Check your internet and try again.'), 0);
    }
    if (!response.ok) throw await failure(response);
    const type = response.headers.get('Content-Type') || '';
    if (!type.includes('text/event-stream') || !response.body) return await response.json();
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let final: any = null;
    for (;;) {
      let chunk;
      try {
        chunk = await reader.read();
      } catch {
        throw timedOut ? slow() : new ApiError(t('The answer was interrupted. Please try again.'), 0);
      }
      const { value, done } = chunk;
      clearTimeout(idle);
      idle = setTimeout(abort, STREAM_IDLE_MS);
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      let cut: number;
      while ((cut = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        for (const line of block.split('\n')) {
          if (!line.startsWith('data:')) continue;
          let event: any;
          try { event = JSON.parse(line.slice(5)); } catch { continue; }
          if (typeof event.delta === 'string') { text += event.delta; paint(); }
          else if (typeof event.error === 'string') throw new ApiError(event.error, 503);
          else if (event.done) final = event;
        }
      }
      if (done) break;
    }
    if (text) paint(true);
    if (!final) throw new ApiError(t('The answer was interrupted. Please try again.'), 0);
    return final;
  } finally {
    clearTimeout(idle);
    clearTimeout(total);
    if (pending) clearTimeout(pending);
    if (reader) reader.cancel().catch(() => {});
  }
}

/** An image the app downloads with the sign-in token (the page screenshot of a URL report). */
export function signedImage(path: string) {
  return { uri: BASE + path, headers: headers(false) };
}

/** Same clean-up the website applies to AI text: no tags, no Markdown emphasis or headings. */
export function plain(text: string) {
  return String(text)
    .replace(/<[^>]{0,200}>/g, '')
    .replace(/\*\*|__|`/g, '')
    .replace(/^\s{0,3}#{1,6}\s+/gm, '')
    .replace(/^(\s*)[*•]\s+/gm, '$1- ')
    .trim();
}

/**
 * A plain ASCII file name for the multipart header. The server keeps only an ASCII name
 * anyway (services/upload_validation.py), and some HTTP clients reject anything else there.
 */
export function uploadName(name: string) {
  const dot = name.lastIndexOf('.');
  const extension = dot > 0 ? name.slice(dot + 1).replace(/[^A-Za-z0-9]/g, '').slice(0, 10) : '';
  const stem = (dot > 0 ? name.slice(0, dot) : name).normalize('NFKD').replace(/[^\x20-\x7e]/g, '').replace(/["\\]/g, '').trim().slice(0, 120);
  return (stem || 'file') + (extension ? `.${extension.toLowerCase()}` : '');
}

/**
 * Upload one file as multipart form data (the file scanner), with progress from 0 to 1.
 *
 * This uses XMLHttpRequest, not fetch: in this Expo SDK the global fetch is expo/fetch, which
 * cannot send React Native's { uri } file parts, so every upload failed before leaving the
 * phone. XMLHttpRequest is React Native's own networking; it streams the file from its uri
 * (content:// or file://) without loading it into memory.
 */
export function upload<T = any>(path: string, file: { uri: string; name: string; mimeType?: string | null },
  onProgress?: (fraction: number) => void): Promise<T> {
  const form = new FormData();
  form.append('file', { uri: file.uri, name: uploadName(file.name), type: file.mimeType || 'application/octet-stream' } as any);
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', BASE + path);
    for (const [key, value] of Object.entries(headers(false))) xhr.setRequestHeader(key, value);
    xhr.timeout = 180_000;
    if (onProgress) xhr.upload.onprogress = (event) => { if (event.lengthComputable && event.total) onProgress(event.loaded / event.total); };
    const offline = () => reject(new ApiError(t('The file could not be uploaded. Check your internet and try again.'), 0));
    xhr.onerror = offline;
    xhr.ontimeout = offline;
    xhr.onload = async () => {
      const parsed = () => { try { return JSON.parse(xhr.responseText); } catch { return {}; } };
      if (xhr.status >= 200 && xhr.status < 300) resolve(parsed());
      else reject(await failure({ status: xhr.status, json: async () => parsed() }));
    };
    xhr.send(form);
  });
}

/** Poll a background task until it finishes; returns its result. */
export async function waitForTask(taskId: string, onStatus: (status: string) => void, isAlive: () => boolean = () => true) {
  for (let i = 0; i < 150 && isAlive(); i++) {
    const task: any = await request(`/tasks/${encodeURIComponent(taskId)}`);
    if (task.state === 'SUCCESS') return task.result;
    if (task.state === 'FAILURE') throw new ApiError(task.error || t('Analysis failed. Please retry.'), 0);
    onStatus(task.status || t('Working…'));
    await new Promise((r) => setTimeout(r, 2500));
  }
  throw new ApiError(t('This is taking longer than usual. Please try again later.'), 0);
}

export type Allowance = { service: string; label: string; remaining: number | null; limit: number | null; percent: number }[];
export type User = { id: number; username: string; email: string; role: string; allowance: Allowance };

export const api = {
  login: (email: string, password: string, device: string) =>
    request<{ token: string; user: User }>('/auth/login', { body: { email, password, device } }),
  logout: () => request('/auth/logout', { method: 'POST', body: {} }),
  providers: () => request<{ providers: string[] }>('/auth/providers'),
  exchange: (code: string, verifier: string, device: string) =>
    request<{ token: string; user: User }>('/auth/oauth/exchange', { body: { code, verifier, device } }),
  me: () => request<{ user: User }>('/me'),
  deleteAccount: (confirm_email: string) => request('/account/delete', { body: { confirm_email } }),
  tool: (name: string, body: unknown) => request(`/tools/${name}`, { body }),
  recent: () => request<{ scans: { id: number; url: string; verdict: string; summary: string; date: string }[] }>('/scans/recent'),
  scanStatus: (id: number) => request<{ id: number; status: string; verdict: string | null }>(`/scans/${id}/status`),
  scan: (id: number) => request(`/scans/${id}`),
  scanAnalysis: (id: number) => request(`/scans/${id}/analysis`),
  /** The assistant reads only server-made evidence: a saved report's number or a tool result's signed receipt. */
  createContext: (tool: string, source: { report_id: number } | { receipt: string }) =>
    request<{ id: string }>('/ai/contexts', { body: { tool, ...source } }),
};


/**
 * Opens a report as a PDF. The server builds it for the signed-in user and answers with a one-time
 * link that lives a few minutes; the phone's browser downloads and shows it (the app keeps no files).
 */
export async function openPdf(path: string, body?: unknown) {
  const { url } = await request<{ url: string }>(path, { method: 'POST', body: body ?? {} });
  if (typeof url !== 'string' || !url.startsWith('/api/mobile/v1/pdf/')) throw new ApiError(t('The PDF could not be prepared.'), 500);
  await Linking.openURL(SITE + url);
}
