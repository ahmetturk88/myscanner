/**
 * Google / GitHub sign-in: the website's provider sign-in runs in the phone's
 * browser and returns a one-time code, which the app trades for its token.
 * A PKCE verifier proves the code was requested by this app.
 */
import * as Crypto from 'expo-crypto';
import * as Linking from 'expo-linking';
import * as WebBrowser from 'expo-web-browser';

import { ApiError, SITE } from '@/lib/api';

const toBase64Url = (base64: string) => base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function randomVerifier() {
  const bytes = Crypto.getRandomBytes(48);
  let binary = '';
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return toBase64Url(globalThis.btoa(binary));
}

/** Run the browser sign-in; resolves with the one-time code and its verifier. */
export async function providerSignIn(provider: string) {
  const verifier = randomVerifier();
  const challenge = toBase64Url(await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, { encoding: Crypto.CryptoEncoding.BASE64 }));
  const redirect = Linking.createURL('auth');
  const start = `${SITE}/api/mobile/v1/auth/oauth/${provider}?redirect=${encodeURIComponent(redirect)}&challenge=${challenge}`;
  const result = await WebBrowser.openAuthSessionAsync(start, redirect);
  if (result.type !== 'success') throw new ApiError('Sign-in was cancelled.', 0);
  const { queryParams } = Linking.parse(result.url);
  const error = queryParams?.error;
  const code = queryParams?.code;
  if (typeof error === 'string') throw new ApiError(error, 0);
  if (typeof code !== 'string') throw new ApiError('Sign-in did not complete. Please try again.', 0);
  return { code, verifier };
}
