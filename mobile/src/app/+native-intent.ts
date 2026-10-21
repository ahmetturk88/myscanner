/**
 * Links the phone hands to the app before the router sees them.
 * The Google/GitHub sign-in return (myscanner://auth?code=…) belongs to the
 * browser session in lib/oauth.ts, not to a screen; letting the router open it
 * showed an "Unmatched Route" page. Returning null keeps the current screen.
 */
const AUTH_RETURN = /^(?:myscanner:\/\/|exp:\/\/[^/]+\/--\/|\/(?:--\/)?)auth\/?(?:[?#]|$)/;

export function redirectSystemPath({ path }: { path: string; initial: boolean }) {
  return AUTH_RETURN.test(path) ? null : path;
}
