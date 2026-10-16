# MyScanner mobile app

Expo (SDK 58) app for Android, using the website's mobile API at `/api/mobile/v1`.
The API address is `expo.extra.apiBaseUrl` in `app.json`.

## Try it on your phone (Expo Go)

1. Install **Expo Go** from Google Play.
2. On your computer:

   ```
   cd mobile
   npm install
   npx expo start --tunnel
   ```

3. Scan the QR code shown in the terminal with Expo Go.

## Checks

```
npm run typecheck
npm run lint
```

## Structure

- `src/app/` screens (Expo Router): sign-in, tabs (Scan, History, Assistant, Account), URL report, tools, QR camera, account deletion
- `src/lib/api.ts` API client: bearer token in secure storage, streamed AI answers
- `src/components/` shared UI and the AI panel
