# Google Play listing and forms

Copy-paste answers for Play Console. Every claim here matches the app as built
(MyScanner 0.6.0, `mobile/`) and the privacy policy at
https://myscanners.com/privacy. Re-check this file whenever the app gains a
new permission, SDK or data flow.

## App setup

| Field | Answer |
|---|---|
| App name | MyScanner |
| Default language | English (United States) – en-US |
| App or game | App |
| Free or paid | Free (a Pro subscription may be added later through Google Play Billing) |
| Category | Tools |
| Contact email | info@myscanners.com |
| Website | https://myscanners.com |
| Privacy policy URL | https://myscanners.com/privacy |

## Store listing

**Short description** (80 characters max, this is 72):

```
Check links, QR codes, files and emails for scams before you trust them.
```

**Full description** (4000 characters max):

```
Got a strange link, QR code, email or file? Check it with MyScanner before you open it.

MyScanner looks at the evidence and tells you in plain words what it found: what looks fine, what looks risky, and what to do next. Every report also keeps the full technical evidence for people who want the details.

WHAT YOU CAN CHECK
• Links – where a link really leads, its security certificate, look-alike names, and public threat lists (malware and phishing).
• QR codes – the app reads the code without opening it, so you can check the link first.
• Websites – connection, redirects and page signals, read-only.
• Files – static inspection and file-hash reputation. Files are never run, and the uploaded copy is deleted when the check ends.
• Email addresses – mail routing, SPF and DMARC protection, throwaway providers and blocklists.
• Passwords – strength estimate and an optional breach check that only sends a short hash prefix, never the password.
• Domains, IP addresses, subdomains and SSL certificates – registration, DNS, reputation and certificate checks.

CLEAR REPORTS
• A verdict you can understand: safe, be careful, not sure or dangerous.
• "Why we think so" lists the reasons behind the verdict.
• "What to do" gives simple next steps.
• "What we checked" shows every check and its result.
• Share a warning with the person who sent you the link.

AI ASSISTANT
Ask the built-in assistant to explain a report or answer security questions. The verdict always comes from MyScanner's checks, not from the AI.

PRIVACY FIRST
• No ads, no tracking, no selling of data.
• The camera is used only while you scan a QR code; the image stays on your phone.
• Delete your account and its data at any time from the app.

A scan checks known warning signs at one moment in time. It can't guarantee that something is safe.
```

**Graphics** (prepared separately):

- App icon 512×512 PNG (from `mobile/assets/images/icon.png`)
- Feature graphic 1024×500
- At least 2 phone screenshots (recommended 4–8): home, a dangerous link report,
  a safe report, QR scanner, file report, AI explanation, settings.

## App content

### Privacy policy
`https://myscanners.com/privacy`

### App access
**All or some functionality is restricted** – the tools need a signed-in account.
Create a dedicated reviewer account on myscanners.com (verified email, not your
own account) and enter its email and password **only in Play Console**. Never
put them in this repository or in chat. Instructions for the reviewer:

```
Sign in with the email and password above. All tools are on the Home tab. To test quickly: open "URL Scanner" from Home and scan https://example.com, or open the QR scanner and point it at any QR code.
```

### Ads
**No, my app does not contain ads.**

### Content rating (IARC questionnaire)
- Category: **Utility, Productivity, Communication or Other**
- Violence, sexuality, language, controlled substances, gambling: **No** to all
- Users can interact or exchange content with each other: **No** (the AI
  assistant is not another user; reports are private)
- Shares the user's current physical location: **No**
- Allows users to buy digital goods: **No** for now (update when Pro launches)
- Unrestricted internet access (web browser or search engine): **No**

Expected result: Everyone / PEGI 3.

### Target audience
**18 and over** only. Don't select younger ages: that brings in the Families
policy, which this app is not designed for.

### News app
**No.**

### Government app
**No.**

### Financial features
**My app doesn't provide any financial features.**

### Health
**My app doesn't have any health features.**

## Data safety

**Does your app collect or share any of the required user data types?** Yes
**Is all of the user data collected by your app encrypted in transit?** Yes (HTTPS only)
**Do you provide a way for users to request that their data is deleted?** Yes
– in the app (Account → Delete account) and at https://myscanners.com/account/delete

Data is **not shared**. The outside services listed in the privacy policy (threat
lists, AI providers, hosting) act as service providers for features the user
asks for, which Google's definition does not count as sharing.

| Data type | Collected | Optional? | Purpose | Notes |
|---|---|---|---|---|
| Personal info → Email address | Yes | Required | Account management | Sign-in and account emails |
| Personal info → Name | Yes | Required | Account management | Username / display name |
| Personal info → User IDs | Yes | Required | Account management | Account ID on our server |
| Files and docs | Yes | Optional | App functionality | Only a file the user picks to scan. **Processed ephemerally**: the upload is deleted when the check ends; the report and file hashes are kept |
| App activity → Other user-generated content | Yes | Optional | App functionality | Links, domains, IPs, emails submitted for checks; questions to the AI assistant |
| Personal info → Other info | Yes | Optional | App functionality | A password typed into the password checker. **Processed ephemerally**, never stored |

**Not collected** (answer "No"): location, contacts, phone number, photos and
videos (QR decoding happens on the phone), audio, calendar, SMS, health,
financial info, web browsing history, installed apps, device or other IDs,
crash logs or diagnostics from the app (the app has no analytics or
crash-reporting SDK).

## Permissions

| Permission | Why |
|---|---|
| CAMERA | Reading QR codes, only while the QR scanner is open |
| INTERNET | Talking to the MyScanner API |

The app does not request microphone, location, contacts, storage or
notification permissions. File scanning uses the Android file picker, which
needs no permission.

## Release

1. Build an app bundle: `npx eas-cli@latest build -p android --profile production`
   (produces an `.aab`; EAS keeps the upload key).
2. Play Console → Testing → **Closed testing** → create track → upload the `.aab`.
3. Add the 12+ testers (a Google Group or an email list) and share the opt-in link.
4. Keep at least 12 testers opted in for **14 days in a row**, then apply for
   production access.
