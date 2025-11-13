# Multi‑Factor Authentication (MFA)

## 1. What is MFA
Multi‑Factor Authentication (MFA) requires two or more independent factors to verify a user’s identity. Common factor categories:
- Something you know — password, PIN  
- Something you have — authenticator app, hardware token, SMS to device  
- Something you are — biometrics (fingerprint, face)  
2FA is a subset of MFA with exactly two factors.

---

## 2. Common MFA methods
- TOTP (Time‑based One‑Time Passwords) — Google Authenticator, Authy; codes change every 30s  
- Push notifications — Duo, Google Prompt; user approves a prompt on their device  
- SMS OTP — codes sent by SMS (least secure: SIM swap, interception)  
- Hardware tokens — YubiKey, FIDO2; strong phishing‑resistant options  
- Email OTP, device fingerprints, and behavioral factors (typing, geo) are also used in conditional flows

---

## 3. Why MFA matters (threat model)
MFA prevents simple credential reuse and blocks many automated attacks (credential stuffing, basic brute force). Weak or misconfigured MFA, however, can be bypassed or undermined and still lead to account takeover.

Typical abuse scenarios:
- Phishing with real‑time relay captures (credential + OTP)  
- Logic flaws that grant full session before OTP validation  
- OTP leakage in responses or logs  
- Brute forcing OTP when rate limits are missing

---

## 4. Where to test (real‑world surfaces)
- Login flows (initial password step and the MFA step)  
- “Remember this device” and backup-code flows  
- Account recovery and MFA reset endpoints (SMS/email change flows)  
- API endpoints used for OTP verification (XHR / JSON responses)  
- Webhooks, notification endpoints and templates that might leak OTPs  
- Session/token issuance and how session state is promoted after OTP

---

## 5. Common vulnerabilities and how to test them

### 5.1 OTP leaked in responses
What to check:
- Inspect XHR/Network responses during verification and resends for OTP values  
- Search HTML/JS source for debug output or OTP variables

Test:
- Trigger OTP generation and watch the Network tab for any token returned in JSON or markup.

---

### 5.2 Session created before OTP verified (logic flaw)
What to check:
- After submitting password, see if an auth cookie or full session token is issued before completing MFA  
- Attempt to access protected pages immediately after password step

Test:
1. Login with correct credentials up to the MFA page.  
2. In a second request, attempt to access a protected resource using the same session/cookies.  
If access is allowed, MFA enforcement is bypassable.

Fix: Maintain a temporary session state (pre‑auth) and issue full authentication session only after successful OTP verification.

---

### 5.3 OTP brute force (no rate limits)
What to check:
- Are there lockouts, delays, CAPTCHA, IP limits on OTP attempts?

Test:
- Use Burp Intruder or scripted requests to submit many OTPs and observe rate limiting, account lockouts, or delays. Stop after a safe number and record behavior.

Mitigations: rate limits, progressive delays, lockouts with proper notification, CAPTCHA, device/IP check.

---

### 5.4 Weak OTP generation or predictable seeds
What to check:
- TOTP secret generation randomness and reuse across accounts
- Time window tolerance and seed management

Test:
- If you can access multiple accounts, check for pattern reuse or predictable secrets (rare in modern services but possible in misconfigured systems).

Mitigations: use secure RNG for seeds, enforce unique secrets per account, short TOTP windows when risk is high.

---

### 5.5 SMS/Mobile weaknesses (SIM swap, interception)
What to check:
- Is SMS the only recovery channel? Are recovery flows robust?  
- Are phone number change flows protected (re-authentication, secondary verification)?

Test:
- Enumerate recovery options; try initiating recovery flows and observe required verification steps.

Mitigations: prefer app/hardware tokens for high‑value accounts; protect phone‑change workflows.

---

### 5.6 Phishing via real‑time proxy (Evilginx style)
What it is:
- A proxy captures credentials, OTPs, and session cookies from victims and reuses them immediately.

What to check:
- Does the application bind sessions to device/browser fingerprints or revalidate on cookie reuse?  
- Are refresh tokens or session cookies protected (HttpOnly, Secure, SameSite)?

Test (allowed/test‑only): In a controlled environment or lab, simulate a phishing relay to test detection and binding behavior.

Mitigations: device binding, short session lifetime, check for anomalous IP/UA changes, use phishing‑resistant MFA (hardware/FIDO2).

---

## 6. Attack workflows (step‑by‑step examples)

### A. Logic‑flaw bypass (session promotion)
1. Submit username+password.  
2. Intercept responses: check for session cookie/authorization token issued at this step.  
3. If session exists, attempt access to protected endpoints without submitting OTP.  
4. If successful, record flow and the missing server‑side check.

Evidence: request/response pairs showing session token issuance and successful access.

---

### B. OTP exfiltration via API leakage
1. Trigger an OTP send (login or resend).  
2. Inspect all API responses (XHR, JSON, HTML) and logs visible in the client for OTP contents.  
3. If OTP appears, record the exact endpoint and response.

Evidence: network capture showing OTP in response body.

---

### C. Brute‑force OTP (rate limit testing)
1. Capture the OTP verification request template.  
2. Use Burp Intruder with a limited, ethical attempt set to test rate limiting and lockout behavior.  
3. Note thresholds and lockout behavior.

Evidence: logs showing attempt counts and server responses (429, 401, account lock).

---

### D. Phishing relay (Evilginx) — lab/test only
1. Set up controlled phishing relay and a test account you own.  
2. Capture credentials, OTP, and session cookies via the relay.  
3. Attempt to reuse cookies and confirm whether session is bound to device or revalidated.  
4. Report findings with proof only from test account.

Mitigations: device fingerprint checks, IP checks, short token lifetime, phishing‑resistant MFA.

---

## 7. Detection & validation checklist

- Check whether a full session token is granted before OTP validation  
- Inspect all XHR/API responses during OTP flows for leaked OTPs  
- Test for rate limiting on OTP verification (Intruder/scripts)  
- Verify recovery/phone‑change flows for weak protections  
- Check cookie/session binding (HttpOnly, Secure, SameSite, origin/device binding)  
- For push MFA, confirm revocation and prompt validation behavior

---

## 8. Practical testing tips & safe rules

- Always use test accounts or explicit permission when testing MFA flows.  
- Prefer non‑destructive proofs (response shows protected resource view only).  
- Log timestamps, request/response pairs, IPs, user‑agents for evidence.  
- Limit brute‑force tests to small, controlled bursts to avoid lockouts or service impact.  
- For phishing tests, use your own infrastructure and accounts in an isolated lab.

---
