# JSON Web Tokens (JWT)

## What JWT is and why it matters : 
A JWT is a compact, URL-safe token used to transmit claims between parties. It’s widely used for stateless authentication: the server issues a token after login and the client sends it on subsequent requests. The server trusts the token’s signature and claims instead of keeping session state.

Structure (three dot-separated base64url parts): 
- Header — token type and algorithm (e.g., `{"alg":"HS256","typ":"JWT"}`)  
- Payload — claims (e.g., `sub`, `exp`, `role`)  
- Signature — integrity proof computed from header + payload and a key

Why this matters for attackers:
- If signature verification is incorrect or keys are weak, tokens can be forged or tampered with.
- Tokens often contain sensitive claims and can be replayed across services if audience checks are missing.
- Misconfigured token handling leads to account takeover or privilege escalation.

---

## Practical — Where to look and what to test
- Authentication response: look for `Authorization: Bearer <token>` or tokens returned in JSON after login.
- Client storage: localStorage, sessionStorage, cookies (check HttpOnly flag).
- API endpoints accepting tokens: Authorization header, cookies, or URL parameters.
- Public JWKS endpoints: `/.well-known/jwks.json`, `/jwks.json`, `/auth/jwks`.
- Code and libraries (if accessible): verify which algorithms are accepted and how keys are loaded.

Basic tools:
- JWT.io / JWT Editor / CyberChef for quick decoding and editing
- Burp Suite / Postman for injecting modified tokens into requests
- Hashcat / John for cracking weak HMAC secrets
- Small Python scripts (PyJWT) to sign/forge tokens locally

---

## Step‑by‑step tests and exploitation techniques

### 1) Inspect token contents (safe first step)
1. Capture a token (login or intercept request).  
2. Base64url decode header and payload (no key needed).  
3. Note claims: `sub`, `role`, `exp`, `aud`, `kid`, `jku`, `jwk` and any sensitive data.  
4. If payload contains secrets or sensitive fields, record it as sensitive‑data exposure.

Why: Decoding reveals whether sensitive data is present and what algorithm the server expects.

---

### 2) Test for missing or disabled signature verification
Goal: See if server accepts unsigned or tampered tokens.

Steps:
1. Change the header to `{"alg":"none"}` and remove signature (token becomes `<header>.<payload>.`).  
2. Send the modified token to the API in the same header/cookie slot.  
3. Observe response: if accepted, you have a critical bypass.

Why it works: Some implementations mistakenly accept `alg: none` and skip verification.

Evidence to capture: request, modified token, and authenticated response or API result.

---

### 3) Weak HMAC secret (HS256) — cracking and forging
Goal: Recover a weak symmetric secret, then forge tokens.

Steps:
1. Identify algorithm `HS256/HS512` in header.  
2. Use a captured token and run hashcat with mode 16500 (or equivalent) against a wordlist:  
   hashcat -a 0 -m 16500 <jwt> <wordlist>  
3. If key cracked, use a JWT tool or PyJWT to sign a new payload with the discovered secret (e.g., elevate `role` to `admin`).  
4. Replay forged token to API and verify privileges.

Why it works: HMAC uses a shared secret; weak keys are brute-forceable.

Evidence: cracked key, forged token, and privileged response.

---

### 4) Algorithm confusion (RS256 -> HS256 downgrade)
Goal: Use the server’s public key as an HMAC secret to forge tokens.

Steps:
1. Find server public key (from JWKS endpoint or published certs).  
2. Create a token with header `{"alg":"HS256"}`.  
3. Use the server public key string as the HMAC secret and sign the token.  
4. Send token to API and check if accepted.

Why it works: If server uses the same verification code path and treats HS and RS keys interchangeably, it may verify HMAC-signed tokens with the public key as secret.

Evidence: public key source, forged token accepted by server.

---

### 5) JWK / JKU / KID injection attacks
Goal: Trick server into using attacker-controlled keys.

A) JWK injection (public key in token header)
Steps:
1. Generate an RSA keypair locally.  
2. Add the matching public key in the JWT header under `jwk`.  
3. Sign token with your RSA private key.  
4. Send token; if server pulls the key from header and uses it to verify, token is accepted.

B) JKU injection (external URL to JWKS)
Steps:
1. Host a JWKS JSON containing your public key at `https://attacker.example/jwks.json`.  
2. Set token header `jku` to that URL and set `kid` to match the key id.  
3. Sign token with your private key and send it.  
4. If server fetches and trusts your JWK, token verifies.

C) KID path injection
Steps:
1. If server resolves `kid` to a file path or remote resource, set `kid` to a path you control or to something like `/dev/null`.  
2. If server loads that as the key (unsanitized) and accepts an empty/attacker-supplied secret, token can be forged.

Why these work: Servers that accept dynamic keys from token headers and do not restrict key sources are exploitable.

Evidence: hosted JWKS, attacker-signed token accepted by server, server logs showing JKU fetch (if available).

---

### 6) Missing/long expiry and token replay
Goal: Use long-lived or missing `exp` tokens to maintain access.

Steps:
1. Check the `exp` claim in decoded payload. If missing or far future, note it.  
2. Reuse the token on the API from a different IP/session to confirm replayability.  
3. If token is valid indefinitely, demonstrate read-only resource access first.

Why it matters: Long-lived tokens increase window for abuse if leaked.

Evidence: token with no/long expiry, successful replay from different environment.

---

### 7) Audience (`aud`) and issuer (`iss`) validation bypass
Goal: Reuse tokens issued for one service on another that fails to verify `aud`/`iss`.

Steps:
1. Decode token and note `aud` and `iss`.  
2. Send token to another service in the same ecosystem that might accept shared tokens.  
3. If service ignores `aud`/`iss`, it may accept the token and grant unintended access.

Why: Microservices sometimes skip audience checks, enabling cross-service token replay.

Evidence: token used on Service A but accepted by Service B without proper audience validation.

---

### 8) Sensitive data in payload
Goal: Identify secrets embedded in the JWT payload.

Steps:
1. Decode payload and inspect for credentials, API keys, flags, or PII.  
2. If found, record exact fields and where token is issued. This is an information exposure finding, not exploitation.

Why: Tokens are stored client-side and base64-decoding leaks any embedded secrets.

Evidence: decoded payload showing sensitive fields.

---

## Detection and validation guidance (safe, non-destructive)
- Always start with decoding — no key required.  
- Make one change at a time and record request/response pairs.  
- When demonstrating a successful bypass, prefer read-only actions (profile fetch) over destructive ones.  
- Use test accounts and out-of-band collectors (for blind JKU/JWK hits) to capture server behavior.  
- Log the exact token used, endpoint, headers, timestamps, and response bodies.

---
