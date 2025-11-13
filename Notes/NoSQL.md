# NoSQL Injection (MongoDB-focused)

## 1. Theory — what NoSQLi is and why it matters
NoSQL Injection happens when untrusted input is used directly in NoSQL database queries (MongoDB, CouchDB, etc.), letting an attacker change query logic. Unlike classic SQLi, NoSQLi often abuses JSON-like operators ($ne, $gt, $regex, $in, $nin) or injects JavaScript into queries ($where). Impact includes authentication bypass, unauthorized data access, data exfiltration and, in rare cases, remote code execution when the database executes JS.

Core points:
- Many web frameworks/parsers convert array-like or object-style inputs automatically (e.g., PHP/Node handlers that parse `foo[$ne]=1` into objects).
- Injection is operator-based: an attacker supplies a structure the application treats as a query operator rather than plain data.
- Attack surfaces include login APIs, search/filter endpoints, and any API accepting JSON bodies.

---

## 2. Where to look (real‑world targets)
- Login forms and auth APIs (most valuable)  
- Search boxes, filters, and admin query UIs  
- JSON/REST APIs that take POST bodies (user, filter, query fields)  
- Any endpoint that accepts arrays/objects via URL-encoded params (e.g., `param[]`, `param[$ne]`)  
- Debug or error pages that reveal server language or stack traces

Why these matter: Login logic and filter endpoints usually build queries directly from user input — the easiest places to change query semantics.

---

## 3. Quick MongoDB recap (practical)
- Documents = JSON-like objects stored in collections  
- Typical query example (pseudo):  
  db.users.find({ username: USERINPUT, password: PASSINPUT })  
- Operators: `$ne`, `$gt`, `$lt`, `$regex`, `$in`, `$nin`, `$where` (JS execution)  
- If USERINPUT or PASSINPUT becomes an object with operator keys, the query changes behavior

---

## 4. Detection — simple probes to try first
- For URL-encoded bodies / form data:
  - Send `user[$ne]=` and `pass[$ne]=` to see if login bypasses
  - Send `user[$regex]=^admin` to test regex matching
- For JSON APIs:
  - POST body with `{"user":{"$ne":""},"pass":{"$ne":""}}`
  - POST body with `{"user":{"$regex":"^adm"},"pass":{"$ne":""}}`
- Observe differences: successful login, different error messages, or behavior (e.g., returning user data)

Start non-destructively: aim to detect changes in authentication or search results.

---

## 5. Exploitation techniques — step‑by‑step

### A. Login bypass via operator injection ($ne)
Goal: Authenticate without valid credentials.

Steps:
1. Capture a valid login request with Burp / browser devtools.
2. Modify POST body (form or JSON) to:
   - form: `user[$ne]=dummy&pass[$ne]=dummy`
   - JSON: `{"user": {"$ne": ""}, "pass": {"$ne": ""}}`
3. Send request. If authentication succeeds, the app used inputs directly in a query and is vulnerable.

Why it works: `{$ne: ""}` matches any non-empty value, turning the credential check into a tautology.

Evidence to capture:
- Original request, modified request, and server response showing successful login or different behavior.

---

### B. Login as specific user using $nin / exclusions
Goal: Force query to match a target user by excluding others.

Steps:
1. Send: `user[$nin][]=admin&pass[$ne]=dummy` or JSON `{"user":{"$nin":["admin"]},"pass":{"$ne":""}}`
2. Add multiple exclusions to influence which record is matched if the app iterates or favors the first match.

Use when `$ne` alone doesn't yield control but exclusion manipulation can.

---

### C. Password discovery via $regex (blind/iterative)
Goal: Determine password length/characters when direct output isn't available.

Steps:
1. Test length: `user=admin&pass[$regex]=^. {5}\$` (checks for 5-character password). In URL-encoded: `pass[$regex]=^.{5}$`
2. If query behavior indicates success for length, bruteforce characters position by position:
   - `pass[$regex]=^a....$` → check true/false
3. Iterate until full password reconstructed.

Notes:
- Use rate limits and ethical constraints — this is slow and noisy.
- Use Burp Intruder or scripted requests with small batches.

---

### D. Syntax injection via $where (JS execution) — high risk, rare
Goal: Inject JavaScript into a `$where` query to execute arbitrary logic.

Prerequisite: application must place user input into a `$where` string (bad practice).

Steps:
1. Find an endpoint that uses `$where` or returns errors showing JS evaluation.
2. Inject payloads that alter JS logic, e.g.:
   - Test: `admin' || 1==1 || 'x` (varies by how the string is concatenated)
3. If confirmed, craft `$where` payloads to return entire collections or filter as desired:
   - Example conceptual payload: `{"$where":"this.username == 'admin' || true"}` (real payload depends on app context)
4. Capture results.

Caution: `$where` allows powerful injection; only proceed with explicit permission and safeguards.

---

## 6. Practical examples and payload formats

1. URL‑encoded / form example (PHP apps often parse these into arrays):
   - `user[$ne]=&pass[$ne]=`
2. JSON POST:
   - `{"user":{"$ne":""},"pass":{"$ne":""}}`
3. Regex-based queries:
   - `{"user":"admin","pass":{"$regex":"^a"}}`
4. Nested structures or arrays:
   - `user[$in][]=admin&user[$in][]=john`

Adjust payload encoding to match the app's content-type (application/x-www-form-urlencoded vs application/json).

---

## 7. Hunting guide — a checklist for each endpoint
- Identify how input is handled: form, JSON, multipart.  
- Try operator payloads: `$ne`, `$regex`, `$gt`, `$lt`, `$in`, `$nin`.  
- For JSON endpoints, send object operators directly.  
- For form endpoints, try `param[$ne]=value` style.  
- Monitor for authentication bypass, unexpected data in responses, or different error messages.  
- If no visible output, use timing/boolean techniques and automation to infer results.

---
