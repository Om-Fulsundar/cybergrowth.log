# ORM Injection

## 1. What is ORM Injection
ORM Injection occurs when user input is used unsafely to build ORM queries or raw queries inside an ORM layer. Developers assume ORMs prevent SQL injection, but unsafe methods (raw queries, unescaped interpolations, whereRaw, .extra(), etc.) let attackers manipulate query logic, causing authentication bypass, data leakage, and unauthorized changes.

Common ORMs:
- Laravel Eloquent (PHP)  
- Django ORM (Python)  
- Hibernate (Java)  
- Active Record (Rails)  
- Entity Framework (.NET)  
- Sequelize (Node.js)

---
## 2. How to detect ORM usage (practical signs)
- Error messages with class traces (e.g., Illuminate\Database\QueryException).  
- Framework-specific session cookies: `laravel_session`, `JSESSIONID`, `_rails_session`.  
- RESTful URLs and resource patterns (e.g., `/users/123/edit`).  
- Parameters such as `?sort=`, `?filter=`, `?order=`, or JSON filters in POST bodies.  
- JavaScript/source comments referencing ORM methods (whereRaw, findBy, objects.raw).

---

## 3. Dangerous ORM patterns to watch
- Interpolated/raw strings:
  - Laravel: `whereRaw("email = '$email'")`, `DB::raw(...)`  
  - Django: `User.objects.raw("SELECT ... '%s' " % email)`  
  - Rails: `where("name = '#{input}'")`  
  - Hibernate: `createQuery("... '" + input + "'")`
- Methods that accept raw SQL or raw clauses (`whereRaw`, `.raw()`, `.extra()`, `sequelize.query()`).
- Sorting or limit parameters inserted directly into SQL fragments (ORDER BY, LIMIT).

---

## 4. Quick test payloads (start non-destructive)
- Basic tautology: `1' OR '1'='1`  
- Single quote close: `' OR '1'='1`  
- Comment terminator: `' --` or `'; --`  
- UNION test (if applicable): `' UNION SELECT NULL --`  
- Time-based (blind): `' OR (SELECT SLEEP(5)) --` (use carefully and with permission)

Apply these in:
- Login fields  
- Search inputs  
- `sort` / `order` / `filter` query parameters  
- JSON filter objects (`{"name":"1' OR '1'='1"}`)

---

## 5. Step-by-step exploitation examples

### A. Authentication bypass (basic)
1. Identify a login endpoint that uses the ORM for authentication.  
2. Intercept the request and replace the username/password values with:
   - `username=1' OR '1'='1`  
   - `password=anything`
3. Send the request. If authentication passes, the application used raw input in the query.

Capture: original request, modified request, and response showing successful authentication.

---

### B. Blind injection (time-based)
1. When no visible output, prepare a payload that delays execution:
   - Example (MySQL syntax inside raw clause): `1' OR (SELECT SLEEP(5)) --`
2. Submit the payload and measure response time.
3. A consistent delay indicates injection.

Use measured, rate-limited tests to avoid service impact.

---

### C. Sort/filter parameter exploitation
1. Identify endpoints like `/users?sort=name` or `/list?order=price`.  
2. Try breaking out of ORDER BY or LIMIT clauses:
   - `?sort=name')); DROP TABLE users; --` (conceptual; do not run destructive payloads)  
   - Read-only example to expand results: `?sort=name')) LIMIT 100 --`
3. Observe errors or unexpected results that indicate direct interpolation.

---

### D. JSON/array operator injection (APIs)
1. For JSON APIs, attempt sending objects that could be interpreted as raw SQL:
   - `{"filter":{"name":"1' OR '1'='1"}}`
2. For frameworks like PHP that interpret `param[$ne]=...`, try array-style operator injection if applicable.

---

## 7. Framework-specific hints and methods

| Framework | Methods to watch |
|-----------|------------------|
| Laravel   | `whereRaw()`, `DB::raw()`, `selectRaw()` |
| Django    | `.raw()`, `.extra()` |
| Rails     | `where("... #{input} ...")` string interpolation |
| Hibernate | `createQuery("... " + input)` |
| Sequelize | `sequelize.query()` with strings |

When you see these methods in stack traces or source comments, increase scrutiny.

---

## 8. checklist (per endpoint)
1. Identify input type: form, query param, JSON body.  
2. Try basic injection payloads (tautology, quote break).  
3. Test sort/order/limit parameters for injection.  
4. Test search and filter functionality with injection payloads.  
5. If no output, use blind techniques (time-based, boolean).  
6. Capture request/response pairs and any DB error messages.  
7. If successful, limit validation to non-destructive read actions (profile fetch, listing).

---
