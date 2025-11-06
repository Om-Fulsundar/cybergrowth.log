
# Insecure Direct Object Reference (IDOR)

IDOR happens when a server exposes internal object references (like user IDs, file names, or tokens) without checking if the user is authorized to access them. If the app trusts user input blindly, attackers can tamper with parameters to access or modify other users' data.

Example:

GET /profile?user_id=1305 → change to → /profile?user_id=1000

If no access control is in place, the attacker can view someone else's profile.

---

## Discovery Techniques

1. Register two accounts: one attacker, one victim.
2. Perform an action or view data as the victim.
3. Capture the request (Burp Suite, browser dev tools).
4. Replay the request using the attacker account, replacing victim identifiers (e.g., user_id, file_id).
5. Check if unauthorized access is granted.

---

## Common Attack Vectors

- **Query parameters**  
  `/invoice?user_id=123`

- **POST body parameters**  
  `POST /update_profile { "user_id": "123" }`

- **Cookies or headers**  
  `X-User-ID: 123`

- **Hidden fields in HTML forms**

- **JavaScript files**  
  Look for hardcoded API paths or IDs.

- **XHR/API calls**  
  Use browser dev tools → Network tab to inspect backend requests.

---

## Exploitation Steps

### 1. Manual ID Swap
- Identify a parameter like `user_id`, `account_id`, or `file_id`.
- Change its value to another valid ID.
- Observe if the server returns data or performs actions without authorization.

### 2. Base64 Encoded IDs
- Example: `?id=MTIz` → decode to `123`
- Modify the decoded value → re-encode → replay the request

### 3. Hashed IDs
- If IDs are hashed (MD5, SHA1, etc.), try cracking them using:
  - crackstation.net
  - hashes.com
- Look for predictable patterns like `md5(123)` or `sha1(user_id)`

### 4. No Visible Parameter
- Inspect:
  - XHR/API requests
  - Hidden form fields
  - JavaScript code
- Use Burp Suite’s **Parameter Miner** to discover hidden parameters

### 5. Parameter Guessing
- Try adding parameters manually:
  
  /user/details → /user/details?user_id=124
  
  If it works, you’ve found an IDOR.

---

## Detection and Validation

- Always test with two separate accounts.
- Confirm that the attacker can access or modify data belonging to the victim.
- Avoid false positives by ensuring the data returned is actually unauthorized.
- Log out and replay requests to check if session or token-based access is enforced.


---


