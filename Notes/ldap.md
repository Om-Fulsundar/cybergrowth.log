# LDAP Injection

## 1. What is LDAP?

LDAP (Lightweight Directory Access Protocol) is used to access and manage directory services like user accounts, groups, and roles. It’s commonly used in:

- Active Directory (Windows)
- OpenLDAP (Linux)

### Default Ports
- 389 → LDAP (unencrypted or StartTLS)
- 636 → LDAPS (LDAP over SSL)

---

## 2. LDAP Directory Basics

LDAP uses a tree-like structure similar to a filesystem.

- **DN (Distinguished Name):** Full path to an entry  
  Example: `cn=John,ou=people,dc=example,dc=com`
- **RDN (Relative Distinguished Name):** Local part of the DN  
  Example: `cn=John`
- **Attributes:** Key-value pairs  
  Example: `mail=john@example.com`

---

## 3. How to Identify LDAP Usage

| Clue                                      | Explanation                                 |
|-------------------------------------------|---------------------------------------------|
| Login forms for internal users            | Often backed by LDAP authentication         |
| Port 389/636 open (Nmap)                  | LDAP or LDAPS service exposed               |
| Error messages mention "LDAP"             | Backend leak                                |
| Admin panels on enterprise apps           | Common LDAP usage                           |
| Logs/source show `(&(uid=...)(password=...))` | Classic LDAP query pattern              |
| Headers mention "AD", "Directory", etc.   | Good signal of LDAP/AD integration          |

---

## 4. LDAP Search Query Structure

Format:
```
(base DN) (scope) (filter) (attributes)
```

Example:
```
ldapsearch -x -H ldap://ip -b "dc=ldap,dc=thm" "(uid=john)"
```

### Filter Examples

| Filter                            | Meaning                  |
|-----------------------------------|--------------------------|
| `(cn=John)`                       | Exact match              |
| `(cn=J*)`                         | Wildcard match           |
| `(&(objectClass=user)(cn=J*))`    | AND logic                |
| `(!(cn=Admin))`                   | NOT logic                |

---

## 5. What is LDAP Injection?

LDAP Injection occurs when unsanitized user input is embedded into LDAP queries. Similar to SQLi, it allows attackers to manipulate query logic.

### Impact
- Authentication bypass
- User enumeration
- Data extraction
- Privilege escalation

---

## 6. Exploitation Techniques

### A. Authentication Bypass

#### Steps
1. Find a login form backed by LDAP
2. Intercept request using Burp
3. Inject payloads like:
   ```
   username = *
   password = *
   ```
4. Query becomes:
   ```
   (&(uid=*)(userPassword=*))
   ```
   → Always true → logs in as first user

---

### B. Wildcard Injection

- Use `*` to match any value
- Example:
  ```
  username = admin*
  password = *
  ```

---

### C. Blind LDAP Injection

- No direct output → rely on behavioral changes
- Steps:
  1. Inject: `username=a*)(|(&` and any password
  2. If error says "Invalid password" → user exists
  3. Use this to brute-force usernames character by character

---

### D. Tautology-Based Bypass

- Inject always-true logic:
  ```
  (&(uid=*)(|(userPassword=pwd)(userPassword=*)))
  ```

---

## 7. Tools for LDAP Testing

| Tool           | Use Case                                |
|----------------|------------------------------------------|
| ldapsearch     | Query LDAP server (recon, enumeration)   |
| Burp Suite     | Intercept and inject login payloads      |
| Wireshark      | Inspect unencrypted LDAP traffic         |
| Python scripts | Automate blind injection and brute-force |

---

## 8. Attack Strategy

| Phase         | Action                                      |
|---------------|---------------------------------------------|
| Recon         | Scan ports, look for LDAP indicators        |
| Detection     | Inject `*`, `)(`, `|` to test logic         |
| Exploitation  | Use tautology or wildcard bypass            |
| Blind Attack  | Automate brute-force with boolean logic     |
| Exfiltration  | Enumerate attributes like `mail`, `uid`, `cn` |

---

## 9. Real-World Tips

- LDAP is often used in enterprise login portals and internal dashboards
- Look for login forms that behave differently with wildcard inputs
- Use Burp to test payloads and observe subtle changes in responses
- Blind LDAPi is slow but effective — automate with Python
- Always sanitize input before embedding in LDAP filters (if developing)

----
