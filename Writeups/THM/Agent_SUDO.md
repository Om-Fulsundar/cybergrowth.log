# Agent Sudo — TryHackMe Walkthrough

<img width="1907" height="368" alt="Screenshot 2025-11-27 215417" src="https://github.com/user-attachments/assets/140120f1-c124-452f-9caf-dd89459090fc" />


This challenge throws a series of questions at us, each one hinting at the next step. Let’s follow the trail, decode the clues, and capture the flags.

---

## Task 1: Enumeration  

First step is always recon. Once the machine boots, I ran an nmap scan to see what’s open.  


<img width="521" height="211" alt="Screenshot 2025-11-27 180542" src="https://github.com/user-attachments/assets/16d70dcc-01ba-4c8b-9cb4-b3072dd1d50d" />


**Q. How many open ports?**  
: 3  

I checked FTP for anonymous login — no luck. Then moved to the web page. 


<img width="708" height="366" alt="Screenshot 2025-11-27 180637" src="https://github.com/user-attachments/assets/97f4b5ac-b651-4df6-9728-8603a030bca5" />


The hint points us toward the **User-Agent** header.  


**Q. How you redirect yourself to a secret page?**  
: user-agent  

At first I didn’t know what value to use. Fuzzing endpoints didn’t help. The challenge hint mentioned `"user-agent : c"`. So I switched the User-Agent to `C` in Burp Suite. That triggered a redirect, and following it gave us the next clue.  



<img width="1592" height="674" alt="Screenshot 2025-11-27 183015" src="https://github.com/user-attachments/assets/b3b83c40-4945-48f8-8c20-b4e4338fe229" />



**Q. What is the agent name?**  
: chris  

---
---


## Task 2: Hash Cracking and Brute Force  


Now we have a username: `chris`. His password is weak, so brute force is the way. I used Hydra with the `rockyou.txt` wordlist against FTP.  


<img width="952" height="205" alt="Screenshot 2025-11-27 183455" src="https://github.com/user-attachments/assets/480411bb-ab0c-447d-83b9-e04f7b693c99" />


Credentials found.  

**Q. FTP password**  
: crystal  

Logged in via FTP :

<img width="715" height="391" alt="Screenshot 2025-11-27 183523" src="https://github.com/user-attachments/assets/30d084b4-2b15-466a-9967-d917b06a23a1" />



Downloaded all files locally using `mget`.


<img width="945" height="335" alt="Screenshot 2025-11-27 191512" src="https://github.com/user-attachments/assets/6d6686e4-af9e-4656-a26b-be027094e03d" />



The text file hinted at checking the image files we pulled down.

We had two: one `.jpg` and one `.png`.  


<img width="942" height="177" alt="Screenshot 2025-11-27 191537" src="https://github.com/user-attachments/assets/7391360d-b585-4d59-8faf-2cdc9f233b58" />


Tried steghide on the JPG with no passphrase — failed. So I moved to the PNG. Running `zsteg` showed there was a zip file embedded. 


<img width="942" height="370" alt="Screenshot 2025-11-27 191714" src="https://github.com/user-attachments/assets/769ce325-9640-4d56-ab80-a5ab9d204762" />


Extracted it with `foremost`.  


<img width="306" height="201" alt="Screenshot 2025-11-27 191803" src="https://github.com/user-attachments/assets/5897525e-8cae-45b7-91dc-9c08920717f6" />


The zip was password‑protected. Time for John the Ripper.  

<img width="953" height="153" alt="Screenshot 2025-11-27 192617" src="https://github.com/user-attachments/assets/6f55e7aa-be83-4882-95fd-421a1037b851" />


<img width="765" height="210" alt="Screenshot 2025-11-27 192811" src="https://github.com/user-attachments/assets/78e40aa1-d4b4-4b89-b354-5afa64f14674" />



**Q. Zip file password**  
: alien  

Unzipped and got a text file. It contained a suspicious string starting with `QXJ...`. 

<img width="536" height="102" alt="Screenshot 2025-11-27 192900" src="https://github.com/user-attachments/assets/55a0e9f4-0107-4bba-b1f5-518819eee206" />



Dropped it into [CyberChef](https://gchq.github.io/CyberChef/#oeol=NEL). Decoded to `Area51`.  


<img width="497" height="381" alt="Screenshot 2025-11-27 193822" src="https://github.com/user-attachments/assets/255ec15c-95f8-49d3-9f56-44159e71facf" />



Tried steghide again on the JPG with password `Area51`. This time it worked.  


<img width="726" height="248" alt="Screenshot 2025-11-27 195021" src="https://github.com/user-attachments/assets/804ff4bd-bc63-41dd-9ba0-f46ac2319fe5" />


**Q. steg password**  
: Area51  

Inside were new credentials.  

**Q. Who is the other agent (in full name)?**  
: james  

**Q. SSH password**  
: hackerrules!  

---

## Task 4: Capture the User Flag  

Logged in via SSH with James’s credentials.  


<img width="657" height="447" alt="Screenshot 2025-11-27 195220" src="https://github.com/user-attachments/assets/2a69b2aa-44fa-4ee9-81a5-f9e2240ac548" />

lets grab user flag first..


<img width="342" height="98" alt="Screenshot 2025-11-27 195234" src="https://github.com/user-attachments/assets/ddfa58aa-3feb-4fba-923f-980bcd36cb62" />


**Q. What is the user flag?**  
: b03d975e8c92a7c04146cfa7a5a313c7  

There was also a photo to retrieve. I started a simple HTTP server on the target machine to get it.

<img width="773" height="255" alt="Screenshot 2025-11-27 195739" src="https://github.com/user-attachments/assets/834a09ee-2007-47a9-9a1b-a8122a54f49a" />



then I went on port 3773 of target IP in the browser . Downloaded the image locally.


<img width="1901" height="788" alt="Screenshot 2025-11-27 195759" src="https://github.com/user-attachments/assets/b47dbfc9-7c00-4b5a-8f15-82ab6b1a4a6b" />

After some simple google search and research on the image I found this page and we got our next answer. ( bit OSINT skills)


<img width="1165" height="693" alt="Screenshot 2025-11-27 200025" src="https://github.com/user-attachments/assets/83d73076-5c7c-4bf7-bc53-af8bef0e0cc5" />


**Q. What is the incident of the photo called?**  
: Roswell alien autopsy  

---
---

## Task 5: Privilege Escalation  

First of all I checked sudo permissions with `sudo -l`. Found:  


<img width="791" height="167" alt="Screenshot 2025-11-27 200430" src="https://github.com/user-attachments/assets/1d6b3e03-27d8-4da3-9861-8e5ff34aca1f" />


```
(ALL, !root) /bin/bash
```  

That line looked suspicious. Googled it and found the CVE on ExploitDB.  


<img width="1502" height="846" alt="Screenshot 2025-11-27 201203" src="https://github.com/user-attachments/assets/e614247f-cd24-440a-b885-2613da700c2d" />


**Q. CVE number for the escalation**  
: CVE-2019-14287  

Followed the exploitation technique described. Ran the command on the target machine and escalated to root.  

<img width="720" height="287" alt="Screenshot 2025-11-27 201432" src="https://github.com/user-attachments/assets/67c4079c-58b8-4cf2-bc21-45ff956e9d71" />
<img width="388" height="72" alt="Screenshot 2025-11-27 201423" src="https://github.com/user-attachments/assets/b841e05f-2e4d-4f8e-ad69-53124ed55b17" />

Now its easy deal !

lets get root flag now..


<img width="890" height="234" alt="Screenshot 2025-11-27 201507" src="https://github.com/user-attachments/assets/0f31629e-c338-411a-b8bc-ada9847cf24b" />


**Q. What is the root flag?**  
: b53a02f55b57d4439e3341834d70c062  

**Q. (Bonus) Who is Agent R?**  
: DesKel  

---
---

Challenge Solved. Flags Captured !

Enumeration, brute force, steganography, OSINT, and privilege escalation — this challenge stacked them all. Each hint pushed us toward the next step, and with the right tools.


