# Mustacchio — TryHackMe Walkthrough  


<img width="1898" height="370" alt="Screenshot 2025-12-03 123806" src="https://github.com/user-attachments/assets/012c4235-2bc9-485a-8ee9-6601ac4ace09" />

 
Boot2root, labeled easy. But we know “easy” usually means a mix of classic tricks. Let’s treat this like a journey — enumerate, exploit, escalate — and see where it takes us.  

---

## Recon and Enumeration

Box is up, so first instinct: full port scan. I hit all 65k ports with nmap.  


<img width="550" height="222" alt="Screenshot 2025-12-03 124401" src="https://github.com/user-attachments/assets/8aa93d9c-a61f-4677-87ba-4c38699cb1ca" />


Open ports:  
- 22/tcp — SSH  
- 80/tcp — HTTP  
- 8765/tcp — ultraseek-http  

lets check web app first..


<img width="1920" height="1080" alt="Screenshot_2025-12-03_12_42_33" src="https://github.com/user-attachments/assets/9c93a10f-9439-4f56-8d34-75fd10f633aa" />


Web on port 80 looked clean, nothing juicy in source. 
That’s when I pivoted to fuzzing with `dirsearch`. 


<img width="713" height="749" alt="Screenshot 2025-12-03 124445" src="https://github.com/user-attachments/assets/105ea454-a7bb-467a-a552-892dec176937" />


A bunch of directories popped up, but while checking these directories, `/custom/js/` caught my eye.  


<img width="766" height="441" alt="Screenshot 2025-12-03 124510" src="https://github.com/user-attachments/assets/7f6939d1-37d4-4349-8ae5-3d5083f707a1" />


Inside: `users.bak`. Perfect. which contains :


<img width="479" height="63" alt="Screenshot 2025-12-03 124553" src="https://github.com/user-attachments/assets/b29ef4ed-d5bd-49aa-93e7-e33c14413aff" />


Cracked the hash on [CrackStation](https://crackstation.net/) — SHA1, 

creds: ` admin:bulldog19 `.  

But where is login panel ? we didnt find any on port 80, but port 8765 had one.


<img width="1920" height="1080" alt="Screenshot_2025-12-03_12_44_28" src="https://github.com/user-attachments/assets/c16bd9bf-beeb-41d3-9cce-dbba27da95a9" />


Dropped the creds in — boom, admin access.  


<img width="1920" height="1080" alt="Screenshot_2025-12-03_12_46_20" src="https://github.com/user-attachments/assets/26679e05-b698-4dcd-9397-b400dee3a47b" />

---

## Digging into the Admin Panel  

Logged in, tried injections, but nothing stuck.Maybe its accepting something particular format. Then I noticed a comment in the source:  


<img width="867" height="496" alt="Screenshot 2025-12-03 124637" src="https://github.com/user-attachments/assets/02e26aa0-5580-4318-8114-685498d22414" />


```
//document.cookie = "Example=/auth/dontforget.bak";
<!-- Barry, you can now SSH in using your key! -->
```  

Two leads: a hidden file and a user name Barry for ssh. We have to find its SSH key too.   

Pulled `dontforget.bak`. It was XML. That screamed “XXE.”  


<img width="1909" height="195" alt="Screenshot 2025-12-03 124717" src="https://github.com/user-attachments/assets/4ea2fa10-1a14-4452-bb76-26b23f486fab" />


I tested by submitting XML comments — confirmed the parser was live. 


<img width="854" height="661" alt="Screenshot 2025-12-02 211814" src="https://github.com/user-attachments/assets/9c429e56-63ef-4239-b1fe-65b36e580af7" />


Time to weaponize. We have to to do XML external entity (XXE) injection. I read about this attack on  [PortSwigger’s XXE guide](https://portswigger.net/web-security/xxe) and made some changes to exploit it.


<img width="1920" height="1080" alt="Screenshot_2025-12-03_13_27_43" src="https://github.com/user-attachments/assets/af05a5d7-f1f5-4754-a406-9ff1bad80876" />


Output gave me `/etc/passwd`. Exploit confirmed. Next target: `/home/barry/.ssh/id_rsa`. 
Extracted Barry’s private key.  ( Usually SSH private key for user is stored in this path)


<img width="1920" height="1080" alt="Screenshot_2025-12-02_21_20_55" src="https://github.com/user-attachments/assets/c55004b4-c626-4e04-83ca-91cccf3210f6" />


Saved the key locally, tried SSH. It asked for a passphrase. (make sure you run `chmod 600 id_rsa' before using it)


<img width="680" height="162" alt="Screenshot 2025-12-02 212240" src="https://github.com/user-attachments/assets/58fe860c-367b-4dc4-b5fc-d6590bf73437" />


We have to get that password first. Here comes John to help.
I ran ` ssh2john id_rsa > musta ` :


<img width="951" height="461" alt="Screenshot 2025-12-03 133131" src="https://github.com/user-attachments/assets/8c380fd7-60f1-4ac8-865e-966d12ff46a4" />



And cracked with `john` + `rockyou.txt`.  


<img width="828" height="222" alt="Screenshot 2025-12-02 213124" src="https://github.com/user-attachments/assets/25cfb953-6811-4f0b-b5d0-6ef5a466dfce" />


Passphrase: ` urieljames `.  

Logged in as Barry:  
```bash
ssh barry@target -i id_rsa
```  


<img width="665" height="471" alt="Screenshot 2025-12-02 213150" src="https://github.com/user-attachments/assets/40e5c1c6-0f3b-4fbc-a4e5-37fec8717a51" />


We’re in.  

lets grab user flag.


<img width="342" height="75" alt="Screenshot 2025-12-02 213202" src="https://github.com/user-attachments/assets/d9171ada-3e94-495e-ae0c-8448dfb7db94" />


**User flag:**  
```
62d77a4d5f97d47c5aa38b3b2651b831
```  

---

## Privilege Escalation  

I tried various ways to prevesc but found nothing but when I checked SUID binaries:  

```bash
find / -type f -perm -4000 2>/dev/null
```  


<img width="620" height="420" alt="Screenshot 2025-12-02 213731" src="https://github.com/user-attachments/assets/737ecebf-0aac-4015-bab4-acfb802b4a00" />


One stood out: `/home/joe/live_log`. Running it showed it was tailing nginx logs.  


<img width="944" height="358" alt="Screenshot 2025-12-02 214404" src="https://github.com/user-attachments/assets/a5ab78d5-adcd-4ada-a1fa-c305d1a3e522" />


`strings` revealed it called `tail`. That’s exploitable.  


<img width="420" height="487" alt="Screenshot 2025-12-02 214004" src="https://github.com/user-attachments/assets/de0692e7-e22f-4073-96be-6a2afca1942f" />


I built a fake `tail` in `/tmp`:  
```bash
echo "/bin/bash -p" > /tmp/tail
chmod +x /tmp/tail
export PATH=/tmp:$PATH
```  

<img width="517" height="84" alt="Screenshot 2025-12-02 214212" src="https://github.com/user-attachments/assets/6456d2dc-7f7c-42cf-bd04-f03ea9dbe0e4" />

<img width="900" height="129" alt="Screenshot 2025-12-02 214600" src="https://github.com/user-attachments/assets/6364da33-7e7f-446f-87db-7200bd06c82f" />


Ran `/home/joe/live_log`. Root shell dropped instantly.  


<img width="348" height="38" alt="Screenshot 2025-12-02 214651" src="https://github.com/user-attachments/assets/eb2945d3-230c-4ae0-a3d5-248ea830172c" />

Woop Woop !! lets grab root flag..


<img width="328" height="108" alt="Screenshot 2025-12-02 214658" src="https://github.com/user-attachments/assets/641c0ba9-08fb-497a-9e1b-5a525114aab3" />


**Root flag:**  
```
3223581420d906c4dd1a5f9b530393a5
```  

---

From nmap to dirsearch, CrackStation to XXE, ssh2john to PATH hijack — every step was a pivot. Mustacchio wasn’t about one big exploit, it was about chaining small wins until root fell in our lap. 

Flags captured, journey complete.  

---
