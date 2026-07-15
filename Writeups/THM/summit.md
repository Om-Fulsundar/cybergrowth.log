# Summit - TryHackMe Walkthrough

<img width="1906" height="247" alt="Screenshot 2026-07-15 202347" src="https://github.com/user-attachments/assets/007d1cb4-9642-4a7e-ae2b-dff0a1252531" />


Some rooms give you a machine and a flag. Summit gives you an adversary who actually adapts. Every time you block him, he comes back smarter - new IP, new domain, new technique. It's less "find the flag" and more "climb the Pyramid of Pain and don't let him back down until he's out of moves." Let's get into it.

---

## Task 1: The Setup

The room throws the objective at us straight up front:

> After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.
>
> Following the Pyramid of Pain's ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

So basically - I'm blue team, there's a pentester named Sphinx on the other end simulating red team, and every time I detect and block his stuff, he has to spend more effort to come back. Classic Pyramid of Pain, gamified.

After the machine booted, I opened up the PicoSecure portal. First thing on screen was a mailbox with an intro email from Sphinx.

<img width="1901" height="857" alt="Screenshot 2026-07-15 200215" src="https://github.com/user-attachments/assets/ea9438ba-8099-44fe-9f63-d66067ebc1d9" />


He's kicking things off simple - first sample, `sample1.exe`, dropped straight into the mail with a link to scan it in the Malware Sandbox tool.

---

## Task 2: Level 1 - Hash-Based Detection

Clicked on `sample1.exe` and submitted it for analysis.

<img width="1917" height="632" alt="Screenshot 2026-07-15 200223" src="https://github.com/user-attachments/assets/d2d11652-52e7-44c2-bd20-c97536dc7525" />


Sandbox ran it and gave back a full report - file info, hashes, behaviour analysis. Tagged as `Trojan.Metasploit.A`, with Metasploit flagged straight up under malicious behaviour.

<img width="1896" height="866" alt="Screenshot 2026-07-15 200238" src="https://github.com/user-attachments/assets/203595db-d8f1-41e3-9940-ce5e4fe137ce" />


Lowest rung of the pyramid is hash values, so that's exactly where I started. Copied the SHA256 and went over to the Manage Hashes section.

<img width="1508" height="630" alt="Screenshot 2026-07-15 200255" src="https://github.com/user-attachments/assets/c7d96483-a7a9-4757-8c2f-f654a44b88a0" />


Added the hash to the blocklist.

<img width="1911" height="753" alt="Screenshot 2026-07-15 200338" src="https://github.com/user-attachments/assets/3d6ddb3e-2cf6-4680-bef0-753adb0f9663" />


And that was level one down - the panel confirmed it right away.

<img width="1908" height="853" alt="Screenshot 2026-07-15 200347" src="https://github.com/user-attachments/assets/02030614-ae4c-4f33-a304-686c5c7a2c94" />


Checked the inbox and sure enough, new mail with the first flag.

<img width="1918" height="850" alt="Screenshot 2026-07-15 200403" src="https://github.com/user-attachments/assets/0ff91e40-bd48-4fb3-b42f-b56bc24649a0" />



**Q. What is the first flag you receive after successfully detecting sample1.exe?**

: THM{f3cbf08151a11a6a331db9c6cf5f4fe4}

But Sphinx's email wasn't just a pat on the back. He straight up told me hashes are the weakest indicator - trivial to defeat by just recompiling the malware. Basically telling me "this won't work twice." And right on cue, `sample2.exe` was sitting in the inbox.

---

## Task 3: Level 2 - IP-Based Detection

Sent `sample2.exe` in for analysis too.

<img width="1918" height="592" alt="Screenshot 2026-07-15 200425" src="https://github.com/user-attachments/assets/002ca879-4ec9-4026-8611-89665e95ea31" />


Scrolled through the report and hit the network activity section - one HTTP GET request going out to a sketchy IP on port 4444, plus a couple of other connections.

<img width="1323" height="701" alt="Screenshot 2026-07-15 200534" src="https://github.com/user-attachments/assets/cfff517d-3ae1-40ec-95ea-64d5e4b815f5" />


That IP address stood out as the malicious C2 destination, so I copied it and headed to the Firewall Rule Manager.

<img width="1908" height="762" alt="Screenshot 2026-07-15 200650" src="https://github.com/user-attachments/assets/78f8e2c6-2eb8-4ad1-9062-fc640b53e8d6" />


Created a new egress rule denying traffic to that IP.

<img width="786" height="653" alt="Screenshot 2026-07-15 200838" src="https://github.com/user-attachments/assets/49867b4e-af2d-4cd2-b1e0-cecd28c2aed7" />


Saved it, and another level cleared - the panel flagged that the rule successfully blocked the sample from reaching the tester's C2 server.

<img width="1892" height="726" alt="Screenshot 2026-07-15 200850" src="https://github.com/user-attachments/assets/a99436db-9ee9-4028-a295-dcbc2c286192" />


Straight to the inbox for the next flag.

<img width="1896" height="857" alt="Screenshot 2026-07-15 200858" src="https://github.com/user-attachments/assets/48d6f14b-531a-489e-a698-d1e7fa1c16b0" />


**Q. What is the second flag you receive after successfully detecting sample2.exe?**

: THM{2ff48a3421a938b388418be273f4806d}

Sphinx wasn't thrilled - said IP blocking is trivial to get around since he can just spin up a new one from a cloud provider. And true to form, `sample3.exe` showed up attached to the mail.

---

## Task 4: Level 3 - Domain-Based Detection

Sent `sample3.exe` for analysis.

<img width="1912" height="601" alt="Screenshot 2026-07-15 200916" src="https://github.com/user-attachments/assets/8501ad92-5ede-4734-a849-dc066d97255c" />


Got the results back - this time there were two HTTP requests, one of them pulling down `backdoor.exe` from a domain called `emudyn.bresonicz.info`. DNS requests confirmed the same domain resolving.

<img width="1252" height="792" alt="Screenshot 2026-07-15 200947" src="https://github.com/user-attachments/assets/bdd259a1-e67c-4526-bd1e-0480b012a2a8" />

Domain was clearly the pivot point here since he can rotate IPs but the domain stayed constant across the download of the payload. Copied the domain and went to the DNS Rule Manager.

<img width="1901" height="817" alt="Screenshot 2026-07-15 201038" src="https://github.com/user-attachments/assets/fc78eec2-682c-47ba-ba38-3f2dfe6e827a" />


Added a new rule categorized as Malware, denying that domain.

<img width="1897" height="752" alt="Screenshot 2026-07-15 201103" src="https://github.com/user-attachments/assets/b26c2f4e-98cd-4378-9de7-8b8e67a8ed60" />


Level solved, confirmation banner popped up saying the DNS filter blocked the sample from reaching the C2 server.

<img width="1211" height="707" alt="Screenshot 2026-07-15 201117" src="https://github.com/user-attachments/assets/3a7ca011-9926-4879-9542-1e8775bcce3a" />


New mail, new flag.

**Q. What is the third flag you receive after successfully detecting sample3.exe?**

: THM{4eca9e2f61a19ecd5df34c788e7dce16}

This time Sphinx sounded a bit more rattled - buying and registering new domains costs him time and money. But he pushed on and said blocking hashes, IPs, or domains won't cut it anymore for the next one. Time to actually look at what the malware *does* on the host instead of what it talks to.

---

## Task 5: Level 4 - Host Artifacts

`sample4.exe` came in next. Sent it to the sandbox.

<img width="1918" height="508" alt="Screenshot 2026-07-15 201136" src="https://github.com/user-attachments/assets/0132fadc-1410-4557-b3c9-743d9e0a0904" />


The behaviour analysis this time flagged something nastier - the malicious process was disabling Windows Defender's real-time monitoring and downloading executables from the internet. Also making unusual outbound connections.

<img width="1238" height="497" alt="Screenshot 2026-07-15 201253" src="https://github.com/user-attachments/assets/c26f88b6-7962-43d5-a0ff-9f4827fe8809" />


I dug into that PID and pulled up its registry activity. Found the exact modification - a write event to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, setting `DisableRealtimeMonitoring` to `1`.

<img width="1242" height="605" alt="Screenshot 2026-07-15 201158" src="https://github.com/user-attachments/assets/6a687876-15e8-4885-952b-15afd3e4d6cd" />


This isn't something you can block with an IP or hash rule - it's a host artifact, a behaviour. So I opened the Sigma Rule Builder in a new tab. Picked Sysmon Event Logs as the log source, then chose Registry Modifications as the detection type.

<img width="822" height="762" alt="Screenshot 2026-07-15 201447" src="https://github.com/user-attachments/assets/9666025d-90c5-4c49-98f6-fb16976714e2" />


Filled in the exact key, value name, and the value it was being set to, mapped it to Defense Evasion under MITRE ATT&CK, and validated the rule.

<img width="1877" height="822" alt="Screenshot 2026-07-15 201507" src="https://github.com/user-attachments/assets/247b00bc-3a9b-4c97-9b74-deca940448eb" />


Level cleared. Got the flag straight after, along with a new challenge attached.

**Q. What is the fourth flag you receive after successfully detecting sample4.exe?**

: THM{c956f455fc076aea829799c0876ee399}

Sphinx's tone had officially shifted from smug to annoyed - said I threw a wrench into his methodology and he's having to retrain his approach. He mentioned this next sample offloads the heavy lifting to his back-end server, so the artifacts on the host itself won't tell the full story. He attached a log of outgoing connections from the last 12 hours and told me to go correlate something.

---

## Task 6: Level 5 - Behavioural Detection (Network Pattern)

Opened the attached `outgoing_connections.log`.

<img width="1013" height="783" alt="Screenshot 2026-07-15 201648" src="https://github.com/user-attachments/assets/1f86f1bf-9470-4052-b26c-9feda207d454" />


Scanning through it, one destination IP kept showing up over and over - same size, same port (443), and roughly the same interval every single time. That's a beacon pattern, textbook C2 heartbeat traffic hiding in plain sight among normal connections.

Went back to Sigma Rule Builder and this time picked Network Connections as the rule type. Set remote IP and port to "Any" since I wanted to catch the pattern rather than one specific host, locked in the size (97 bytes) and the frequency (1800 seconds), and mapped it to Command and Control under ATT&CK.

<img width="818" height="857" alt="Screenshot 2026-07-15 201813" src="https://github.com/user-attachments/assets/626c761a-7b48-4143-a4ad-78c784bf9c0e" />


Validated it - level solved, next flag and challenge dropped in.


<img width="1887" height="846" alt="Screenshot 2026-07-15 201827" src="https://github.com/user-attachments/assets/73c6e51e-18b2-4c12-b7ee-017247d03c25" />

**Q. What is the fifth flag you receive after successfully detecting sample5.exe?**

: THM{46b21c4410e47dc5729ceadef0fc722e}

---

## Task 7: Level 6 - TTPs (The Top of the Pyramid)

Sphinx's last email had a real edge to it - said he can't keep burning tools and infrastructure forever, the cost isn't worth it anymore, and this would be his final trick. Attached was `commands.log`, a full log of the commands he runs on victims once he's got access.

Opened it up:

```
dir c:\ >> %temp%\exfiltr8.log
dir "c:\Documents and Settings" >> %temp%\exfiltr8.log
dir "c:\Program Files" >> %temp%\exfiltr8.log
dir d:\ >> %temp%\exfiltr8.log
net localgroup administrator >> %temp%\exfiltr8.log
ver >> %temp%\exfiltr8.log
systeminfo >> %temp%\exfiltr8.log
ipconfig /all >> %temp%\exfiltr8.log
netstat -ano >> %temp%\exfiltr8.log
net start >> %temp%\exfiltr8.log
```


<img width="857" height="432" alt="Screenshot 2026-07-15 201939" src="https://github.com/user-attachments/assets/1654c86c-d83c-4331-8b25-dbe6d97a03de" />


This is straight-up recon and data exfiltration - dumping directory listings, local admin group, system info, network config, running services, all appended into one file (`exfiltr8.log`) sitting in `%temp%`. Doesn't matter what hash, IP, domain, or process runs it - this is his TTP (Tactics, Techniques, and Procedures), the actual behaviour pattern, and that's the hardest thing for an adversary to change.

Went to Sigma Rule Builder one final time, picked File Creation and Modification as the rule type, set the file path to `%temp%` and file name to `exfiltr8.log`, and mapped it to Exfiltration under ATT&CK.

<img width="900" height="790" alt="Screenshot 2026-07-15 202059" src="https://github.com/user-attachments/assets/9dd571b6-5cf8-486b-8dcd-7c3dd99afb44" />


Validated the rule - and that was the top of the pyramid, cleared.

<img width="1882" height="780" alt="Screenshot 2026-07-15 202105" src="https://github.com/user-attachments/assets/16099bda-53d2-4bb8-a7a7-1964c77a84de" />


Checked the mail one last time.

<img width="1901" height="756" alt="Screenshot 2026-07-15 202115" src="https://github.com/user-attachments/assets/5cb3beaa-3afd-46e4-bb38-ce2076f0410f" />


**Q. What is the final flag you receive from Sphinx?**

: THM{c8951b2ad24bbcbac60c16cf2c83d92c}

Sphinx's last message basically threw in the towel - said I'd chased him all the way up the Pyramid of Pain and he had nothing left to burn. Detected his hashes, blocked his IPs, killed his domains, caught his host artifacts, picked apart his network behaviour, and finally nailed his TTPs. Nowhere left to hide.

---

Summit isn't your usual boot2root - no shells, no SUID binaries, no privilege escalation. It's a slow, deliberate climb where every level you win pushes the adversary to spend more time and money to come back. That's the actual point of the Pyramid of Pain in real SOC work: the higher up the indicators you're detecting, the more expensive it gets for an attacker to evade you. By the end, Sphinx wasn't beaten by one clever exploit - he was priced out of the engagement entirely.

Six levels, six flags, and a pentester who finally gave up. Not a bad way to spend an afternoon.

---
