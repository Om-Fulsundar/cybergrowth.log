# Shadow Trace - TryHackMe Walkthrough

<img width="1890" height="221" alt="Screenshot 2026-07-25 151329" src="https://github.com/user-attachments/assets/da7df34a-da84-4039-bb0e-fae6e6f65928" />


DFIR rooms hit different from your usual boot2root. No shells to pop, no root flag waiting at the end - just a suspicious binary, a pile of alerts, and the job of figuring out exactly what happened. Shadow Trace throws a sketchy `windows-update.exe` at you and expects a proper investigation. Let's dig in.

---

## Task 2: File Analysis

The task briefing is straightforward: analyse the binary sitting at `C:\Users\DFIRUser\Desktop\windows-update.exe` on the attached machine and answer the questions. Room also mentions a `DFIR Tools` folder on the desktop loaded with everything needed for the job.

Started the lab machine, gave it the couple minutes it needed to boot, and took a first look at `windows-update.exe`.

**Q. What is the architecture of the binary file windows-update.exe?**

: 64-bit

**Q. What is the hash (sha-256) of the file windows-update.exe?**

For this one I just popped open PowerShell and ran `Get-FileHash` on it.

```powershell
PS C:\Users\DFIRUser\Desktop> get-FileHash ".\windows-update.exe"
```

<img width="982" height="177" alt="Screenshot 2026-07-25 144750" src="https://github.com/user-attachments/assets/413e61b3-aca9-4270-8d4d-acda35d66ba3" />


: b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc

Next up was static analysis, so I opened PeStudio (already sitting in the DFIR Tools folder) and dropped the exe in there.

**Q. Identify the URL within the file to use it as an IOC**

Headed straight to the indicators section and it was sitting right there in the strings list.

<img width="1171" height="678" alt="Screenshot 2026-07-25 145220" src="https://github.com/user-attachments/assets/433519b6-13c9-4dab-94db-d7b7295c5457" />


: http://tryhatme.com/update/security-update.exe

**Q. With the URL identified, can you spot a domain that can be used as an IOC?**

To dig this one out I went back to PowerShell and grepped the strings of the binary for anything related.

```powershell
PS C:\Users\DFIRUser\Desktop> strings .\windows-update.exe | findstr "tryhatme"
```

<img width="765" height="92" alt="Screenshot 2026-07-25 145607" src="https://github.com/user-attachments/assets/8e910430-2438-45a4-b24b-641fa0738884" />


That pulled up a second, more suspicious-looking domain used for callbacks alongside the update URL.

: responses.tryhatme.com

While I was in there I also noticed a base64 blob tacked onto the end of the `tryhatme.com/` string. Dropped it into an online base64 decoder to see what it unpacked to.

<img width="808" height="748" alt="Screenshot 2026-07-25 145655" src="https://github.com/user-attachments/assets/c137a54b-7540-4b2e-85bf-f4a84d835e6d" />


**Q. Input the decoded flag from the suspicious domain**

: THM{you_g0t_some_IOCs_friend}

**Q. What library related to socket communication is loaded by the binary?**

Back to PeStudio, this time checking the libraries section - and there it was, flagged clean as day.

<img width="1102" height="552" alt="Screenshot 2026-07-25 150848" src="https://github.com/user-attachments/assets/49cdb737-fe5f-4055-bba2-f9718cef5523" />


: WS2_32.dll

That wrapped up the static analysis side of things. Binary confirmed malicious, IOCs extracted, hidden flag pulled out of a base64 string tucked inside the URL. Task 2 done.

---

## Task 3: Alert Analysis

This part flips the perspective - instead of picking apart the binary itself, I'm looking at a static SOC-style alert dashboard and working out what actually fired and why.

Opened up the site and got a clean little alerting interface showing two records.


<img width="1325" height="721" alt="Screenshot 2026-07-25 150926" src="https://github.com/user-attachments/assets/2692a00d-7bf2-4aff-9541-0f04c78354d4" />


Two critical alerts on the board - one a suspicious PowerShell execution, the other a suspicious browser download triggered via Chrome's JavaScript execution. Both flagged on the same host.

**Q. Can you identify the malicious URL from the trigger by the process powershell.exe?**

Looked at the command logged for the PowerShell alert and immediately spotted a base64-encoded chunk sitting inside a `DownloadString` call.

<img width="1266" height="206" alt="Screenshot 2026-07-25 151036" src="https://github.com/user-attachments/assets/5819b1a8-e5a0-4d3d-963c-4d86742b452f" />


Copied that string into CyberChef and decoded it straight away.

<img width="661" height="417" alt="Screenshot 2026-07-25 151024" src="https://github.com/user-attachments/assets/841f5070-8ff7-40f6-9627-2f46f6cc84d0" />


: https://tryhatme.com/dev/main.exe

**Q. Can you identify the malicious URL from the alert triggered by chrome.exe?**

This one was encoded a bit differently - instead of base64 it was a comma-separated list of decimal character codes stuffed inside a `fetch()` call, being mapped back to characters and reconstructed into a URL client-side.

<img width="1252" height="222" alt="Screenshot 2026-07-25 151123" src="https://github.com/user-attachments/assets/8a6f7c34-95ac-4b34-83ec-0b04c5398d64" />


Pasted the decimal string into CyberChef, ran it through a decimal-to-text decode, and got the URL straight out.

<img width="958" height="382" alt="Screenshot 2026-07-25 151111" src="https://github.com/user-attachments/assets/33241132-32d9-4037-a372-6c290c84354c" />


: https://reallysecureupdate.tryhatme.com/update.exe

**Q. What's the name of the file saved in the alert triggered by chrome.exe?**

Still sitting right there in the same command block - the script writes the downloaded blob out to a file before triggering the download.

: test.txt

---

Between the two tasks, Shadow Trace covers pretty much the full first pass of an incident: pull the binary apart statically, extract every IOC you can find, then flip over to the alerting side and prove out exactly what the payload did once it landed - PowerShell staging a second-stage download, and a browser process quietly saving it to disk under an innocent filename. No exploitation, no shells, just methodical digging - which honestly is most of real DFIR work anyway.

Static analysis and log correlation, box checked.

---
