# Benign - TryHackMe Walkthrough (SOC Analysis Practice with Splunk)

<img width="1900" height="222" alt="Screenshot 2026-07-29 015808" src="https://github.com/user-attachments/assets/5b42c43c-d472-4c15-ad95-dd316901dc06" />


Same drill as ItsyBitsy, different SIEM this time - Splunk instead of Kibana, and a compromised HR host to untangle. Let's get into the logs.

---

## Scenario

> One of the client's IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win_eventlogs** for further investigation.

Room also lays out the network map - three departments, each with three users:

**IT Department**
- James
- Moin
- Katrina

**HR Department**
- Haroon
- Chris
- Diana

**Marketing Department**
- Bell
- Amelia
- Deepak

Booted the machine, got into Splunk, set the index to `win_eventlogs` as instructed and pushed the time range to All Time so nothing got missed.

<img width="1918" height="782" alt="Screenshot 2026-07-29 010922" src="https://github.com/user-attachments/assets/ce9c84ab-a903-4038-b75a-a1590f900adc" />


**Q. How many logs are ingested from the month of March, 2022?**

: 13959

---

## Spotting the Imposter

**Q. Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?**

Checked the `UserName` field in the sidebar - there were 11 distinct usernames when only 9 real employees exist across the three departments. Ran a quick stats query to break it down properly.

```spl
index="win_eventlogs" | stats count by UserName
```

<img width="892" height="822" alt="Screenshot 2026-07-29 013425" src="https://github.com/user-attachments/assets/149a8b22-9ec9-4ab8-bc77-867fbfa9ef84" />


Scrolling through the list, one entry jumped out right next to the real `Amelia` - a lookalike username using a `1` in place of the `i`.

: Amel1a

---

## Tracking Down the Compromised HR User

**Q. Which user from the HR department was observed to be running scheduled tasks?**

Went through the three HR usernames one by one - Haroon, Chris, and Diana - running a stats query against `CommandLine` for each to see what they'd actually executed.

```spl
index="win_eventlogs" UserName="Chris.fort" | stats count by CommandLine
```

Haroon and Diana looked clean, but Chris's tab had a command line creating a scheduled task pointed at a binary sitting in his temp folder - a classic persistence move.

<img width="1906" height="857" alt="Screenshot 2026-07-29 014538" src="https://github.com/user-attachments/assets/24aa3f28-0eac-4ab2-a681-7728c786edf7" />


: Chris.fort

**Q. Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?**

Wasn't immediately sure what counted as a LOLBin here, so I looked it up - Living Off the Land Binaries, legitimate Windows system tools (things like `certutil.exe`, `rundll32.exe`, `bitsadmin.exe`) that attackers abuse to download or execute payloads while blending into normal system activity, since they're trusted binaries that don't usually trip signature-based detection.

With that in mind I ran the same style of query against Haroon's activity.

```spl
index="win_eventlogs" UserName=haroon | stats count by CommandLine
```

And there it was - `certutil.exe` being used with `-urlcache` to pull down a file from an external domain.

<img width="1037" height="461" alt="Screenshot 2026-07-29 015217" src="https://github.com/user-attachments/assets/df32ae6d-7de5-454e-8115-8802c441c7cd" />


: haroon

---

## Pulling the Payload Details

**Q. To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?**

: certutil.exe


**Q. What was the date that this binary was executed by the infected host? (YYYY-MM-DD)**

Expanded the actual event to check the timestamp.

<img width="1308" height="498" alt="Screenshot 2026-07-29 015411" src="https://github.com/user-attachments/assets/2859394d-b8d0-4ecf-b831-9d94654b766e" />


: 2022-03-04

**Q. Which third-party site was accessed to download the malicious payload?**

Right there in the same command line.

: controlc.com

**Q. What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?**

: benign.exe


**Q. The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?**

Rather than pulling the file down directly on the host, I opened the URL in an online sandboxed browser instead - safer way to poke at an unknown link without touching it on my own machine. Page rendered as a ControlC paste holding the flag straight up.

<img width="1026" height="478" alt="Screenshot 2026-07-29 015628" src="https://github.com/user-attachments/assets/82b5b3b0-f1f9-4d82-92c2-e2739d9f27af" />


: THM{KJ&*H^B0}

**Q. What is the URL that the infected host connected to?**

: https://controlc.com/e4d11035

---

Between the lookalike username, the scheduled task persistence, and `certutil` quietly pulling a payload from a paste site, Benign packs a solid little investigation into a handful of Splunk queries. Same fundamentals as the Kibana room, just a different query language to lean on.

---
