# ItsyBitsy - TryHackMe Walkthrough (SOC Analysis Practice with ELK)

<img width="1906" height="233" alt="Screenshot 2026-07-29 002521" src="https://github.com/user-attachments/assets/309cd284-3502-474f-832e-a29c9f0289f1" />


Not every room needs a terminal and a reverse shell. ItsyBitsy hands you a Kibana dashboard, a pile of connection logs, and a story - an analyst spotted something weird, and now it's on you to dig through the noise and pull the actual incident out of it. Good practice for the kind of work a SOC analyst actually does day to day, so figured I'd log this one properly too.

---

## Scenario

Room sets the stage like this:

> During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern THM:{ ____ }. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.

So the job here is pure log analysis - trace the user's connections, find the link they hit, pull the content of the file they grabbed, and answer along the way.

Once the machine booted up I opened it in the browser and the first thing I did was bump the Kibana time range out to the last 10 years, just to make sure every log in the index was actually visible instead of getting stuck on a default window.

<img width="1918" height="857" alt="Screenshot 2026-07-28 233533" src="https://github.com/user-attachments/assets/668a4690-5f62-4e24-bb2e-0e713b2c6062" />


That alone answered the first question.

**Q. How many events were returned for the month of March 2022?**

: 1482

---

## Tracking the Suspect

Next question was about pinning down the IP tied to the suspicious user. Before jumping straight to IPs, I checked what fields were available and had a look at `user_agent` first to see who's who.

<img width="696" height="383" alt="Screenshot 2026-07-28 233814" src="https://github.com/user-attachments/assets/5d5c980d-74d0-4526-961e-31d6025421d3" />


Two user agents stood out in the breakdown - regular browser traffic under `Mozilla/5.0`, and a tiny sliver of traffic tagged `bitsadmin`. That second one is not something a normal user's browser generates, so I filtered on it and got exactly two matching results.

<img width="1498" height="377" alt="Screenshot 2026-07-28 233834" src="https://github.com/user-attachments/assets/5e1ab225-d3f6-4812-bd08-6fa61156dc58" />


Both hits pointed to the same source IP.

**Q. What is the IP associated with the suspected user in the logs?**

: 192.166.65.54

**Q. The user's machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?**

This one had me stuck for a bit since I was expecting to find a binary name buried somewhere in the request details. Ended up backing out and just researching what `bitsadmin` actually is - turns out it's a legitimate command-line tool built into Windows for creating, managing, and monitoring download/upload jobs through the Background Intelligent Transfer Service. Which means the answer had been staring at me the whole time in the user-agent field itself - attackers love abusing BITS jobs because it's a trusted Microsoft binary, so it slides right past a lot of basic detection.

: bitsadmin

---

## Tracing the C2 Connection

**Q. The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?**

Expanded one of the two `bitsadmin` documents and looked at the host field.

<img width="1493" height="273" alt="Screenshot 2026-07-29 001116" src="https://github.com/user-attachments/assets/63534307-4df2-4670-be63-831b9f21acb9" />


: pastebin.com

**Q. What is the full URL of the C2 to which the infected host is connected?**

The document had a `uri` field sitting right alongside the host, holding the path.

<img width="1157" height="305" alt="Screenshot 2026-07-29 001204" src="https://github.com/user-attachments/assets/ac6442b1-2c86-457d-8d4c-edf705499782" />


Stitched the host and uri together for the full link.

: pastebin.com/yTg0Ah6a

**Q. A file was accessed on the filesharing site. What is the name of the file accessed?**

Tried hitting that URL directly first but it wouldn't load properly, so I ran it through an online browser sandbox instead and got the page to render.

<img width="1022" height="682" alt="Screenshot 2026-07-29 002415" src="https://github.com/user-attachments/assets/310f5df4-bb0e-41cf-9da3-66b0673377a5" />


Turned out to be a plain text paste sitting on Pastebin, and honestly the flag was sitting right there in the same screenshot before I'd even finished answering the question.

: secret.txt

**Q. The file contains a secret code with the format THM{_}.**

: THM{SECRET_CODE}

---

Nothing flashy about ItsyBitsy - no exploitation, no privilege escalation, just a Kibana dashboard and a trail of breadcrumbs. But that's honestly the bulk of real SOC work: filtering noise, spotting the one weird user-agent in a sea of normal traffic, recognizing a living-off-the-land binary like `bitsadmin` for what it is, and following the connection all the way to the payload. Good one to keep in the practice rotation alongside the exploitation-heavy boxes.

---
