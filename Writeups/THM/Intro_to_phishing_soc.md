# Introduction to Phishing Analysis — SOC Simulator Walkthrough

This simulator focuses on real-world phishing alert triage from a SOC analyst’s perspective. Throughout the investigation, multiple alerts with different severities were analyzed, validated, and documented to determine whether they were false positives or actual threats requiring escalation.

---

# Scenario Overview

As soon as the machine boots, we are dropped into the SIEM dashboard.

<img width="1540" height="764" alt="Screenshot 2026-05-15 214608" src="https://github.com/user-attachments/assets/f3d799ae-35c0-46d8-8886-2f6a74aef8f3" />


I immediately received an alert, assigned it to myself, and started the investigation process.

---

# Alert 1 — False Positive Investigation

## Alert Details

<img width="1489" height="599" alt="Screenshot 2026-05-15 214636" src="https://github.com/user-attachments/assets/575e65d6-9800-4ef4-a1ad-614d2828989c" />


The alert contained a URL inside the email content.
First step was to validate the URL using the analysis tools available inside the analyst VM.

## URL Analysis

<img width="1118" height="796" alt="Screenshot 2026-05-15 214735" src="https://github.com/user-attachments/assets/4817da7b-3b3b-4f6d-af64-435aab1ba404" />


The URL came back clean, and the sender’s domain also appeared legitimate. Nothing suspicious was found during investigation.

Since:

* The URL was not malicious
* The domain looked genuine
* No suspicious indicators were observed

I classified the alert as a **False Positive** and added a short analyst comment before closing it.


<img width="816" height="542" alt="Screenshot 2026-05-15 221432" src="https://github.com/user-attachments/assets/b33542df-5e13-46c6-8bc2-bd1220a46db8" />

---

# Alert 2 — Blacklisted Malicious URL

While handling the first alert, three more alerts appeared in the dashboard.

<img width="1503" height="467" alt="Screenshot 2026-05-15 215128" src="https://github.com/user-attachments/assets/28b3ee22-ce7a-4320-a192-c5efb06ba7b6" />


Following standard SOC workflow, I prioritized the **Critical** and **High Severity** alerts first.
I selected alert `8816` and assigned it to myself.

## Alert Details

<img width="1477" height="654" alt="Screenshot 2026-05-15 215216" src="https://github.com/user-attachments/assets/c15dc077-5e0b-4fff-9884-3e86394ed550" />


The alert indicated that a user attempted to access a URL already present in the firewall blacklist.

To confirm whether the URL was genuinely malicious, I checked it using the scanner available in the VM.

## Threat Validation

<img width="1094" height="787" alt="Screenshot 2026-05-15 215956" src="https://github.com/user-attachments/assets/9597c9ca-e5c0-420c-9b7b-e79f90bbed0e" />


The URL was detected as malicious, confirming the alert as a **True Positive**.

However, before escalation, I verified the network activity in Splunk to check whether the connection was actually successful or blocked by the firewall.

## Splunk Investigation

<img width="1202" height="406" alt="Screenshot 2026-05-15 215442" src="https://github.com/user-attachments/assets/1ed9cc40-d453-4cd2-9dca-3135ee422599" />


The logs confirmed that the firewall had already blocked the request successfully. Since the malicious connection never succeeded, no further compromise indicators were observed.

Because of that:
* Alert classification: **True Positive**
* Escalation required: **No**
* Status: **Closed**

---

## Incident Report Submitted

```text
Time of activity: 05/15/2026 17:17:43.788

List of Affected Entities:
SourceIP: 10.20.2.17
SourcePort: 34257
DestinationIP: 67.199.248.11
DestinationPort: 80
URL: http://bit.ly/3sHkX3da12340

Reason for Classifying as True Positive:
The URL given is detected as malicious by trydetectme.thm

Reason for Escalating the Alert:
The URL is from blacklist of firewall and actually is malicious

Recommended Remediation Actions:
Keep the URL in blacklist as it is.
Aware users about the risks of visiting such URLs.

List of Attack Indicators:
URL: http://bit.ly/3sHkX3da12340
DestinationIP: 67.199.248.11
DestinationPort: 80

Verdict: True Positive
Severity: High
Status: Closed
```

---

# Alert 3 — Suspicious Phishing Domain

After handling the previous alert, I continued investigating the remaining medium-severity alerts in chronological order.

One of the alerts immediately stood out because the sender domain looked suspicious.

## Alert Details

<img width="1499" height="607" alt="Screenshot 2026-05-15 220641" src="https://github.com/user-attachments/assets/2b2bd78d-da82-42f0-87b1-955b4607cec7" />


The domain clearly appeared suspicious, but proper validation was still necessary before escalation.

I checked the URL provided in the email using the analysis tools available in the VM.

## URL Investigation

<img width="1134" height="818" alt="Screenshot 2026-05-15 220719" src="https://github.com/user-attachments/assets/2cd05bf6-0928-4109-a624-ec599b56b506" />


The URL was detected as malicious.

At this point, the alert was already leaning toward a **True Positive**, but I still needed to confirm:

* Whether the user actually accessed the link
* Whether the firewall blocked or allowed the traffic

So I moved to Splunk for deeper investigation.

## Splunk Analysis

<img width="1529" height="799" alt="Screenshot 2026-05-15 220832" src="https://github.com/user-attachments/assets/448ec328-0987-424a-b3a3-53ff48402bfa" />


Interestingly, the logs showed that:

* The user accessed the URL
* The firewall allowed the traffic

This significantly increased the severity of the incident because the malicious domain was not blocked.

Due to this:

* The alert was marked as **True Positive**
* Escalation was required for further investigation and containment

---

## Incident Report Submitted

```text
Time of activity: 05/15/2026 17:18:47.788

List of Affected Entities:
no-reply@m1crosoftsupport.co
c.allen@thetrydaily.thm
URL: https://m1crosoftsupport.co/login

Reason for Classifying as True Positive:
The URL given in mail is detected as malicious and domain of host is suspicious.

Reason for Escalating the Alert:
The URL is malicious and allowed in firewall traffic.
Domain is also suspicious so both URL and domain needs further investigation.

Recommended Remediation Actions:
Add the URL to blacklist of firewall
Block the sender domain 'm1crosoftsupport.co'
Scan users machine for any malicious activity

List of Attack Indicators:
no-reply@m1crosoftsupport.co
https://m1crosoftsupport.co/login

Verdict: True Positive
Severity: Medium
Status: Escalated
```

---

# Conclusion

This simulator provided a good introduction to phishing alert triage and SOC investigation workflow. From validating URLs and analyzing firewall logs to deciding whether escalation was necessary, each alert required a different level of investigation before reaching a final verdict.


<img width="1505" height="499" alt="Screenshot 2026-05-15 221856" src="https://github.com/user-attachments/assets/6662b63d-4667-4a91-89e7-de8983d4b45a" />


Simulator completed successfully.
