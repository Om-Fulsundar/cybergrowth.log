# Crack the Gate 1 — PicoCTF

## Description

> We suspect one of our persons of interest is hiding data inside a restricted web portal.
> We know the login email (`ctf-player@picoctf.org`), but the password is unknown.
> The challenge description hints that the developer may have left a secret way in.

Once the instance loads, we’re greeted with a simple login form asking for an email and password. 


<img width="995" height="680" alt="Screenshot 2025-11-19 223640" src="https://github.com/user-attachments/assets/62f7dba5-91dc-4c9a-962b-07108706949a" />



Nothing unusual on the surface, so I immediately checked the page source.

Near the bottom of the HTML, a suspicious comment appears:

```
<!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
```

<img width="918" height="310" alt="Screenshot 2025-11-19 223728" src="https://github.com/user-attachments/assets/72436676-3cf6-4938-af89-e82ca78836bf" />


This isn’t obfuscated; it’s just **ROT13**. Decoding it gives:


<img width="1044" height="339" alt="Screenshot 2025-11-19 191708" src="https://github.com/user-attachments/assets/f4f8ab2a-1e37-4c64-9b42-4d6816ccc84c" />


So the server trusts a custom request header as a developer backdoor.
I entered the known email with any random password, intercepted the request in Burpsuite and sent it to Burp Repeater, and added the hinted header: 

```
X-Dev-Access: yes
```

Resent the request — access granted instantly. The response returned the flag.


<img width="1430" height="618" alt="Screenshot 2025-11-19 224202" src="https://github.com/user-attachments/assets/a87df811-1cb9-46a8-80f5-f1e38fccc470" />



**Flag:**
`picoCTF{brut4_f0rc4_1a386e6f}`


Crack the Gate 1 complete.

---
---

# Crack the Gate 2 — PicoCTF

### Description

> The login system has been “upgraded” with basic rate-limiting, blocking repeated failed attempts.
> A tip suggests the system still trusts user-controlled headers.
> Our task: bypass rate-limiting, brute force the password for `ctf-player@picoctf.org`, and retrieve the secret.

Same login page as before, but this time incorrect attempts quickly trigger a lockout. The challenge also provides a password list — clearly meant to be used.

I captured a login request using the known email and a dummy password. After a few repeated attempts, the server began returning rate-limit messages.

Because the previous challenge used a trusted header, I tested whether `X-Forwarded-For` was also honored.
It was — meaning the rate-limiter uses the *client IP*, and that value is taken from headers we control.

To automate the attack, I did the following:

1. Imported the captured request into Burp Intruder.
2. Added a custom header:

   ```
   X-Forwarded-For: §IP§
   ```
   
3. Loaded the provided password list as payload set 1.
4. Loaded a list of random IPs as payload set 2.
5. Set Intruder mode to **Pitchfork**, pairing password + IP per attempt.

Because each request had a unique spoofed IP, the rate limiter never triggered.


<img width="935" height="602" alt="Screenshot 2025-11-19 192902" src="https://github.com/user-attachments/assets/58659e5a-6e18-4680-a3e8-fc8c8571fb99" />



After the attack finished, one response stood out — a different length and no rate-limit message.


<img width="1862" height="431" alt="Screenshot 2025-11-19 192848" src="https://github.com/user-attachments/assets/85bed4ac-c457-4cf5-87d9-45c474881f71" />


Opening it revealed the correct password and the flag.


<img width="504" height="515" alt="Screenshot 2025-11-19 192924" src="https://github.com/user-attachments/assets/b6c5c721-a877-48b1-972f-7bd1a9276625" />


Crack the Gate 2 solved.

---
