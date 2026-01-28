# picoCTF 2022 — Roboto Sans  


<img width="960" height="790" alt="Screenshot 2026-01-28 195329" src="https://github.com/user-attachments/assets/fc88659a-b74b-4dbb-8eb1-abe28823b959" />


The challenge description is short and cryptic: *“The flag is somewhere on this web application not necessarily on the website. Find it.”*  Translation : the flag is hiding, probably giggling at us from some obscure corner. Time to play hide‑and‑seek with a CTF box.

---

 
Once the instance spins up, we’re greeted with a yoga‑themed website. Peaceful vibes, calming colors… 


<img width="1890" height="967" alt="Screenshot 2026-01-28 195125" src="https://github.com/user-attachments/assets/39603ddf-0de1-4502-9d97-4c7edb1d19d1" />



But we’re not here for inner balance. We’re here to break stuff.  

Checked the source code. Nothing obvious, but then I spotted a cheeky comment:  


<img width="1126" height="242" alt="Screenshot 2026-01-28 195159" src="https://github.com/user-attachments/assets/59209611-b59d-4df5-a217-ee49d8de8bd4" />


```
<!-- The flag is not here but keep digging :) -->
```
  
Ah, the classic troll comment. Thanks, devs.

---


Challenge says “not necessarily on the website,” so I started poking around directories. Standard move: check `robots.txt`.  

Sure enough, `/robots.txt` had some juicy entries:  


<img width="818" height="437" alt="Screenshot 2026-01-28 195130" src="https://github.com/user-attachments/assets/dde4f468-0456-45e5-bc24-9dbbca349398" />



```
User-agent *
Disallow: /cgi-bin/
Think you have seen your flag or want to keep looking.

ZmxhZzEudHh0; anMvbX1maW
anMvbX1maWx1LnR4dA==
...
Disallow: /wp-admin/
```  

That random string ending with `==` screamed *Base64*. When you see `==`, your brain should instantly go: “Decode me!” It’s basically the neon sign of encodings.

---


Dropped the string into an online Base64 decoder. Out popped:  


<img width="673" height="680" alt="Screenshot 2026-01-28 195110" src="https://github.com/user-attachments/assets/de38d2ff-3c01-4ea3-8af3-4d9d6b058076" />


```
js/myfile.txt
```  

So the robots were hiding a file in `/js/`. Sneaky, but not sneaky enough.

---

Navigated to:  

```
saturn.picoctf.net:61791/js/myfile.txt
```  

And there it was, shining like a treasure chest at the end of a dungeon crawl:  


<img width="789" height="216" alt="Screenshot 2026-01-28 195037" src="https://github.com/user-attachments/assets/ee1613cf-7bc9-48d0-80dd-c32905a98d5f" />


```
picoCTF{Who_D03sN7_L1k5_90BOT5_032f1c2b}
```

---


This challenge was basically a game of “peekaboo” with the flag. The devs left breadcrumbs in the source, robots.txt gave us encoded hints, and Base64 decoding led straight to the prize. Moral of the story: always check robots.txt — it’s like the diary where websites confess their secrets.  
