# c4ptur3-th3-fl4g — TryHackMe Walkthrough


<img width="1905" height="372" alt="Screenshot 2025-11-21 195438" src="https://github.com/user-attachments/assets/b34430bf-23fc-433d-b7c8-dc505cbfee7f" />


Alright, beginner CTF challenge they said. Let’s see if we can peel back every layer of encoding they throw at us. I’ll walk you through exactly how I solved it, step by step, so you can follow along.

---

## Task 1: String Decoding

First one is just a string:  
`c4n y0u c4p7u23 7h3 f149?`  

Easy — that’s leetspeak. Reads as: **“can you capture the flag?”**

---

### Binary → ASCII  
We’re given a bunch of binary values like:

```
01101100 01100101 01110100 01110011 ...
```

I dropped them into [RapidTables Binary to ASCII converter](https://www.rapidtables.com/convert/number/binary-to-ascii.html).  


<img width="764" height="641" alt="Screenshot 2025-11-21 185859" src="https://github.com/user-attachments/assets/4a1e48de-adad-48c7-b670-51d6e29cb996" />


Output: **lets try some binary out!**

---

### Base32  
Next string looked suspicious:  
```
MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======
```
Ran it through [CyberChef](https://gchq.github.io/CyberChef/#oeol=NEL) — it auto‑detects encodings.  


<img width="579" height="347" alt="Screenshot 2025-11-21 185921" src="https://github.com/user-attachments/assets/bfc6b1b4-7cdd-4726-bdb6-eaf179bc71bb" />


Decoded: **“base32 is super common in CTF's”**

---

### Base64  
Another one:  
```
RWFjaCBCYXNlNjQgZGln...
```

Straight into CyberChef again.  


<img width="757" height="313" alt="Screenshot 2025-11-21 185936" src="https://github.com/user-attachments/assets/4b575f12-b8d1-427c-b52e-d4b29e4edb0c" />



Decoded: **“Each Base64 digit represents exactly 6 bits of data.”**

---

### Hexadecimal / Base16  
String of hex values:  
```
68 65 78 61 64 65 63 69 6d 61 6c ...
```

Converted with CyberChef.  

<img width="671" height="311" alt="Screenshot 2025-11-21 185949" src="https://github.com/user-attachments/assets/2e3bb0f5-e476-478b-b770-dab9abfcbb5a" />


Output: **“hexadecimal or base16?”**

---

### ROT13  
Classic ROT13:  
```
Ebgngr zr 13 cynprf!
```

Used [Cryptii ROT13 decoder](https://cryptii.com/pipes/rot13-decoder).  


<img width="1677" height="421" alt="Screenshot 2025-11-21 190005" src="https://github.com/user-attachments/assets/40dacf58-90f3-4450-824f-6aea6de4af85" />


Decoded: **“Rotate me 13 places!”**

---

### ROT47  
This one wasn’t ROT13, looked messier:  
```
*@F DA:? >6 C:89E C@F?5 ...
```

Tried ROT47 in Cryptii.  


<img width="1648" height="420" alt="Screenshot 2025-11-21 190021" src="https://github.com/user-attachments/assets/18595cfd-4a37-4d19-8e7f-d5a90dd43e56" />



Decoded: **“You spin me right round baby right round (47 times)”**

---

### Morse Code  
We get a bunch of dots and dashes.  
I pasted them into [Morse Code Translator](https://morsecode.world/international/translator.html).  


<img width="955" height="382" alt="Screenshot 2025-11-21 190038" src="https://github.com/user-attachments/assets/ea47d30c-bc7c-4268-95bb-736c0022cb6b" />


Output: **“TELECOMMUNICATIONENCODING”**

---

### BCD (Binary Coded Decimal)  
String of decimal values:  
```
85 110 112 97 99 107 32 116 104 105 115 32 66 67 68
```

Decoded with CyberChef.  

<img width="526" height="332" alt="Screenshot 2025-11-21 190053" src="https://github.com/user-attachments/assets/b503bcf9-5548-4a9c-8fe9-4bdd008a0f0d" />



Output: **“Unpack this BCD”**

---

### Nested ROT47 → ASCII  
One tricky string.. lets decode it..
first I decoded it from base64 and we got binary..


<img width="963" height="728" alt="Screenshot 2025-11-21 190118" src="https://github.com/user-attachments/assets/3b916252-2958-49a4-bce5-040942ac029e" />


I pasted this binary output to RapidTables and found another rot47 string..


<img width="772" height="647" alt="Screenshot 2025-11-21 190136" src="https://github.com/user-attachments/assets/dc239b03-a314-4043-a96d-54c07a1f3d2f" />

then I move this output to Cryptii to decode it and got ASCII..


<img width="1762" height="440" alt="Screenshot 2025-11-21 190154" src="https://github.com/user-attachments/assets/c8422578-7ef4-457d-be30-6d1c2e9bfdcc" />


and finally, when I put it on cyberchef again.. we got our string..


<img width="965" height="467" alt="Screenshot 2025-11-21 190207" src="https://github.com/user-attachments/assets/9ce7d488-4d93-43e6-a618-d3506c5d6f69" />



Output: **“Let’s make this a bit trickier ...”**

---

## Task 2: Spectrograms

We’re given an audio file. Challenge hints at spectrograms.  
Uploaded it to [dCode Spectral Analysis](https://www.dcode.fr/spectral-analysis).  


<img width="641" height="614" alt="Screenshot 2025-11-21 190818" src="https://github.com/user-attachments/assets/ff74e2e2-6005-403e-85b0-125882021a2e" />



Hidden message revealed: **“Super Secret Message”**

---

## Task 3: Steganography

Image provided. Metadata check gave nothing. Tried `steghide`:  

```bash
steghide extract -sf stegosteg.jpg
```

It asked for a passphrase, but extraction worked. 


<img width="496" height="195" alt="Screenshot 2025-11-21 191906" src="https://github.com/user-attachments/assets/04373f96-1d26-4b93-92ef-7975f2ac907c" />


Payload file contained:  
**“SpaghettiSteg”**

---

## Task 4: Security Through Obscurity

Another image. Ran `strings` on it:  

```bash
strings image.png
```

At the bottom:  


<img width="308" height="120" alt="Screenshot 2025-11-21 192203" src="https://github.com/user-attachments/assets/8a01c811-80fe-44f4-a7b1-47b470662ce9" />


```
"AHH_YOU_FOUND_ME!"
hackerchat.png
```


- First filename & extension: **hackerchat.png**  
- Hidden text: **AHH_YOU_FOUND_ME!**

---

So that’s the whole ride: binary, base encodings, ROT tricks, Morse, BCD, spectrograms, and steganography. Each layer was a classic CTF puzzle — nothing too fancy, but a great reminder that persistence and the right tools (CyberChef, Cryptii, RapidTables, dCode, steghide, strings) will get you through. 

Challenge solved, flags captured.  

