# HTML injection 

Injection of HTML tags into a web page to manipulate UI or insert malicious content (may lead to XSS).

---

###  Where to Test

- Search bars
    
- Comment fields
    
- Profile/Bio pages
    
- Contact/Feedback forms
    
- URL params like `?msg=<b>Hi</b>`
    

---

###  How to Detect

Inject simple HTML:

- `<b>test</b>` → bold text?
    
- `<marquee>scroll</marquee>`
    
- `<img src=x onerror=alert(1)>` → check for XSS
    

 **If tags render = vulnerable**

---

###  Testing Approach

1. Inject basic tags
    
2. Check reflection in response
    
3. Inspect source (are tags parsed or escaped?)
    
4. Try XSS probes if HTMLi confirmed
    

---

###  Payloads

```html
<b>Bold</b>
<marquee>Scroll</marquee>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

---

###  Tips

- Not all HTMLi = XSS, but can escalate
    
- Stored HTMLi = more impact
    
- Even harmless rendering is reportable
    
