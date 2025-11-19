# FindMe — PicoCTF Writeup

### Description

> Help us test the form by submitting the username as `test` and password as `test!`

Once the instance boots, we’re greeted with a basic login page.


<img width="849" height="500" alt="Screenshot 2025-11-19 233051" src="https://github.com/user-attachments/assets/a67a7cd1-a16d-4351-a637-e23cf66a6647" />


I entered the provided credentials —   `test:test!`   — and got redirected to `/home`.

The `/home` page says:

> “Welcome fellow Human. Search for flags.”


<img width="1321" height="446" alt="Screenshot 2025-11-19 193209" src="https://github.com/user-attachments/assets/95a9a96d-5f4e-4e4c-ad23-5d33a6671a10" />


There’s a search bar, but no visible flag or clues. I tried fuzzing inputs and inspecting the page source — nothing useful. Time to intercept traffic with Burp Suite.

I captured the login request and noticed something interesting in the response:


<img width="1451" height="458" alt="Screenshot 2025-11-19 200050" src="https://github.com/user-attachments/assets/4f4f57f4-1b93-422a-ae26-d5b375184825" />



```http
HTTP/1.1 302 Found
Location: /next-page/id=cGljbONURntwem94aWVzX2Fs
```


That `id` parameter looked like base64. I decoded it:


```
picoCTF{proxie_all
```


Looks like the first half of the flag.

I followed the redirect to `/next-page/id=...` and inspected the response. Inside the HTML, a JavaScript snippet triggered another redirect after 2 seconds:

```js
window.location = "/next-page/id=bF90aGVfd2F5X2RmNDRjOTRjfQ=="
```


<img width="1447" height="692" alt="Screenshot 2025-11-19 200231" src="https://github.com/user-attachments/assets/dadae265-2dfe-4123-a047-3cf182e4ab1d" />



Decoded that second `id`:

```
ll_the_way_df44c94c}
```

---

### Final Flag Assembly

Combining both decoded parts:

- First: `picoCTF{proxie_all`
- Second: `ll_the_way_df44c94c}`


<img width="714" height="710" alt="Screenshot 2025-11-19 200217" src="https://github.com/user-attachments/assets/2a980d47-3c51-46db-89f8-64bbd6fd7c55" />


Final flag:

**picoCTF{proxies_all_the_way_df44c94c}**

---

