## Pickle Rick Writeup

<img width="1918" height="380" alt="Screenshot 2025-11-08 183931" src="https://github.com/user-attachments/assets/5cbed24d-8b23-45db-9a86-7b9bc8f00b9c" />

A fun Rick and Morty-themed CTF where we help Rick turn back into a human by finding three secret ingredients for his pickle-reversal potion.

---

Lets Start !

Once the machine boots up, we get the target IP.


<img width="1629" height="205" alt="Screenshot 2025-11-08 184236" src="https://github.com/user-attachments/assets/5ab92131-d153-4143-93d7-c89311455cd6" />

---

The first step is a port scan. I used a basic  scan (no filters or  flag) : 


<img width="732" height="194" alt="Screenshot 2025-11-08 184557" src="https://github.com/user-attachments/assets/9100e27b-ef31-4438-b86a-c84c2d2d6b02" />


**Results:**

- Port 22 → SSH
- Port 80 → HTTP

Port 80 being open means there's a web application running. I opened the IP in a browser and landed on a Rick and Morty-themed site.


<img width="1920" height="760" alt="Screenshot_2025-11-08_14_55_39" src="https://github.com/user-attachments/assets/7156f212-a6de-4d07-8d00-69f058e7a2f0" />


The homepage has a message from Rick asking Morty to log into his computer and find three secret ingredients. He doesn’t remember the password.

I checked the page source and found a hidden comment:


<img width="1920" height="738" alt="Screenshot_2025-11-08_14_57_35" src="https://github.com/user-attachments/assets/e004fd83-e165-45ec-ac9f-576cba87f4f2" />


where I saw a Username.. which means this site must have other pages too .. lets find its directories.. 


I used `dirsearch` to fuzz for directories:


<img width="946" height="666" alt="Screenshot 2025-11-08 185441" src="https://github.com/user-attachments/assets/650f8dee-c79d-4019-a53b-cbee37ca8f14" />


We found that there is 1 login page , robots.txt and directory called assets.

Navigating to `/login.php`, I found a standard login form :


<img width="1912" height="716" alt="Screenshot_2025-11-08_14_59_40" src="https://github.com/user-attachments/assets/58b7ba6e-9b0a-4821-b2eb-621896d997bd" />



I tried SQLi and brute-force attacks using the username `R1ckRul3s`, but no luck.

/assets is directory in which site data is strored :


<img width="1163" height="669" alt="Screenshot 2025-11-08 190030" src="https://github.com/user-attachments/assets/c03615cf-1d55-45b2-a108-ddada40f2414" />


i went through these files nothing was there. 
Then I checked `/robots.txt` and found this line :


<img width="1920" height="577" alt="Screenshot_2025-11-08_15_00_51" src="https://github.com/user-attachments/assets/78e9e476-758b-43ef-af6c-acd024732b87" />


This looks weird.. maybe password? I checked this as a password for username R1ckRul3s
and BOOM !!
we get logged in !


<img width="1920" height="587" alt="Screenshot_2025-11-08_15_01_37" src="https://github.com/user-attachments/assets/7fe35adc-5757-4e06-9887-2603b49a67b9" />


Inside the portal, most sections were inaccessible except for the **Command Panel**. I tried basic Linux commands.
Using `ls`, I found:


<img width="1920" height="998" alt="Screenshot_2025-11-08_15_02_01" src="https://github.com/user-attachments/assets/c42dabee-9c57-449b-90df-6b7d05cf0b1e" />


we have multiple files here.. from which Sup3rS3cretPickl3Ingred.txt is interesting so i use cat command to read the file but the command was blocked.


<img width="1920" height="1038" alt="Screenshot_2025-11-08_15_02_20" src="https://github.com/user-attachments/assets/01515dbe-3677-46cc-a51d-b0b29f19f24f" />


Then i tried multiple alternatives for cat commands and finally found one which is useful,
when i use less Sup3rS3cretPickl3Ingred.txt command .. it got executed and we get our first answer of challenge's question :

**Q. What is the first ingredient that Rick needs?**


<img width="1920" height="1007" alt="Screenshot_2025-11-08_15_03_40" src="https://github.com/user-attachments/assets/0428b7f1-164c-488f-9991-c4dfb0e3b2fb" />




```
mr. meeseek hair
```
---

now we have clue.txt .. when i read it said : “Look around the file system for the other ingredient.”


<img width="1914" height="795" alt="Screenshot_2025-11-08_18_36_09" src="https://github.com/user-attachments/assets/486833c4-808c-4647-9ffc-dd8ff062bb0e" />


I checked the current directory with `pwd` → `/var/www/html`
by doing backtracking i found path to /home, Inside `/home/rick/` there was second ingredient..
command : less /home/rick/second\ ingredients
then i read that file which was answer of our second question :

**Q. What is the second ingredient in Rick’s potion?**



<img width="1914" height="874" alt="Screenshot_2025-11-08_15_27_31" src="https://github.com/user-attachments/assets/a463955d-84fe-4daf-94d3-56b3fcb7ba33" />




```
1 jerry tear
```
---

now the third question was :
**Q. What is the last and final ingredient?**

For the third ingredient, I suspected it might be in `/root`. Tried accessing it directly — denied.
Then i tried sudo to get into and it worked! i got files in root directory too which was 3rd.txt

<img width="1920" height="751" alt="Screenshot_2025-11-08_18_33_21" src="https://github.com/user-attachments/assets/70798363-2c80-4ee3-9fee-c9c4442fffc4" />


When i read it and that was our third answer..

<img width="1920" height="609" alt="Screenshot_2025-11-08_18_33_59" src="https://github.com/user-attachments/assets/4e627eab-6a9f-44ff-b49c-0c70c9dc55da" />



```
fleeb juice
```
---

Rick’s potion is complete. Mission accomplished!

---------
