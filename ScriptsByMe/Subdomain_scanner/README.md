
# simple-subdomain-scanner

A threaded Python-based subdomain scanner that checks for live subdomains over HTTPS. Designed for fast enumeration using wordlists, with optional verbose output and result saving.

---

## Features

- Multi-threaded scanning for speed
- Uses HTTPS requests to check subdomain availability
- Verbose mode for live output
- Saves discovered subdomains to `found_subdomains.txt`
- Graceful handling of timeouts and connection errors

---

## Usage

```bash
python scanner.py domain.com -w wordlist.txt -v -t 1000
```
or make it executable and run :
```
./subd.py -h
```

### Arguments

- `domain.com` : Target domain to scan
- `-w wordlist.txt` : Path to subdomain wordlist
- `-v` : Verbose output (optional)
- `-t 100` : Number of threads to use (optional, default is 500)

---

## Output

- Live subdomains are printed to console if `-v` is used (verbose mode)(else it will be printed once scan is completed.)
- All discovered subdomains are saved to `found_subdomains.txt`

---
## Screenshot :

<img width="471" height="340" alt="Screenshot 2025-11-14 195912" src="https://github.com/user-attachments/assets/aa320852-8713-4170-baf9-e1da7cce92d1" />



Let me know when you push this to GitHub — I can help you write the commit message or batch your README sections for future tools.
