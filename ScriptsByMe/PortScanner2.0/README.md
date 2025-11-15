# advanced-port-scanner

A threaded Python-based TCP port scanner that checks for open ports on a target IP address. This version supports custom port ranges, adjustable thread count, optional delay between scans, and saves results to a file.
our prev. version scans the port but it was too slow.. we ve used multithreading in it .. its more fast and has some extra features too.

---

## Features

- Multi-threaded TCP port scanning
- Customizable start and end port range
- Adjustable thread count for performance tuning
- Optional delay between scans for stealth or rate control
- Verbose mode for live output
- Saves discovered open ports to `open_ports.txt`
- Displays total time taken for the scan

---

## Usage

```bash
python scanner.py <IP> -s 20 -e 1000 -v -t 1000 --delay 0.01
```
or make it executable and use :
```
./scanner.py
```

### Arguments

- `<IP>` : Target IPv4 address to scan
- `-s` : Starting port (default: 1)
- `-e` : Ending port (default: 65535)
- `-t` : Number of threads to use (default: 500)
- `-v` : Verbose mode (optional)
- `--delay` : Delay between scans in seconds (default: 0.0)

---

## Output

- Prints open ports found
- Shows total time taken for the scan
- In verbose mode, prints live updates of open ports as they are discovered
- Saves all open ports to `open_ports.txt`

---

## screenshot :

<img width="603" height="316" alt="Screenshot 2025-11-16 001710" src="https://github.com/user-attachments/assets/54cb6ff3-a032-4493-80ad-f8cc284d7742" />



