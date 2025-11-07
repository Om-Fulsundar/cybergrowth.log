# simple-rce-py

A minimal Python-based Remote Command Execution (RCE) tool using TCP sockets.

---

##  Features

- Remote command execution over TCP
- Client connects to server and executes received commands
- Server sends commands and receives output
- Graceful exit with `"exit"` command
- Lightweight and dependency-free (uses only Python standard library)

---

## Usage : 

###  Server :
```bash
python server.py
```
- Starts a listener on `127.0.0.1:3173`
- Accepts one client connection
- Sends commands interactively
- Type `exit` to terminate session

###  Client
```bash
python client.py
```
- Connects to server at `127.0.0.1:3173`
- Waits for commands
- Executes each command and sends output back

---
DO NOT USE THIS ON INTERNET AS IT IS NOT SAFE.
---
