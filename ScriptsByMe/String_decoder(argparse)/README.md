
#  String Decoder CLI

A simple Python command-line tool to decode strings using various encoding formats like Base64, Base32, Base16, Hex, URL encoding, and ROT13.

##  Features

- Decode strings encoded in:
  - Base64 (`--b64`)
  - Base32 (`--b32`)
  - Base16 (`--b16`)
  - Hexadecimal (`--hex`)
  - URL encoding (`--url`)
  - ROT13 cipher (`--rot13`)
- Accepts multiple inputs per format
- Graceful error handling for invalid inputs
---

##  Usage

```bash
python3 decode.py [options] <encoded_string>
```
```
./decode.py [options] <encoded_string>
```
(make file executable before using second command)

---

###  Options

| Option     | Description                     |
|------------|---------------------------------|
| `--b64`    | Decode Base64 encoded string    |
| `--b32`    | Decode Base32 encoded string    |
| `--b16`    | Decode Base16 encoded string    |
| `--hex`    | Decode hexadecimal string       |
| `--url`    | Decode URL-encoded string       |
| `--rot13`  | Decode ROT13 cipher             |

###  Examples

```bash
python3 decode.py --b64 SGVsbG8gd29ybGQ=
python3 decode.py --b32 JBSWY3DPEB3W64TMMQ======
python3 decode.py --b16 48656C6C6F
python3 decode.py --hex 48656c6c6f
python3 decode.py --url Hello%20World%21
python3 decode.py --rot13 Uryyb Jbeyq
```

You can also decode multiple strings at once:

```bash
python3 decode.py --b64 SGVsbG8= V29ybGQ=
```
----

Screenshot :

<img width="561" height="311" alt="image" src="https://github.com/user-attachments/assets/7d142f3f-5760-4e5a-96b1-039f2ac1c1b0" />

