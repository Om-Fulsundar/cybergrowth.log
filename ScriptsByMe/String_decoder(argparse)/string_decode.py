#!/usr/bin/python3
import argparse
import sys
import base64
import urllib.parse
import codecs

parser = argparse.ArgumentParser(
    description="Python script to decode strings",
    usage=f'%(prog)s --b64/--b32/--b16/--hex/--url/--rot13 cipher'
)

parser.add_argument("--b64", help="decode base64 encoding", metavar="base64", dest="b64", nargs="+")
parser.add_argument("--b32", help="decode base32 encoding", metavar="base32", dest="b32", nargs="+")
parser.add_argument("--b16", help="decode base16 encoding", metavar="base16", dest="b16", nargs="+")
parser.add_argument("--hex", help="decode hex string", metavar="hex", dest="hex", nargs="+")
parser.add_argument("--url", help="decode URL encoding", metavar="url", dest="url", nargs="+")
parser.add_argument("--rot13", help="decode ROT13 cipher", metavar="rot13", dest="rot13", nargs="+")

args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

if args.b64:
    for i in args.b64:
        try:
            print(base64.b64decode(i).decode())
        except Exception as e:
            print(f"b64 decode error: {e}")

if args.b32:
    for i in args.b32:
        try:
            print(base64.b32decode(i).decode())
        except Exception as e:
            print(f"b32 decode error: {e}")

if args.b16:
    for i in args.b16:
        try:
            print(base64.b16decode(i).decode())
        except Exception as e:
            print(f"b16 decode error: {e}")

if args.hex:
    for i in args.hex:
        try:
            print(bytes.fromhex(i).decode())
        except Exception as e:
            print(f"hex decode error: {e}")

if args.url:
    for i in args.url:
        try:
            print(urllib.parse.unquote(i))
        except Exception as e:
            print(f"url decode error: {e}")

if args.rot13:
    for i in args.rot13:
        try:
            print(codecs.decode(i, 'rot_13'))
        except Exception as e:
            print(f"rot13 decode error: {e}")
