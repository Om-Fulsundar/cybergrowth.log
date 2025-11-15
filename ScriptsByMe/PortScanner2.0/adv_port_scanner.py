#!/usr/bin/python3

from argparse import ArgumentParser
import socket
from threading import Thread
from time import time, sleep

open_ports = []

def prep_args():
    parser = ArgumentParser(
        description="Advance port scanner (next version of prev. one)",
        usage="%(prog)s <IP>",
        epilog="Example : %(prog)s 192.168.0.0 -s 20 -e 1000 -v -t 1000 --delay 0.01"
    )
    parser.add_argument(metavar="IPv4", dest="ip", help="IP address to scan")
    parser.add_argument("-s", "--start", dest="start", type=int, help="starting port (default = 1)", default=1, metavar="")
    parser.add_argument("-e", "--end", dest="end", type=int, help="ending port (default = 65535)", default=65535, metavar="")
    parser.add_argument("-t", "--threads", dest="threads", type=int, help="number of Threads", default=500, metavar="")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="verbose mode")
    parser.add_argument("--delay", dest="delay", type=float, help="delay between scans in seconds", default=0.0)
    args = parser.parse_args()
    return args

def prep_ports(start: int, end: int):
    for port in range(start, end + 1):
        yield port

def prep_threads(threads: int):
    thread_list = []
    for i in range(threads + 1):
        thread_list.append(Thread(target=scan_port))
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()

def scan_port():
    while True:
        try:
            s = socket.socket()
            s.settimeout(1)
            port = next(ports)
            sleep(arguments.delay)
            s.connect((arguments.ip, port))
            open_ports.append(port)
            if arguments.verbose:
                print(f"\r{open_ports}", end="")
        except (ConnectionRefusedError, socket.timeout):
            continue
        except StopIteration:
            break

if __name__ == "__main__":
    arguments = prep_args()
    ports = prep_ports(arguments.start, arguments.end)
    start_time = time()
    prep_threads(arguments.threads)
    end_time = time()
    if arguments.verbose:
        print()
    print(f"Open Ports found : {open_ports}")
    print(f"Time Taken : {round(end_time - start_time, 2)}")

    with open("open_ports.txt", "w") as f:
        for port in open_ports:
            f.write(str(port) + "\n")
    print("Results saved to open_ports.txt")
