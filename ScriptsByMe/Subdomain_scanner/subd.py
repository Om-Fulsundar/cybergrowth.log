#!/usr/bin/python3

from argparse import ArgumentParser, FileType
from requests import get, exceptions
from threading import Thread

subdomains = []

def prep_args():
    parser = ArgumentParser(
        description="Simple Subdomain Scanner",
        usage="%(prog)s domain.com",
        epilog="Example: %(prog)s google.com -v -t 500 -w wordlist.txt"
    )
    parser.add_argument(metavar="Domain", dest="domain", help="Domain name")
    parser.add_argument("-w", "--Wordlist", metavar="", dest="wordlist", type=FileType("r"), help="Path or name of subdomain wordlist.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--threads", type=int, metavar="", dest="threads", default=500, help="Threads to use")
    args = parser.parse_args()
    return args

def prepare_words():
    words = arguments.wordlist.read().split()
    for word in words:
        yield word

def prep_threads():
    thread_list = []
    for i in range(arguments.threads):
        thread_list.append(Thread(target=check_subdomain))
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()

def check_subdomain():
    while True:
        try:
            word = next(words)
            url = f"https://{word}.{arguments.domain}"
            request = get(url, timeout=5)
            if request.status_code == 200:
                subdomains.append(url)
                if arguments.verbose:
                    print(url)
        except (exceptions.ConnectionError, exceptions.ReadTimeout):
            continue
        except StopIteration:
            break

if __name__ == "__main__":
    arguments = prep_args()
    words = prepare_words()
    prep_threads()

    print("\nSubdomains found:")
    for j in subdomains:
        print(j)

    with open("found_subdomains.txt", "w") as f:
        for sub in subdomains:
            f.write(sub + "\n")
    print("\nResults saved to found_subdomains.txt")
