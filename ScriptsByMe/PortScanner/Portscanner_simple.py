import sys
import socket

if len(sys.argv) == 1:
    print(f"Usage : python3 {sys.argv[0]} IP start_port(optional) end_port(optional)" , file=sys.stderr)
    sys.exit(1)

ip = sys.argv[1]
start = 1
end = 65535

if len(sys.argv) >= 3:
    start = int(sys.argv[2])
    if len(sys.argv) >= 4:
        end = int(sys.argv[3])

def check_port(port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip,port))
        return True
    except (ConnectionRefusedError,socket.timeout):
        return False

for port in range (start,end+1):
    response = check_port(port)
    if response:
        print(f"Open Port Found : {port}")

