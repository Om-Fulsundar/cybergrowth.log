from scapy.all import *
from prettytable import PrettyTable

class Netscan:
    def __init__(self, host):
        self.host = host
        self.alive = {}
        self.answered = []  

    def create(self):
        layer1 = Ether(dst="ff:ff:ff:ff:ff:ff")
        layer2 = ARP(pdst=self.host)
        self.packet = layer1 / layer2

    def send(self):
        answered, unanswered = srp(self.packet, timeout=1, verbose=False)
        if answered:
            self.answered = answered
        else:
            self.answered = []
            print("No Host is up")
            
    def get_alive(self):
        for sent, received in self.answered:
            self.alive[received.psrc] = received.hwsrc

    def show_alive(self):
        if not self.alive:
            print("No live hosts found.")
            return
        table = PrettyTable(["IP Address", "MAC Address"])
        for ip, mac in self.alive.items():
            table.add_row([ip, mac])
        print("\nLive Hosts on the Network:")
        print(table)


print("=== IP Range Scanner ===")
target = input("Enter target IP range : ").strip()
scanner = Netscan(target)
scanner.create()
scanner.send()
scanner.get_alive()
scanner.show_alive()
