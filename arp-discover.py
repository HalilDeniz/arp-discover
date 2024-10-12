#!/usr/bin/env python3

import argparse
import time
from os import system
from re import search
from netaddr import IPNetwork
from scapy.all import *
from subprocess import run
from colorama import Fore, Style, init
from scapy.layers.l2 import ARP, Ether

init(autoreset=True)

class ArpDiscover:
    def __init__(self, args):
        self.mac_ip = {}
        self.mac_count = {}
        self.args = args

    def check_uid(self):
        output = run(["id", "-u"], capture_output=True)

        if int(output.stdout.decode()) != 0:
            print(Fore.RED + "Error: arp-discover.py requires super-user privileges.")
            exit(1)

    def get_local_address(self, up_interface):
        output = run(["ip", "addr", "show", up_interface], capture_output=True)
        r = search(r"([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", output.stdout.decode())
        if r:
            return r.group()
        else:
            print(Fore.RED + "Error: Could not detect local IP address for the given interface.")
            exit(1)

    def gen_ip_list(self, address_cidr):
        ip_list = []
        ipnet = IPNetwork(address_cidr)

        for i in ipnet[1:-1]:
            ip_list.append(str(i))

        return ip_list

    def passive_discover(self, protocol):
        system("clear")
        print(Fore.YELLOW + f"Sniffing on {self.args.interface} with protocol filter '{protocol}'...")
        print(Fore.YELLOW + f"{'IP Address':<20}{'MAC Address':<20}{'Count'}")
        print("-" * 50)
        sniff(filter=protocol, iface=self.args.interface, prn=self.check_pkt)

    def check_pkt(self, pkt):
        if ARP in pkt:
            self.mac_count[pkt[ARP].hwsrc] = self.mac_count.get(pkt[ARP].hwsrc, 0) + 1
            if pkt[ARP].hwsrc not in self.mac_ip.keys():
                self.mac_ip[pkt[ARP].hwsrc] = pkt[ARP].psrc

            system("clear")
            print(Fore.YELLOW + f"{'IP Address':<20}{'MAC Address':<20}{'Count'}")
            print("-" * 50)
            for mac, ip in self.mac_ip.items():
                print(Fore.GREEN + f"{ip:<20}{mac:<20}{self.mac_count[mac]}")

    def arp_scan(self, targets, up_interface):
        system("clear")
        print(Fore.YELLOW + f"Performing ARP Scan on {up_interface}...")
        print(Fore.YELLOW + f"{'IP Address':<20}{'MAC Address':<20}")
        print("-" * 40)
        for target in targets:
            p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            ans, unans = srp(p, iface=up_interface, verbose=0, timeout=self.args.timeout)

            for i in ans:
                print(Fore.GREEN + f"{i[1][ARP].psrc:<20}{i[1][Ether].src:<20}")
            time.sleep(self.args.speed)

        print(Fore.CYAN + "\nARP Scan Completed")

    def run(self):
        self.check_uid()

        if self.args.passive:
            self.passive_discover(self.args.protocol)
        else:
            if self.args.ip_range:
                ip_range = self.args.ip_range
            else:
                ip_range = self.get_local_address(self.args.interface)

            local_net_list = self.gen_ip_list(ip_range)
            self.arp_scan(local_net_list, self.args.interface)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network ARP Scanner and Sniffer Tool")
    parser.add_argument('-p', "--passive", action="store_true", default=True, help="Run in passive mode (default)")
    parser.add_argument('-a', "--active", action="store_true", help="Run in active mode (ARP scan)")
    parser.add_argument('-i', "--interface", required=True, help="Specify the network interface (e.g., eth0, wlan0)")
    parser.add_argument('--protocol', default="arp", help="Specify the protocol to filter during sniffing (default is 'arp')")
    parser.add_argument('--ip-range', help="Specify a custom IP range for ARP scanning (e.g., 192.168.1.0/24)")
    parser.add_argument('--timeout', type=int, default=2, help="Timeout in seconds for ARP scan (default is 2 seconds)")
    parser.add_argument('--speed', type=float, default=0.5, help="Speed (time in seconds) between each ARP request (default is 0.5 seconds)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    arp_discover = ArpDiscover(args)
    arp_discover.run()
