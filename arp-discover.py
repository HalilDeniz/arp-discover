#!/usr/bin/env python3


import time
import argparse
from os import system
from re import search
from netaddr import IPNetwork
from scapy.all import *
from subprocess import run


def parse_arguments():
	parser = argparse.ArgumentParser()

	parser.add_argument('-p', "--passive", action = "store_true", default = True, help = "Run in passive mode (default)")
	parser.add_argument('-a', "--active", action = "store_true", help = "Run in active mode (ARP scan)")

	return parser.parse_args()


def check_uid():
	output = run(["id", "-u"], capture_output = True)

	if int(output.stdout.decode()) != 0:
		return False

	return True


def get_up_interface():
	output = run(["ip", 'l'], capture_output = True)

	for i in output.stdout.decode().split('\n'):
		if search("state UP", i):
			return i.split()[1].strip(':')


def get_local_address(up_interface):
	output = run(["ip", "addr", "show", up_interface], capture_output = True)

	r = search("([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}", output.stdout.decode())

	return r.group()


def gen_ip_list(address_cidr):
	ip_list = []

	ipnet = IPNetwork(address_cidr)

	for i in ipnet[1:-1]:
		ip_list.append(str(i))

	return ip_list


def passive_discover():
	system("clear")

	sniff(filter = 'arp', prn = check_pkt)


def check_pkt(pkt):
	mac_count[pkt[ARP].hwsrc] = mac_count.get(pkt[ARP].hwsrc, 0) + 1

	if pkt[ARP].hwsrc not in mac_ip.keys():
		mac_ip[pkt[ARP].hwsrc] = pkt[ARP].psrc

	system("clear")
	print("IP:\t\tMAC:\t\t\tCount:")

	for mac, ip in mac_ip.items():
		print("%s\t%s\t%d" %(ip, mac, mac_count[mac]))


def arp_scan(targets, up_interface):
	p = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = targets)

	ans, unans = srp(p, verbose = 0, timeout = 2)

	print("%s:" %(up_interface))

	for i in ans:
		print("%s\t%s" %(i[1][ARP].psrc, i[1][Ether].src))


if __name__ == "__main__":
	if not check_uid():
		print("Error: arp-discover.py requires super-user privileges.")

		exit()

	args = parse_arguments()

	if not args.active:
		mac_ip = {}
		mac_count = {}

		passive_discover()
	else:
		up_interface = get_up_interface()
		local_net = get_local_address(up_interface)

		local_net_list = gen_ip_list(local_net)

		arp_scan(local_net_list, up_interface)