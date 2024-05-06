import nmap
import socket
import requests

print("Welcome to Bloody's Hacker Port Scanner :)")
def get_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def get_isp_provider(ip_address):
    url = f"https://ipapi.co/{ip_address}/json/"
    response = requests.get(url)
    data = response.json()
    return data.get('org', 'Unknown')

def scan_network(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, '1-1024')

    print(f"\nIP Address: {ip_address}")
    print(f"MAC Address: {get_mac_address(ip_address)}")
    print(f"ISP Provider: {get_isp_provider(ip_address)}\n")

    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")

            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

        print()

# Get IP address from the user
ip_address = input("Enter the IP address to scan: ")

# Scan the network
scan_network(ip_address)