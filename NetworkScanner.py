from scapy.all import *
import threading 

def scan_ip_range(ip_range):
    print(f"Scanning started: {ip_range}")
    arp_request = ARP(pdst=ip_range)  
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(f"Devices on the network:")
    for element in answered_list:
        print(f"IP: {element[1].psrc} | MAC: {element[1].hwsrc}")

def scan_ports(ip):
    open_ports = []
    print(f"Scanning: {ip}")
    for port in range(1, 1025):  # Scanning ports from 1 to 1024
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=False)
        if response is None:
            continue
        if response.haslayer(TCP) and response[TCP].flags == 18:  # SYN+ACK flag
            open_ports.append(port)
    return open_ports

def network_scan(ip_range):
    scan_ip_range(ip_range)
    ip_to_scan = input("Enter the IP address whose ports you want to scan: ")
    open_ports = scan_ports(ip_to_scan)
    if open_ports:
        print(f"Open Ports: {open_ports}")
    else:
        print("No open ports found.")

ip_range = input("Enter the IP range you want to scan (e.g., 192.168.1.1/24): ")
network_scan(ip_range)
