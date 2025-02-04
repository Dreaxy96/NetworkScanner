from scapy.all import *
import threading 


def scan_ip_range(ip_range):
    print(f"Tarama başlatılıyor: {ip_range}")
    arp_request = ARP(pdst=ip_range)  
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(f"Ağdaki Cihazlar:")
    for element in answered_list:
        print(f"IP: {element[1].psrc} | MAC: {element[1].hwsrc}")


def scan_ports(ip):
    open_ports = []
    print(f"Tarama yapılıyor: {ip}")
    for port in range(1, 1025):  
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=False)
        if response is None:
            continue
        if response.haslayer(TCP) and response[TCP].flags == 18:  # SYN+ACK flag
            open_ports.append(port)
    return open_ports


def network_scan(ip_range):
    scan_ip_range(ip_range)
    ip_to_scan = input("Portlarını taramak istediğiniz IP adresini girin: ")
    open_ports = scan_ports(ip_to_scan)
    if open_ports:
        print(f"Açık Portlar: {open_ports}")
    else:
        print("Açık port bulunamadı.")

# Kullanıcıdan ağ aralığını alma
ip_range = input("Tarama yapmak istediğiniz IP aralığını girin (ör. 192.168.1.1/24): ")
network_scan(ip_range)
