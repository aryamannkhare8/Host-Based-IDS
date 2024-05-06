# Importing required Scapy components for packet manipulation and analysis
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from triggeremail import *

import time

# Function to log details about each packet that is captured
def log_packet(packet):
    global times
    global timestamp_suspicious
    timestamp = time.time()  # Capture the current time as timestamp for the log
    packet_info = ""
    counter = 0

    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src  # Source IP address
        dst_ip = packet[IP].dst  # Destination IP address
        protocol = packet[IP].proto  # Protocol used at the IP layer
        packet_size = len(packet)  # Total size of the packet
        counter = analyseSize(packet_size)  # Analyze the size of the packet for any irregularity

        # Increment global count if size analysis indicates suspicious activity
        if counter != 0:
            times += 1

        # Extract TCP specific information if it's a TCP packet
        if protocol == 6 and TCP in packet:
            src_port = packet[TCP].sport  # Source port
            dst_port = packet[TCP].dport  # Destination port
            packet_info += f"Source Port:{src_port}\nDestination Port:{dst_port}\n"
            
            # Mapping of port numbers to their respective protocols
            protocols = {
                80: "HTTP", 443: "HTTPS", 21: "FTP", 20: "FTP Data Transfer",
                22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 110: "POP3",
                143: "IMAP", 389: "LDAP", 445: "SMB", 3389: "RDP",
                3306: "MySQL Database", 5432: "PostgreSQL Database",
                161: "SNMP (UDP)", 162: "SNMP Trap (UDP)", 123: "NTP (UDP)",
                137: "NetBIOS (UDP)", 138: "NetBIOS (UDP)", 139: "NetBIOS (UDP)",
                636: "LDAP Secure", 8080: "HTTP Proxy", 8443: "HTTPS Proxy",
                67: "DHCP", 68: "DHCP", 88: "Kerberos Authentication", 
                993: "IMAPS", 995: "POP3S"
            }
            if dst_port in protocols:
                packet_info += "Protocol Used:" + protocols[dst_port] + "\n"
                counter = analysePort(dst_port)
                times += 1

        # Extract UDP specific information if it's a UDP packet
        elif protocol == 17 and UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_info += f"Source Port:{src_port}\nDestination Port:{dst_port}\n"

        # Extract raw payload data if available
        if Raw in packet:
            payload_data = packet[Raw].load.hex()
            packet_info += f"Payload Data:{payload_data}\n"

        # Extract Ethernet and ARP information for further context
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            packet_info += f"Source MAC:{src_mac}\nDestination MAC:{dst_mac}\n"
        elif ARP in packet:
            arp_request = packet[ARP].op == 1  # Checking if ARP packet is a request
            packet_info += f"ARP Request:{arp_request}\n"

        # Extract DNS query information if the packet is a DNS request
        if DNS in packet and packet[DNS].qd:
            dns_query = packet[DNS].qd.qname.decode()
            packet_info += f"DNS Query:{dns_query}\n"

        # Format log entry and write it to packet_log.txt
        log_entry = f"Timestamp:{timestamp}\nSource IP:{src_ip}\nDestination IP:{dst_ip}\nProtocol:{protocol}\nPacket Size:{packet_size}\n{packet_info}\n"
        with open("packet_log.txt", "a") as log_file:
            log_file.write(log_entry)

        # Log suspicious activity in a separate file if any indicators are triggered
        if counter != 0:
            with open("suspicious.txt", "a") as log_file:
                log_file.write(log_entry)
            timestamp_suspicious.append(timestamp)

# Variables to track suspicious activities and their timestamps
times = 0
timestamp_suspicious=[]

# Initialize packet sniffing using Scapy's sniff function, specifying that the log_packet function should be applied to each packet
sniff(prn=log_packet)

# If suspicious activities were logged during packet sniffing, send an email notification
if times > 0:
    send_email(timestamp_suspicious)
