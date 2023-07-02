from scapy.all import *
from scapy.layers.inet import TCP, IP


def stealth_check(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        stealth_check.stealth_count += 1
        event_name = "Stealth Scan"
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Event: {event_name}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Stealth scan detected: count: {stealth_check.stealth_count}")
        print()


stealth_check.stealth_count = 0


def null_check(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 0:
        null_check.null_count += 1
        event_name = "NULL Scan"
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Event: {event_name}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"NULL scan detected: count: {null_check.null_count}")
        print()


null_check.null_count = 0


def FIN_check(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 1:
        FIN_check.FIN_count += 1
        event_name = "FIN Scan"
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Event: {event_name}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"FIN scan detected: count: {FIN_check.FIN_count}")
        print()


FIN_check.FIN_count = 0


def Xmas_check(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 41:
        Xmas_check.Xmas_count += 1
        event_name = "Xmas Scan"
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Event: {event_name}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Xmas scan detected: count: {Xmas_check.Xmas_count}")
        print()


Xmas_check.Xmas_count = 0

path1 = "./stealth.pcap"
path2 = "./null.pcap"
path3 = "./fin.pcap"
path4 = "./xmas.pcap"

file1 = rdpcap(path1)
file2 = rdpcap(path2)
file3 = rdpcap(path3)
file4 = rdpcap(path4)

for packet in file1:
    stealth_check(packet)

for packet in file2:
    null_check(packet)

for packet in file3:
    FIN_check(packet)

for packet in file4:
    Xmas_check(packet)
