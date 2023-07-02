import pyshark
from ipaddress import IPv4Address, IPv4Network


def attack_check(path1, path2, path3, path4):
    ip_ranges = [
        IPv4Network('31.187.93.96/28'),
        IPv4Network('46.136.153.0/24'),
        IPv4Network('46.136.176.0/24'),
        IPv4Network('46.136.231.0/24')
    ]

    file1 = pyshark.FileCapture(path1)
    file2 = pyshark.FileCapture(path2)
    file3 = pyshark.FileCapture(path3)
    file4 = pyshark.FileCapture(path4)

    alertsList = []

    for packet in file1, file2, file3, file4:
        if 'ip' in packet:
            source_ip = packet['ip'].src
            destination_ip = packet['ip'].dst

            for ip_range in ip_ranges:
                if IPv4Address(source_ip) in ip_range:
                    event_name = "Attack from Restricted IP Range"
                    alert = f"Event: {event_name}\nSource IP: {source_ip}\nDestination IP: {destination_ip}"
                    alertsList.append(alert)
                    break
    return alertsList


path1 = "./stealth.pcap"
path2 = "./null.pcap"
path3 = "./fin.pcap"
path4 = "./xmas.pcap"

attacks = attack_check(path1, path2, path3, path4)

if attacks:
    print("Events detected in file:")
    for alert in attacks:
        print(alert)
else:
    print("No events detected.")
