import pyshark


def is_nikto(packet):
    if 'http' in packet and 'user_agent' in packet.http.field_names:
        user_agent = packet.http.user_agent.lower()
        if 'nikto' in user_agent:
            return True
    return False


def nikto_check(path1):
    global niktoCount
    niktoCount = 0
    file1 = pyshark.FileCapture(path1, display_filter='http')
    alertsList = []

    for packet in file1:
        if is_nikto(packet):
            event_name = "Nikto Scan"
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            alert = f"Event: {event_name}\nSource IP: {source_ip}\nDestination IP: {destination_ip}"
            alertsList.append(alert)
            niktoCount += 1

    return alertsList


path1 = "./nikto.pcap"

attacks = nikto_check(path1)

if attacks:
    print("Events detected in the capture file:")
    for alert in attacks:
        print(alert)
        break
else:
    print("No events detected.")
