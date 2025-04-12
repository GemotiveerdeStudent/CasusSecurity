import os

def parse_firewall_log(path="C:\\Windows\\System32\\LogFiles\\Firewall\\Pfirewall.log"):
    if not os.path.exists(path):
        return []

    ip_hits = {}

    with open(path, "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) < 8:
                continue

            action, protocol, src_ip, dst_ip, src_port, dst_port, direction = parts[1:8]

            if direction == "OUTBOUND" and dst_ip.count(".") == 3:  # alleen IPv4
                if dst_ip not in ip_hits:
                    
                    ip_hits[dst_ip] = 1
                else:
                    ip_hits[dst_ip] += 1

    return ip_hits  # { '8.8.8.8': 3, '1.1.1.1': 1 }