import os
import subprocess

def parse_firewall_log(path="C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"):
    import os
    if not os.path.exists(path):
        return []

    ip_hits = {}

    with open(path, "r") as file:
        for line in file:
            if line.startswith("20"):  # simpele check op datum
                parts = line.strip().split()

                try:
                    action = parts[2]
                    protocol = parts[3]
                    src_ip = parts[4]
                    dst_ip = parts[5]
                    dst_port = parts[7]
                except IndexError:
                    continue

                # Filter lege IP's of ongeldige regels
                if dst_ip.count(".") != 3 and ":" not in dst_ip:
                    continue

                key = (dst_ip, protocol, dst_port, action)

                if key not in ip_hits:
                    ip_hits[key] = 1
                else:
                    ip_hits[key] += 1

    # Converteren naar lijst van tuples
    return [(ip, hits, proto, port, action) for (ip, proto, port, action), hits in ip_hits.items()]



import subprocess

def is_firewall_logging_enabled():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True, text=True, check=True
        )
        return "LogAllowedConnections                 Enable" in result.stdout
    except Exception as e:
        print("[firewall check] Fout:", e)
        return False


def enable_firewall_logging():
    try:
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "logging", "allowedconnections", "enable"],
            check=True
        )
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"],
            check=True
        )
        print("✅ Firewall logging is ingeschakeld.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[enable_logging] Fout bij inschakelen logging: {e}")
        return False
