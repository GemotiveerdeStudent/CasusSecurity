import os
import subprocess

def parse_firewall_log(path="C:\\Windows\\System32\\LogFiles\\Firewall\\Pfirewall.log"):
    if not os.path.exists(path):
        return {}

    ip_hits = {}

    try:
        with open(path, "r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) < 8:
                    continue

                # Expected format: date time action protocol src_ip dst_ip src_port dst_port direction
                action, protocol, src_ip, dst_ip, src_port, dst_port, direction = parts[1:8]

                # Alleen IP-adressen (geen ::1, etc.)
                if dst_ip.count(".") == 3:
                    ip_hits[dst_ip] = ip_hits.get(dst_ip, 0) + 1
    except PermissionError:
        print("Geen toestemming om firewall log te lezen.")

    return ip_hits

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
